
import csv
import hashlib
from collections import Counter
from datetime import datetime
from pathlib import Path

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = Path(__file__).resolve().parent
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"
REPORT_DIR = PROJECT_ROOT / "reports"

WINDOWS_FINDINGS_FILE = MODULE_DIR / "windows_validation_findings.csv"
REGISTER_FILE = REPORT_DIR / "investigation_register.csv"
SUMMARY_FILE = REPORT_DIR / "investigation_register_summary.txt"

# Set to an integer during testing to limit records per check.
# Set to None to capture every record matching each defined check.
MAX_RECORDS_PER_CHECK = None

SOURCE_TABLES = {
    "DNS": "normalized_events",
    "Application Security": "normalized_app_events",
    "Firewall": "normalized_firewall_events",
    "Linux Syslog": "normalized_linux_events",
    "Windows Security": "normalized_windows_events",
}

ANALYST_FIELDS = [
    "investigation_status",
    "analyst_notes",
    "investigation_outcome",
]

REGISTER_FIELDS = [
    "investigation_id",
    "source",
    "check_name",
    "severity",
    "event_timestamp",
    "source_line_number",
    "source_event_id",
    "host",
    "username",
    "src_ip",
    "dst_ip",
    "event_id",
    "field_name",
    "observed_value",
    "reason_flagged",
    "raw_event",
    "investigation_status",
    "analyst_notes",
    "investigation_outcome",
]

DEFAULT_STATUS = "New"
DEFAULT_OUTCOME = "Undetermined"


def text_value(value):
    if value is None:
        return ""
    return str(value)


def stable_id(source, check_name, identity):
    content = f"{source}|{check_name}|{identity}"
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16].upper()
    return f"INV-{digest}"


def load_existing_updates():
    updates = {}

    if not REGISTER_FILE.exists():
        return updates

    with REGISTER_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            investigation_id = text_value(
                row.get("investigation_id")
            ).strip()

            if investigation_id:
                updates[investigation_id] = {
                    field: text_value(row.get(field))
                    for field in ANALYST_FIELDS
                }

    return updates


def get_tables(connection):
    return {
        row[0]
        for row in connection.execute("SHOW TABLES").fetchall()
    }


def get_columns(connection, table):
    return {
        row[0]
        for row in connection.execute(
            f'DESCRIBE "{table}"'
        ).fetchall()
    }


def value_from(row, columns, name):
    if name in columns:
        return row.get(name)
    return None


def record_identity(row, columns):
    identity_fields = [
        "source_line_number",
        "source_event_id",
        "event_id",
        "event_timestamp",
        "host",
        "username",
        "src_ip",
        "dst_ip",
        "raw_event",
    ]

    parts = [
        f"{field}={text_value(value_from(row, columns, field))}"
        for field in identity_fields
    ]

    return "|".join(parts)


def make_finding(
    source,
    check_name,
    row,
    columns,
    reason,
    severity="MEDIUM",
    field_name="",
    observed_value="",
    identity=None,
):
    identity = identity or record_identity(row, columns)

    finding = {
        "investigation_id": stable_id(
            source, check_name, identity
        ),
        "source": source,
        "check_name": check_name,
        "severity": severity,
        "event_timestamp": text_value(
            value_from(row, columns, "event_timestamp")
        ),
        "source_line_number": text_value(
            value_from(row, columns, "source_line_number")
        ),
        "source_event_id": text_value(
            value_from(row, columns, "source_event_id")
        ),
        "host": text_value(
            value_from(row, columns, "host")
        ),
        "username": text_value(
            value_from(row, columns, "username")
        ),
        "src_ip": text_value(
            value_from(row, columns, "src_ip")
        ),
        "dst_ip": text_value(
            value_from(row, columns, "dst_ip")
        ),
        "event_id": text_value(
            value_from(row, columns, "win_event_id")
            or value_from(row, columns, "event_id")
        ),
        "field_name": field_name,
        "observed_value": text_value(observed_value),
        "reason_flagged": reason,
        "raw_event": text_value(
            value_from(row, columns, "raw_event")
        ),
        "investigation_status": DEFAULT_STATUS,
        "analyst_notes": "",
        "investigation_outcome": DEFAULT_OUTCOME,
    }

    return finding


def add_finding(findings, finding):
    if (
        MAX_RECORDS_PER_CHECK is not None
        and MAX_RECORDS_PER_CHECK >= 0
    ):
        check_count = sum(
            1
            for existing in findings
            if existing["source"] == finding["source"]
            and existing["check_name"] == finding["check_name"]
        )

        if check_count >= MAX_RECORDS_PER_CHECK:
            return

    findings.append(finding)


def fetch_rows(connection, table, columns, where_clause, parameters=None):
    selected = [
        column
        for column in [
            "source_line_number",
            "source_event_id",
            "event_id",
            "event_timestamp",
            "source_timestamp",
            "host",
            "username",
            "src_ip",
            "dst_ip",
            "raw_event",
            "source_labels",
            "dns_query",
            "dns_query_type",
            "dns_subdomain_entropy",
            "dns_query_length",
            "event_category",
            "app_attack_type",
            "app_detection",
            "app_uri",
            "app_method",
            "app_status",
            "severity",
            "fw_action",
            "fw_rule",
            "fw_protocol",
            "fw_tcp_flags",
            "fw_src_port",
            "fw_dst_port",
            "linux_hostname",
            "linux_process",
            "linux_pid",
            "linux_auth_result",
            "linux_message",
            "win_event_id",
            "win_process",
            "win_command_line",
            "event_action",
        ]
        if column in columns
    ]

    if not selected:
        return []

    sql = (
        "SELECT "
        + ", ".join(f'"{column}"' for column in selected)
        + f' FROM "{table}" WHERE {where_clause}'
    )

    if MAX_RECORDS_PER_CHECK is not None:
        sql += f" LIMIT {int(MAX_RECORDS_PER_CHECK)}"

    cursor = connection.execute(sql, parameters or [])
    names = [item[0] for item in cursor.description]

    return [
        dict(zip(names, values))
        for values in cursor.fetchall()
    ]


def run_query_check(
    connection,
    findings,
    source,
    table,
    columns,
    check_name,
    where_clause,
    reason,
    severity="MEDIUM",
    field_name="",
    observed_field="",
):
    rows = fetch_rows(
        connection, table, columns, where_clause
    )

    for row in rows:
        observed = row.get(observed_field) if observed_field else ""
        finding = make_finding(
            source=source,
            check_name=check_name,
            row=row,
            columns=columns,
            reason=reason,
            severity=severity,
            field_name=field_name,
            observed_value=observed,
        )
        add_finding(findings, finding)


def investigate_dns(connection, tables, findings):
    source = "DNS"
    table = SOURCE_TABLES[source]

    if table not in tables:
        print(f"Skipping {source}: table not found.")
        return

    columns = get_columns(connection, table)

    if "source_labels" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "DNS_SOURCE_LABEL_REVIEW",
            """
            EXISTS (
                SELECT 1
                FROM UNNEST(source_labels) AS labels(label)
                WHERE LOWER(CAST(label AS VARCHAR)) IN (
                    'suspicious-tld', 'dga', 'c2',
                    'beacon', 'high-entropy', 'dns-tunneling'
                )
            )
            """,
            "The DNS record contains a source label that warrants review.",
            "MEDIUM", "source_labels", "source_labels",
        )

    if "dns_subdomain_entropy" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "DNS_HIGH_ENTROPY_QUERY_REVIEW",
            "dns_subdomain_entropy >= 4.5",
            "The subdomain entropy meets the configured review threshold; this alone does not establish tunnelling.",
            "MEDIUM", "dns_subdomain_entropy",
            "dns_subdomain_entropy",
        )

    if "dns_query_length" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "DNS_LONG_QUERY_REVIEW",
            "dns_query_length >= 70",
            "The DNS query meets the configured length threshold; inspect the domain and surrounding context.",
            "LOW", "dns_query_length", "dns_query_length",
        )


def investigate_application(connection, tables, findings):
    source = "Application Security"
    table = SOURCE_TABLES[source]

    if table not in tables:
        print(f"Skipping {source}: table not found.")
        return

    columns = get_columns(connection, table)

    if "app_attack_type" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "APP_RECORDED_ATTACK_CLASSIFICATION",
            """
            app_attack_type IS NOT NULL
            AND TRIM(CAST(app_attack_type AS VARCHAR)) <> ''
            """,
            "The source records an attack classification. Verify the request and detection context.",
            "MEDIUM", "app_attack_type", "app_attack_type",
        )

    if "event_category" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "APP_SECURITY_ALERT_REVIEW",
            "UPPER(COALESCE(event_category, '')) = 'SECURITY_ALERT'",
            "The application event is categorized as a security alert; confirm the raw request and rule context.",
            "MEDIUM", "event_category", "event_category",
        )


def investigate_firewall(connection, tables, findings):
    source = "Firewall"
    table = SOURCE_TABLES[source]

    if table not in tables:
        print(f"Skipping {source}: table not found.")
        return

    columns = get_columns(connection, table)

    if {"fw_action", "fw_rule"}.issubset(columns):
        run_query_check(
            connection, findings, source, table, columns,
            "FIREWALL_ALLOW_DENY_RULE_REVIEW",
            """
            UPPER(COALESCE(fw_action, '')) = 'ALLOW'
            AND UPPER(COALESCE(fw_rule, '')) LIKE '%DENY%'
            """,
            "The action is ALLOW while the rule name contains DENY; verify the firewall's rule naming and action semantics.",
            "MEDIUM", "fw_action/fw_rule", "fw_action",
        )

    if {"fw_protocol", "fw_tcp_flags"}.issubset(columns):
        run_query_check(
            connection, findings, source, table, columns,
            "FIREWALL_PROTOCOL_FLAG_REVIEW",
            """
            UPPER(COALESCE(fw_protocol, '')) <> 'TCP'
            AND UPPER(COALESCE(fw_tcp_flags, ''))
                NOT IN ('', 'NONE', 'NULL')
            """,
            "A non-TCP record contains TCP-style flags; confirm the source format and field semantics.",
            "LOW", "fw_protocol/fw_tcp_flags", "fw_tcp_flags",
        )


def investigate_linux(connection, tables, findings):
    source = "Linux Syslog"
    table = SOURCE_TABLES[source]

    if table not in tables:
        print(f"Skipping {source}: table not found.")
        return

    columns = get_columns(connection, table)

    if "linux_auth_result" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "LINUX_AUTHENTICATION_FAILURE_REVIEW",
            """
            LOWER(COALESCE(linux_auth_result, ''))
            LIKE '%fail%'
            """,
            "The normalized authentication result indicates failure; review the account, host, and message.",
            "LOW", "linux_auth_result", "linux_auth_result",
        )

    if "linux_message" in columns:
        run_query_check(
            connection, findings, source, table, columns,
            "LINUX_PRIVILEGE_ACTIVITY_REVIEW",
            """
            LOWER(COALESCE(linux_message, '')) LIKE '%sudo%'
            """,
            "The message mentions sudo; determine whether the privilege-related activity was expected.",
            "LOW", "linux_message", "linux_message",
        )


def import_windows_findings(findings):
    if not WINDOWS_FINDINGS_FILE.exists():
        print(
            "Windows validation CSV not found; "
            "Windows validation findings will be skipped."
        )
        return

    with WINDOWS_FINDINGS_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        reader = csv.DictReader(file)

        required = {
            "severity", "check_name", "row_number", "event_id",
            "host", "username", "field_name", "observed_value",
            "details",
        }

        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                "Windows findings CSV is missing columns: "
                + ", ".join(sorted(missing))
            )

        for row in reader:
            identity = "|".join(
                text_value(row.get(field))
                for field in (
                    "check_name", "row_number", "event_id",
                    "host", "username", "field_name",
                    "observed_value", "details",
                )
            )

            finding = {
                "investigation_id": stable_id(
                    "Windows Security", row["check_name"], identity
                ),
                "source": "Windows Security",
                "check_name": row["check_name"],
                "severity": row["severity"],
                "event_timestamp": "",
                "source_line_number": row["row_number"],
                "source_event_id": "",
                "host": row["host"],
                "username": row["username"],
                "src_ip": "",
                "dst_ip": "",
                "event_id": row["event_id"],
                "field_name": row["field_name"],
                "observed_value": row["observed_value"],
                "reason_flagged": row["details"],
                "raw_event": "",
                "investigation_status": DEFAULT_STATUS,
                "analyst_notes": "",
                "investigation_outcome": DEFAULT_OUTCOME,
            }
            add_finding(findings, finding)


def preserve_analyst_updates(findings, existing_updates):
    for finding in findings:
        previous = existing_updates.get(
            finding["investigation_id"], {}
        )

        for field in ANALYST_FIELDS:
            value = previous.get(field, "")
            if value:
                finding[field] = value


def write_register(findings):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with REGISTER_FILE.open(
        "w", newline="", encoding="utf-8-sig"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=REGISTER_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(findings)


def write_summary(findings):
    by_source = Counter(row["source"] for row in findings)
    by_severity = Counter(
        (row["severity"] or "UNSPECIFIED").upper()
        for row in findings
    )
    by_check = Counter(
        (row["source"], row["check_name"])
        for row in findings
    )
    by_status = Counter(
        row["investigation_status"] or "UNSPECIFIED"
        for row in findings
    )
    by_outcome = Counter(
        row["investigation_outcome"] or "UNSPECIFIED"
        for row in findings
    )

    lines = [
        "UNIFIED INVESTIGATION REGISTER SUMMARY",
        "=" * 42,
        f"Generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
        f"Total findings: {len(findings):,}",
        "",
        "FINDINGS BY SOURCE",
        "-" * 24,
    ]

    for source in SOURCE_TABLES:
        lines.append(f"{source}: {by_source[source]:,}")

    lines.extend(["", "FINDINGS BY SEVERITY", "-" * 24])
    for severity, count in sorted(by_severity.items()):
        lines.append(f"{severity}: {count:,}")

    lines.extend(["", "FINDINGS BY CHECK", "-" * 24])
    for (source, check_name), count in sorted(by_check.items()):
        lines.append(f"{source} | {check_name}: {count:,}")

    lines.extend(["", "INVESTIGATION STATUS", "-" * 24])
    for status, count in sorted(by_status.items()):
        lines.append(f"{status}: {count:,}")

    lines.extend(["", "INVESTIGATION OUTCOME", "-" * 24])
    for outcome, count in sorted(by_outcome.items()):
        lines.append(f"{outcome}: {count:,}")

    lines.extend([
        "",
        "IMPORTANT NOTES",
        "-" * 24,
        "Every entry is a review lead, not a confirmed incident.",
        "Checks are source-specific; no cross-source correlation is performed.",
        "Only the Windows validation findings CSV is imported as existing findings.",
        "Other sources use the explicit checks defined in this module.",
        "Thresholds and conditions are review criteria, not proof of malicious activity.",
        "The DuckDB connection is read-only.",
        "The original Windows validation findings CSV is not modified.",
        "",
        "OUTPUT FILES",
        str(REGISTER_FILE),
        str(SUMMARY_FILE),
    ])

    SUMMARY_FILE.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    existing_updates = load_existing_updates()
    findings = []

    print("UNIFIED INVESTIGATION REGISTER")
    print("=" * 36)
    print("Database mode: READ ONLY")
    print("Cross-source correlation: OUT OF SCOPE")

    if not DB_FILE.is_file():
        raise FileNotFoundError(f"Database not found: {DB_FILE}")

    with duckdb.connect(str(DB_FILE), read_only=True) as connection:
        tables = get_tables(connection)

        investigate_dns(connection, tables, findings)
        investigate_application(connection, tables, findings)
        investigate_firewall(connection, tables, findings)
        investigate_linux(connection, tables, findings)

    # Use the dedicated validation output for Windows findings.
    import_windows_findings(findings)

    # Keep the first instance of any repeated finding ID.
    unique_findings = {}
    for finding in findings:
        unique_findings.setdefault(
            finding["investigation_id"], finding
        )
    findings = list(unique_findings.values())

    preserve_analyst_updates(findings, existing_updates)
    write_register(findings)
    write_summary(findings)

    print(f"\nTotal findings: {len(findings):,}")
    for source in SOURCE_TABLES:
        count = sum(1 for row in findings if row["source"] == source)
        print(f"  {source}: {count:,}")

    print(f"\nRegister: {REGISTER_FILE}")
    print(f"Summary:  {SUMMARY_FILE}")
    print("\nDatabase and source validation files were not modified.")


if __name__ == "__main__":
    main()
