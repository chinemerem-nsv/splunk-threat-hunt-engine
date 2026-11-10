
from pathlib import Path
from datetime import datetime
import sys

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"
LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"

# Each table is investigated independently. No cross-source correlation.
SOURCE_TABLES = {
    "DNS": "normalized_events",
    "Application Security": "normalized_app_events",
    "Firewall": "normalized_firewall_events",
    "Linux Syslog": "normalized_linux_events",
    "Windows Security": "normalized_windows_events",
}

MAX_ROWS = 10


class Tee:
    """Write output to both the terminal and a report file."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def show_rows(connection, query, parameters=None, limit=MAX_ROWS):
    result = connection.execute(query, parameters or []).fetchall()
    columns = [item[0] for item in connection.description]

    if not result:
        print("No matching records.")
        return

    print(" | ".join(columns))

    for row in result[:limit]:
        values = []

        for value in row:
            display = str(value) if value is not None else "NULL"
            if len(display) > 350:
                display = display[:350] + "...[truncated]"
            values.append(display)

        print(" | ".join(values))

    if len(result) > limit:
        print(f"... {len(result) - limit:,} additional rows not displayed.")


def get_tables(connection):
    return {
        row[0]
        for row in connection.execute("SHOW TABLES").fetchall()
    }


def get_columns(connection, table):
    return {
        row[0]
        for row in connection.execute(f'DESCRIBE "{table}"').fetchall()
    }


def table_available(connection, tables, table):
    if table not in tables:
        print(f"Table unavailable: {table}")
        return False
    return True


def common_source_review(connection, table):
    print(f"\nSource table: {table}")

    result = connection.execute(
        f"""
        SELECT
            COUNT(*) AS total_records,
            COUNT(event_id) AS records_with_event_id,
            COUNT(DISTINCT event_id) AS distinct_event_ids,
            COUNT(*) FILTER (
                WHERE event_id IS NULL
                   OR TRIM(CAST(event_id AS VARCHAR)) = ''
            ) AS missing_event_ids,
            COUNT(*) FILTER (
                WHERE event_timestamp IS NOT NULL
            ) AS timestamped_records,
            COUNT(*) FILTER (
                WHERE event_timestamp IS NULL
            ) AS missing_timestamps,
            MIN(event_timestamp) AS earliest_timestamp,
            MAX(event_timestamp) AS latest_timestamp
        FROM "{table}"
        """
    ).fetchone()

    labels = [
        "Total records",
        "Records with event ID",
        "Distinct event IDs",
        "Missing event IDs",
        "Timestamped records",
        "NULL timestamps",
        "Earliest timestamp",
        "Latest timestamp",
    ]

    for label, value in zip(labels, result):
        if isinstance(value, int):
            value = f"{value:,}"
        print(f"  {label}: {value}")

    raw_count = connection.execute(
        f"""
        SELECT COUNT(*)
        FROM "{table}"
        WHERE raw_event IS NULL
           OR TRIM(CAST(raw_event AS VARCHAR)) = ''
        """
    ).fetchone()[0]

    print(f"  Missing/empty raw events: {raw_count:,}")

    if result[0] != result[2] or result[3] > 0:
        print("  Integrity warning: event IDs are missing or duplicated.")
    else:
        print("  Event ID check: no missing or duplicate event IDs.")

    if result[5] > 0:
        print(
            "  Timestamp note: some records lack normalized timestamps. "
            "Investigate this source's timestamp format before using "
            "time-based detections."
        )


def dns_investigation(connection, tables):
    section("1. DNS INVESTIGATION")
    table = SOURCE_TABLES["DNS"]

    if not table_available(connection, tables, table):
        return

    columns = get_columns(connection, table)
    common_source_review(connection, table)

    print("\nDNS query types and response codes:")
    show_rows(connection, f"""
        SELECT dns_query_type, dns_response_code, COUNT(*) AS records
        FROM "{table}"
        GROUP BY dns_query_type, dns_response_code
        ORDER BY records DESC LIMIT 15
    """)

    if "source_labels" in columns:
        print("\nExisting source labels:")
        show_rows(connection, f"""
            SELECT label, COUNT(*) AS records
            FROM (
                SELECT UNNEST(source_labels) AS label
                FROM "{table}"
            ) labels
            GROUP BY label
            ORDER BY records DESC LIMIT 15
        """)

    print("\nHighest-entropy DNS queries:")
    show_rows(connection, f"""
        SELECT event_timestamp, src_ip, dns_query, dns_query_type,
               dns_subdomain_entropy, dns_query_length, source_labels
        FROM "{table}"
        WHERE dns_subdomain_entropy IS NOT NULL
        ORDER BY dns_subdomain_entropy DESC LIMIT 10
    """)

    print("\nLongest DNS queries:")
    show_rows(connection, f"""
        SELECT event_timestamp, src_ip, dns_query, dns_query_length,
               dns_subdomain_entropy, source_labels
        FROM "{table}"
        WHERE dns_query_length IS NOT NULL
        ORDER BY dns_query_length DESC LIMIT 10
    """)

    print(
        "\nInterpretation: entropy, query length, and source labels are "
        "investigation leads, not proof of DNS tunnelling or C2 activity."
    )


def application_investigation(connection, tables):
    section("2. APPLICATION SECURITY INVESTIGATION")
    table = SOURCE_TABLES["Application Security"]

    if not table_available(connection, tables, table):
        return

    common_source_review(connection, table)

    print("\nEvent categories:")
    show_rows(connection, f"""
        SELECT event_category, COUNT(*) AS records
        FROM "{table}"
        GROUP BY event_category
        ORDER BY records DESC
    """)

    print("\nRecorded attack classifications:")
    show_rows(connection, f"""
        SELECT app_attack_type, severity, app_detection,
               COUNT(*) AS records
        FROM "{table}"
        WHERE app_attack_type IS NOT NULL
          AND TRIM(app_attack_type) <> ''
        GROUP BY app_attack_type, severity, app_detection
        ORDER BY records DESC LIMIT 20
    """)

    print("\nHTTP status distribution:")
    show_rows(connection, f"""
        SELECT app_status, COUNT(*) AS records
        FROM "{table}"
        GROUP BY app_status
        ORDER BY records DESC LIMIT 15
    """)

    print("\nAuthentication field distribution:")
    show_rows(connection, f"""
        SELECT app_auth, COUNT(*) AS records
        FROM "{table}"
        GROUP BY app_auth
        ORDER BY records DESC LIMIT 15
    """)

    print("\nReused source ID summary:")
    show_rows(connection, f"""
        WITH repeated_ids AS (
            SELECT source_event_id, COUNT(*) AS record_count
            FROM "{table}"
            WHERE source_event_id IS NOT NULL
              AND TRIM(source_event_id) <> ''
            GROUP BY source_event_id
            HAVING COUNT(*) > 1
        )
        SELECT COUNT(*) AS repeated_id_groups,
               COALESCE(SUM(record_count - 1), 0) AS excess_occurrences
        FROM repeated_ids
    """)

    print("\nMost-repeated source IDs:")
    show_rows(connection, f"""
        SELECT source_event_id,
               COUNT(*) AS records,
               COUNT(DISTINCT raw_event) AS distinct_raw_events,
               COUNT(DISTINCT event_timestamp) AS distinct_timestamps,
               COUNT(DISTINCT src_ip) AS distinct_source_ips,
               COUNT(DISTINCT app_uri) AS distinct_uris
        FROM "{table}"
        WHERE source_event_id IS NOT NULL
          AND TRIM(source_event_id) <> ''
        GROUP BY source_event_id
        HAVING COUNT(*) > 1
        ORDER BY records DESC, source_event_id
        LIMIT 10
    """)

    print("\nRepresentative recorded security alerts:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, src_ip, username,
               app_method, app_uri, app_status, app_attack_type,
               severity, raw_event
        FROM "{table}"
        WHERE UPPER(COALESCE(event_category, '')) = 'SECURITY_ALERT'
           OR (
               app_attack_type IS NOT NULL
               AND TRIM(app_attack_type) <> ''
           )
        ORDER BY source_line_number LIMIT 10
    """)

    print(
        "\nInterpretation: attack labels and signature matches describe "
        "what the source recorded. Validate the raw request and context "
        "before treating a label as confirmed malicious activity."
    )


def firewall_investigation(connection, tables):
    section("3. FIREWALL INVESTIGATION")
    table = SOURCE_TABLES["Firewall"]

    if not table_available(connection, tables, table):
        return

    common_source_review(connection, table)

    print("\nAction and rule combinations:")
    show_rows(connection, f"""
        SELECT fw_action, fw_rule, COUNT(*) AS records
        FROM "{table}"
        GROUP BY fw_action, fw_rule
        ORDER BY records DESC LIMIT 20
    """)

    print("\nProtocol and TCP-flag combinations:")
    show_rows(connection, f"""
        SELECT fw_protocol, fw_tcp_flags, COUNT(*) AS records
        FROM "{table}"
        GROUP BY fw_protocol, fw_tcp_flags
        ORDER BY records DESC LIMIT 25
    """)

    print("\nNon-TCP records with TCP-style flags:")
    show_rows(connection, f"""
        SELECT fw_protocol, fw_tcp_flags, COUNT(*) AS records
        FROM "{table}"
        WHERE UPPER(COALESCE(fw_protocol, '')) <> 'TCP'
          AND UPPER(COALESCE(fw_tcp_flags, ''))
              NOT IN ('', 'NONE', 'NULL')
        GROUP BY fw_protocol, fw_tcp_flags
        ORDER BY records DESC LIMIT 20
    """)

    print("\nALLOW actions paired with DENY-named rules:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, src_ip, dst_ip,
               fw_src_port, fw_dst_port, fw_protocol, fw_action, fw_rule,
               fw_tcp_flags, raw_event
        FROM "{table}"
        WHERE UPPER(COALESCE(fw_action, '')) = 'ALLOW'
          AND UPPER(COALESCE(fw_rule, '')) LIKE '%DENY%'
        ORDER BY source_line_number LIMIT 10
    """)

    print(
        "\nInterpretation: these combinations are quality or semantics "
        "checks. Confirm the firewall's field definitions before deciding "
        "that a record represents a real policy violation."
    )


def linux_investigation(connection, tables):
    section("4. LINUX SYSLOG INVESTIGATION")
    table = SOURCE_TABLES["Linux Syslog"]

    if not table_available(connection, tables, table):
        return

    common_source_review(connection, table)

    print("\nHost distribution:")
    show_rows(connection, f"""
        SELECT linux_hostname, COUNT(*) AS records
        FROM "{table}"
        GROUP BY linux_hostname
        ORDER BY records DESC LIMIT 20
    """)

    print("\nProcess distribution:")
    show_rows(connection, f"""
        SELECT linux_process, COUNT(*) AS records
        FROM "{table}"
        GROUP BY linux_process
        ORDER BY records DESC LIMIT 20
    """)

    print("\nRecorded authentication classifications:")
    show_rows(connection, f"""
        SELECT linux_auth_result, COUNT(*) AS records
        FROM "{table}"
        GROUP BY linux_auth_result
        ORDER BY records DESC
    """)

    print("\nRepresentative authentication-related messages:")
    show_rows(connection, f"""
        SELECT source_line_number, source_timestamp, linux_hostname,
               linux_process, linux_pid, username, linux_auth_result,
               linux_message, raw_event
        FROM "{table}"
        WHERE LOWER(COALESCE(linux_message, '')) LIKE '%failed%'
           OR LOWER(COALESCE(linux_message, '')) LIKE '%accepted%'
           OR LOWER(COALESCE(linux_message, '')) LIKE '%session opened%'
           OR LOWER(COALESCE(linux_message, '')) LIKE '%sudo%'
        ORDER BY source_line_number LIMIT 10
    """)

    print(
        "\nTimestamp note: the source uses month/day/time without a year. "
        "Keep source_timestamp and event_timestamp unchanged until "
        "reliable year context is established."
    )


def windows_investigation(connection, tables):
    section("5. WINDOWS SECURITY INVESTIGATION")
    table = SOURCE_TABLES["Windows Security"]

    if not table_available(connection, tables, table):
        source_file = LOG_DIR / "windows_security_events.log"

        if source_file.is_file():
            print(f"Source file found: {source_file}")
            print(
                "The Windows source is not yet available "
                "as a normalized table."
            )
            print("No Windows events were queried or modified.")
        else:
            print(f"Windows table and source file not found: {table}")

        return

    columns = get_columns(connection, table)
    common_source_review(connection, table)

    for field in (
        "host",
        "win_event_id",
        "win_event_type",
        "event_action",
        "severity",
        "username",
    ):
        if field not in columns:
            continue

        print(f"\nWindows distribution by {field}:")
        show_rows(connection, f"""
            SELECT "{field}", COUNT(*) AS records
            FROM "{table}"
            GROUP BY "{field}"
            ORDER BY records DESC LIMIT 15
        """)

    if "win_event_type" in columns:
        print("\nRecorded Windows event-type distribution:")
        show_rows(connection, f"""
            SELECT win_event_type, COUNT(*) AS records
            FROM "{table}"
            GROUP BY win_event_type
            ORDER BY records DESC LIMIT 20
        """)

    if "win_event_id" not in columns:
        print(
            "\nWindows-specific checks skipped: "
            "win_event_id field is unavailable."
        )
        return

    event_id_expr = 'TRY_CAST("win_event_id" AS INTEGER)'

    print("\n4624 — recorded successful logons:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, win_event_id,
               event_action, username, src_ip, win_process,
               win_command_line, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4624
        ORDER BY event_timestamp, source_line_number LIMIT 10
    """)

    print("\n4624 — distribution by host and account:")
    show_rows(connection, f"""
        SELECT host, username, COUNT(*) AS records,
               COUNT(DISTINCT src_ip) AS distinct_source_ips
        FROM "{table}"
        WHERE {event_id_expr} = 4624
        GROUP BY host, username
        ORDER BY records DESC LIMIT 15
    """)

    print("\n4634 — recorded logoff events by host and account:")
    show_rows(connection, f"""
        SELECT host, username, COUNT(*) AS records
        FROM "{table}"
        WHERE {event_id_expr} = 4634
        GROUP BY host, username
        ORDER BY records DESC LIMIT 15
    """)

    print("\n4688 — process creation records with command lines:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               win_process, win_command_line, src_ip, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4688
          AND win_command_line IS NOT NULL
          AND TRIM(CAST(win_command_line AS VARCHAR)) <> ''
        ORDER BY source_line_number LIMIT 10
    """)

    print(
        "\n4688 — command lines containing review-worthy "
        "scripting or execution terms:"
    )
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               win_process, win_command_line, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4688
          AND (
              LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%powershell%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%-enc%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%encodedcommand%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '% -w hidden%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%downloadstring%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%frombase64string%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%rundll32%'
              OR LOWER(COALESCE(CAST(win_command_line AS VARCHAR), ''))
                  LIKE '%regsvr32%'
          )
        ORDER BY source_line_number LIMIT 10
    """)

    print("\n4104 — PowerShell script-related events:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               win_process, win_command_line, severity, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4104
        ORDER BY source_line_number LIMIT 10
    """)

    print("\n5156/5157 — allowed/blocked network filtering events:")
    show_rows(connection, f"""
        SELECT win_event_id, event_action, host, username, src_ip,
               win_process, win_command_line, severity,
               COUNT(*) AS records
        FROM "{table}"
        WHERE {event_id_expr} IN (5156, 5157)
        GROUP BY win_event_id, event_action, host, username, src_ip,
                 win_process, win_command_line, severity
        ORDER BY records DESC LIMIT 15
    """)

    print("\n5157 — representative blocked connection events:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               src_ip, win_process, win_command_line, severity, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 5157
        ORDER BY source_line_number LIMIT 10
    """)

    print("\n4698 — scheduled-task creation events:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               win_process, win_command_line, severity, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4698
        ORDER BY source_line_number LIMIT 10
    """)

    print("\n1102 — security audit log-clearing records:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               event_action, severity, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 1102
        ORDER BY event_timestamp, source_line_number LIMIT 10
    """)

    print("\n4697 — service installation events:")
    show_rows(connection, f"""
        SELECT source_line_number, event_timestamp, host, username,
               win_process, win_command_line, severity, raw_event
        FROM "{table}"
        WHERE {event_id_expr} = 4697
        ORDER BY source_line_number LIMIT 10
    """)

    print(
        "\nInterpretation: these are source-record-based review queries. "
        "Event IDs and labels are not, by themselves, proof of malicious "
        "activity. Command-line terms can have legitimate uses; review "
        "full raw events and relevant host context before assigning a verdict."
    )


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"investigation_report_{timestamp}.txt"

    original_stdout = sys.stdout
    original_stderr = sys.stderr

    try:
        with report_file.open("w", encoding="utf-8") as report:
            sys.stdout = Tee(original_stdout, report)
            sys.stderr = Tee(original_stderr, report)

            print(f"Investigation report: {report_file}")
            print("=" * 78)
            print("SPLUNK THREAT HUNT ENGINE")
            print("SOURCE-BY-SOURCE INVESTIGATION CHECKS")
            print("=" * 78)
            print(f"Database: {DB_FILE}")
            print("Mode: READ ONLY")
            print("Cross-source event correlation: OUT OF SCOPE")

            try:
                if not DB_FILE.is_file():
                    raise FileNotFoundError(
                        f"Database not found: {DB_FILE}"
                    )

                with duckdb.connect(
                    str(DB_FILE),
                    read_only=True,
                ) as connection:
                    tables = get_tables(connection)

                    print(f"\nDatabase tables found: {len(tables)}")
                    for table in sorted(tables):
                        print(f"  {table}")

                    dns_investigation(connection, tables)
                    application_investigation(connection, tables)
                    firewall_investigation(connection, tables)
                    linux_investigation(connection, tables)
                    windows_investigation(connection, tables)

                print("\n" + "=" * 78)
                print("SOURCE-BY-SOURCE INVESTIGATION COMPLETED")
                print(
                    "Database unchanged: all database connections "
                    "were read-only."
                )
                print("No cross-source event correlation was performed.")
                print("=" * 78)

            except Exception as error:
                print(
                    f"\nINVESTIGATION ERROR: {error}",
                    file=sys.stderr,
                )
                raise

    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr

    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
