
from pathlib import Path
import csv
import json
import re
import sys

import duckdb


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"
TABLE_NAME = "normalized_windows_events"
OUTPUT_FILE = (
    Path(__file__).resolve().parent / "windows_validation_findings.csv"
)

BATCH_SIZE = 5000
VERBOSE = True


# ============================================================
# GENERAL HELPERS
# ============================================================

def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip()


def is_missing(value):
    return value is None or normalize_text(value) == ""


def normalize_quoted_value(value):
    """Normalize common quote and backslash escaping."""
    if value is None:
        return ""

    value = value.replace(r"\"", '"').replace(r"\'", "'")
    value = value.replace("\\\\", "\\")
    return value


def safe_json_loads(value):
    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def parse_key_value_event(value):
    """Parse quoted and unquoted key-value event fields."""
    if not isinstance(value, str) or not value.strip():
        return None

    pattern = re.compile(
        r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)="""
        r"""(?:"(?P<double>(?:\\.|[^"\\])*)"|'(?P<single>(?:\\.|[^'\\])*)'|(?P<bare>\S*))"""
    )

    parsed = {}

    for match in pattern.finditer(value):
        key = match.group("key").lower()

        if match.group("double") is not None:
            field_value = normalize_quoted_value(match.group("double"))
        elif match.group("single") is not None:
            field_value = normalize_quoted_value(match.group("single"))
        else:
            field_value = match.group("bare") or ""

        parsed.setdefault(key, field_value)

    return parsed or None


def parse_raw_event(value):
    """Support JSON objects and plain-text key-value events."""
    json_value = safe_json_loads(value)

    if isinstance(json_value, dict):
        return json_value, "JSON"

    if isinstance(json_value, list):
        return None, "JSON_NON_OBJECT"

    if not isinstance(value, str) or not value.strip():
        return None, "EMPTY"

    parsed_text = parse_key_value_event(value)

    if parsed_text is not None:
        return parsed_text, "KEY_VALUE_TEXT"

    return None, "UNPARSED"


def flatten_dict(data, prefix=""):
    flattened = {}

    if not isinstance(data, dict):
        return flattened

    for key, value in data.items():
        key = str(key)
        full_key = f"{prefix}.{key}" if prefix else key

        if isinstance(value, dict):
            flattened.update(flatten_dict(value, full_key))
        else:
            flattened[full_key] = value

    return flattened


def find_value(raw_data, candidate_names):
    """Find a raw field by case-insensitive leaf name."""
    if not isinstance(raw_data, dict):
        return None, None

    flattened = flatten_dict(raw_data)
    candidates = {str(name).lower() for name in candidate_names}

    for field_name, value in flattened.items():
        leaf_name = field_name.rsplit(".", 1)[-1].lower()

        if leaf_name in candidates:
            return value, field_name

    for field_name, value in flattened.items():
        if field_name.lower() in candidates:
            return value, field_name

    return None, None


def normalize_windows_event_id(value):
    """Normalize a Windows Event ID without extracting arbitrary numbers."""
    if value is None or isinstance(value, bool):
        return ""

    if isinstance(value, int):
        return str(value) if value >= 0 else ""

    if isinstance(value, float):
        if value >= 0 and value.is_integer():
            return str(int(value))
        return ""

    text_value = normalize_text(value)

    if text_value.isdigit():
        return str(int(text_value))

    match = re.fullmatch(
        r"(?:windows\s+)?event\s*(?:id)?\s*[:=#-]?\s*(\d+)",
        text_value,
        flags=re.IGNORECASE,
    )

    return str(int(match.group(1))) if match else ""


def quote_identifier(identifier):
    return '"' + str(identifier).replace('"', '""') + '"'


def get_record_value(record, selected, logical_field):
    column = selected.get(logical_field)
    return record.get(column) if column else None


def add_finding(
    findings,
    severity,
    check_name,
    row_number,
    event_id,
    host,
    username,
    field_name,
    observed_value,
    details,
):
    findings.append({
        "severity": severity,
        "check_name": check_name,
        "row_number": row_number,
        "event_id": normalize_text(event_id),
        "host": normalize_text(host),
        "username": normalize_text(username),
        "field_name": field_name or "",
        "observed_value": normalize_text(observed_value),
        "details": details,
    })


# ============================================================
# DATABASE DISCOVERY
# ============================================================

def locate_database():
    candidates = [DB_FILE]

    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "threat_hunt.duckdb")

    checked = set()

    for candidate in candidates:
        candidate = candidate.resolve()

        if candidate in checked:
            continue

        checked.add(candidate)

        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "Could not locate threat_hunt.duckdb. "
        "Check PROJECT_ROOT and DB_FILE."
    )


def discover_table(connection, preferred_name):
    rows = connection.execute("""
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'main'
        ORDER BY table_name
    """).fetchall()

    tables = [row[0] for row in rows]

    if preferred_name in tables:
        return preferred_name

    section("DATABASE TABLE DISCOVERY")
    print(f"Requested table: {preferred_name}")
    print("Available tables:")

    for table in tables:
        print(f"  - {table}")

    raise RuntimeError(f"Table '{preferred_name}' was not found.")


# ============================================================
# FIELD DISCOVERY
# ============================================================

FIELD_ALIASES = {
    "event_id": [
        "win_event_id",
        "windows_event_id",
        "eventid",
        "Event ID",
        "event_id",
    ],
    "record_id": [
        "event_id",
        "record_id",
        "event_record_id",
    ],
    "provider": [
        "provider",
        "provider_name",
        "source_provider",
        "ProviderName",
    ],
    "channel": [
        "win_channel",
        "channel",
        "log_channel",
        "event_channel",
    ],
    "timestamp": [
        "event_timestamp",
        "timestamp",
        "time_created",
        "TimeCreated",
        "system_time",
    ],
    "host": [
        "host",
        "hostname",
        "computer",
        "computer_name",
    ],
    "username": [
        "username",
        "user",
        "user_name",
        "target_user_name",
        "subject_user_name",
        "account_name",
    ],
    "process": [
        "win_process",
        "process_name",
        "process",
        "image",
    ],
    "command_line": [
        "win_command_line",
        "command_line",
        "process_command_line",
    ],
    "event_type": [
        "win_event_type",
        "event_type",
        "category",
        "event_category",
    ],
    "severity": [
        "severity",
        "risk_level",
        "alert_severity",
    ],
    "source_event_id": [
        "source_event_id",
        "event_record_id",
        "record_id",
    ],
    "raw_event": [
        "raw_event",
        "raw_json",
        "raw",
        "event_json",
        "original_event",
    ],
}


RAW_FIELD_CANDIDATES = {
    "event_id": ["event_id", "eventid", "windows_event_id"],
    "provider": ["provider", "provider_name", "providername"],
    "channel": ["channel", "log_channel"],
    "host": ["host", "hostname", "computer", "computer_name"],
    "username": [
        "username",
        "user",
        "user_name",
        "account_name",
        "targetusername",
        "subjectusername",
    ],
    "process": ["win_process", "process_name", "process", "image"],
    "command_line": [
        "win_command_line",
        "command_line",
        "process_command_line",
    ],
    "event_type": ["event_type", "category", "event_category"],
}


def discover_fields(columns):
    lower_to_actual = {column.lower(): column for column in columns}
    selected = {}

    for logical_name, aliases in FIELD_ALIASES.items():
        selected[logical_name] = next(
            (
                lower_to_actual[alias.lower()]
                for alias in aliases
                if alias.lower() in lower_to_actual
            ),
            None,
        )

    return selected


# ============================================================
# VALIDATION CHECKS
# ============================================================

def compare_with_raw(
    findings,
    row_number,
    record,
    selected,
    parsed_raw,
    event_id,
    host,
    username,
):
    if not isinstance(parsed_raw, dict):
        return

    for logical_field, candidates in RAW_FIELD_CANDIDATES.items():
        column = selected.get(logical_field)

        if not column:
            continue

        normalized_value = record.get(column)
        raw_value, raw_field_name = find_value(parsed_raw, candidates)

        if raw_field_name is None:
            continue

        if is_missing(normalized_value) or is_missing(raw_value):
            continue

        if logical_field == "event_id":
            left = normalize_windows_event_id(normalized_value)
            right = normalize_windows_event_id(raw_value)

            if not left or not right:
                continue
        else:
            left = normalize_text(normalized_value).casefold()
            right = normalize_text(raw_value).casefold()

        if left != right:
            add_finding(
                findings,
                "MEDIUM",
                "NORMALIZED_RAW_FIELD_MISMATCH",
                row_number,
                event_id,
                host,
                username,
                logical_field,
                normalized_value,
                f"Normalized value differs from raw field "
                f"'{raw_field_name}'. Raw value: {raw_value!r}. "
                "Review extraction and normalization.",
            )


def check_required_fields(
    findings,
    row_number,
    record,
    selected,
    event_id,
    host,
    username,
):
    for logical_field in ("event_id", "channel", "host"):
        column = selected.get(logical_field)

        if not column:
            continue

        value = record.get(column)

        if is_missing(value):
            add_finding(
                findings,
                "MEDIUM",
                "MISSING_CORE_FIELD",
                row_number,
                event_id,
                host,
                username,
                logical_field,
                value,
                f"Column '{column}' is empty. Review the source record "
                "and extraction logic.",
            )


def check_event_4104(
    findings,
    row_number,
    record,
    selected,
    parsed_raw,
    event_id,
    host,
    username,
):
    if normalize_windows_event_id(event_id) != "4104":
        return

    event_type = get_record_value(record, selected, "event_type")
    process = get_record_value(record, selected, "process")
    command_line = get_record_value(record, selected, "command_line")

    raw_message, _ = (
        find_value(parsed_raw, ["message"])
        if isinstance(parsed_raw, dict)
        else (None, None)
    )

    label = normalize_text(event_type).casefold()
    context = " ".join([
        normalize_text(process),
        normalize_text(command_line),
        normalize_text(raw_message),
    ]).casefold()

    if (
        label
        and "powershell" not in label
        and "script" not in label
        and "powershell" not in context
        and "script block" not in context
    ):
        add_finding(
            findings,
            "MEDIUM",
            "EVENT_4104_CLASSIFICATION_REVIEW",
            row_number,
            event_id,
            host,
            username,
            "event_type",
            event_type,
            "Event ID 4104 is commonly associated with PowerShell "
            "script-block logging, but the available label and context "
            "do not clearly reflect that. Verify the source event.",
        )


def executable_basename(value):
    """
    Extract an executable name from a path or command-line executable token.
    This does not attempt to interpret the remaining command arguments.
    """
    text = normalize_text(value)

    if not text:
        return ""

    if text.startswith('"'):
        match = re.match(r'"([^"]+)"', text)

        if not match:
            return ""

        executable = match.group(1)
    else:
        executable = text.split(maxsplit=1)[0]

    executable = executable.replace("\\", "/").rsplit("/", 1)[-1]

    return executable.casefold()


def check_process_command_consistency(
    findings,
    row_number,
    record,
    selected,
    event_id,
    host,
    username,
):
    """
    Compare executable names only for Event ID 4688 (process creation).

    Other event types may store a script, parent process, or contextual
    command text in a field that is not the executable being audited.
    """
    if normalize_windows_event_id(event_id) != "4688":
        return

    process = normalize_text(
        get_record_value(record, selected, "process")
    )
    command_line = normalize_text(
        get_record_value(record, selected, "command_line")
    )

    if not process or not command_line:
        return

    process_executable = executable_basename(process)
    command_executable = executable_basename(command_line)

    if not process_executable or not command_executable:
        return

    if process_executable == command_executable:
        return

    add_finding(
        findings,
        "LOW",
        "PROCESS_COMMAND_LINE_REVIEW",
        row_number,
        event_id,
        host,
        username,
        "process",
        process,
        f"For Event ID 4688, the process field resolves to "
        f"'{process_executable}', while the first executable token in "
        f"the command line resolves to '{command_executable}'. "
        "Verify the raw event and confirm that both fields describe "
        "the same process before treating this as a mismatch.",
    )


def check_simulated_markers(
    findings,
    row_number,
    record,
    selected,
    raw_text,
    event_id,
    host,
    username,
):
    """
    Flag explicit test/simulation phrases.

    The broad SIMULATED_ substring is intentionally excluded because it
    can occur in generic dataset labels and produce large volumes of noise.
    """
    searchable = [normalize_text(raw_text)]

    for field in ("event_type", "command_line"):
        value = get_record_value(record, selected, field)

        if value is not None:
            searchable.append(normalize_text(value))

    text = " ".join(searchable)

    marker_patterns = (
        r"\bSIMULATED ATTACK\b",
        r"\bSYNTHETIC EVENT\b",
        r"\bTEST EVENT\b",
        r"\bTEST_RECORD\b",
        r"\bSIMULATION\s*=\s*TRUE\b",
    )

    matched = [
        pattern
        for pattern in marker_patterns
        if re.search(pattern, text, flags=re.IGNORECASE)
    ]

    if not matched:
        return

    add_finding(
        findings,
        "INFO",
        "SIMULATED_OR_TEST_DATA_MARKER",
        row_number,
        event_id,
        host,
        username,
        "raw_event",
        "; ".join(matched),
        "An explicit test or simulation marker was found. Treat this "
        "as dataset context, not proof of a real-world attack.",
    )


def check_special_event_ids(
    findings,
    row_number,
    event_id,
    host,
    username,
):
    """
    Generate contextual review leads for selected security-relevant events.

    Routine network allow/block events (5156 and 5157) remain part of
    dataset statistics but do not create one finding per event.
    """
    notes = {
        "1102": (
            "Windows Security audit log cleared. Verify authorization, "
            "the initiator, and surrounding events."
        ),
        "4697": (
            "A service was installed. Review its binary path, account, "
            "initiator, and authorization."
        ),
        "4698": (
            "A scheduled task was created. Review its action, execution "
            "account, initiator, and authorization."
        ),
    }

    normalized_id = normalize_windows_event_id(event_id)
    note = notes.get(normalized_id)

    if not note:
        return

    severity = "MEDIUM" if normalized_id == "1102" else "INFO"

    add_finding(
        findings,
        severity,
        "EVENT_ID_CONTEXT_REVIEW",
        row_number,
        event_id,
        host,
        username,
        "win_event_id",
        normalized_id,
        note,
    )


# ============================================================
# MAIN VALIDATION
# ============================================================

def main():
    section("WINDOWS EVENT VALIDATION")

    database_path = locate_database()

    print(f"Database: {database_path}")
    print(f"Table requested: {TABLE_NAME}")
    print(f"Output CSV: {OUTPUT_FILE}")
    print("Database mode: READ-ONLY")

    connection = duckdb.connect(str(database_path), read_only=True)
    findings = []

    try:
        table_name = discover_table(connection, TABLE_NAME)
        quoted_table = quote_identifier(table_name)

        column_rows = connection.execute(
            f"PRAGMA table_info({quoted_table})"
        ).fetchall()

        columns = [row[1] for row in column_rows]

        section("TABLE SCHEMA")
        print(f"Table: {table_name}")
        print(f"Column count: {len(columns)}")

        for column in columns:
            print(f"  - {column}")

        selected = discover_fields(columns)

        section("LOGICAL FIELD MAPPING")

        for logical_field, actual_column in selected.items():
            print(
                f"{logical_field:16} -> "
                f"{actual_column if actual_column else 'NOT FOUND'}"
            )

        if not selected.get("event_id"):
            raise RuntimeError(
                "No Windows Event ID column found. "
                "Expected win_event_id or a recognized alias."
            )

        section("DATASET SUMMARY")

        row_count = connection.execute(
            f"SELECT COUNT(*) FROM {quoted_table}"
        ).fetchone()[0]

        print(f"Rows to check: {row_count:,}")

        # Start the row cursor after the COUNT query has completed.
        cursor = connection.execute(f"SELECT * FROM {quoted_table}")

        checked = 0
        missing_event_id_count = 0
        raw_format_counts = {}
        event_id_counts = {}
        record_id_counts = {}
        source_id_counts = {}

        raw_column = selected.get("raw_event")
        record_id_column = selected.get("record_id")
        source_id_column = selected.get("source_event_id")

        while True:
            batch = cursor.fetchmany(BATCH_SIZE)

            if not batch:
                break

            for row in batch:
                checked += 1
                record = dict(zip(columns, row))

                event_id = record.get(selected["event_id"])
                host = get_record_value(record, selected, "host")
                username = get_record_value(record, selected, "username")

                normalized_id = normalize_windows_event_id(event_id)

                if not normalized_id:
                    missing_event_id_count += 1
                else:
                    event_id_counts[normalized_id] = (
                        event_id_counts.get(normalized_id, 0) + 1
                    )

                if record_id_column:
                    record_id = normalize_text(
                        record.get(record_id_column)
                    )

                    if record_id:
                        record_id_counts[record_id] = (
                            record_id_counts.get(record_id, 0) + 1
                        )

                if source_id_column:
                    source_id = normalize_text(
                        record.get(source_id_column)
                    )

                    if source_id:
                        source_id_counts[source_id] = (
                            source_id_counts.get(source_id, 0) + 1
                        )

                raw_text = record.get(raw_column) if raw_column else None
                parsed_raw, raw_format = parse_raw_event(raw_text)

                raw_format_counts[raw_format] = (
                    raw_format_counts.get(raw_format, 0) + 1
                )

                check_required_fields(
                    findings,
                    checked,
                    record,
                    selected,
                    event_id,
                    host,
                    username,
                )

                if parsed_raw is not None:
                    compare_with_raw(
                        findings,
                        checked,
                        record,
                        selected,
                        parsed_raw,
                        event_id,
                        host,
                        username,
                    )

                check_event_4104(
                    findings,
                    checked,
                    record,
                    selected,
                    parsed_raw,
                    event_id,
                    host,
                    username,
                )

                check_process_command_consistency(
                    findings,
                    checked,
                    record,
                    selected,
                    event_id,
                    host,
                    username,
                )

                check_simulated_markers(
                    findings,
                    checked,
                    record,
                    selected,
                    raw_text,
                    event_id,
                    host,
                    username,
                )

                check_special_event_ids(
                    findings,
                    checked,
                    event_id,
                    host,
                    username,
                )

            if VERBOSE and (checked % 50000 == 0 or checked == row_count):
                print(f"Processed {checked:,} / {row_count:,} rows")

        section("VALIDATION COUNTS")

        print(f"Total rows checked: {checked:,}")
        print(
            "Rows with missing/invalid Windows Event ID: "
            f"{missing_event_id_count:,}"
        )

        print("\nRaw-event formats:")

        for format_name, count in sorted(raw_format_counts.items()):
            print(f"  {format_name}: {count:,}")

        print(f"\nDistinct Windows Event IDs: {len(event_id_counts):,}")
        print("Most frequent Windows Event IDs:")

        for event_id, count in sorted(
            event_id_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:10]:
            print(f"  {event_id}: {count:,}")

        # Repeated Event IDs are normal event-type counts.
        # Check record identifiers separately.
        repeated_record_groups = {
            identifier: count
            for identifier, count in record_id_counts.items()
            if count > 1
        }

        repeated_source_groups = {
            identifier: count
            for identifier, count in source_id_counts.items()
            if count > 1
        }

        print(
            "\nRepeated internal record-ID groups: "
            f"{len(repeated_record_groups):,}"
        )
        print(
            "Repeated source/record-ID groups: "
            f"{len(repeated_source_groups):,}"
        )

        for identifier, count in repeated_record_groups.items():
            add_finding(
                findings,
                "LOW",
                "REPEATED_INTERNAL_RECORD_ID",
                0,
                "",
                "",
                "",
                record_id_column,
                identifier,
                f"This identifier occurs {count} times. Verify uniqueness "
                "requirements before treating it as a duplicate.",
            )

        for identifier, count in repeated_source_groups.items():
            add_finding(
                findings,
                "LOW",
                "REPEATED_SOURCE_RECORD_ID",
                0,
                "",
                "",
                "",
                source_id_column,
                identifier,
                f"This source identifier occurs {count} times. Check the "
                "source's uniqueness rules before deduplicating records.",
            )

        if checked != row_count:
            raise RuntimeError(
                f"Row count mismatch: expected {row_count:,}, "
                f"processed {checked:,}. Findings were not exported."
            )

        section("EXPORT FINDINGS")

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "severity",
            "check_name",
            "row_number",
            "event_id",
            "host",
            "username",
            "field_name",
            "observed_value",
            "details",
        ]

        with OUTPUT_FILE.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)

        severity_counts = {}
        check_counts = {}

        for finding in findings:
            severity = finding["severity"]
            check_name = finding["check_name"]

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            check_counts[check_name] = check_counts.get(check_name, 0) + 1

        print(f"Total findings: {len(findings):,}")

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = severity_counts.get(severity, 0)

            if count:
                print(f"  {severity}: {count:,}")

        if VERBOSE and check_counts:
            print("\nFindings by check:")

            for check_name, count in sorted(
                check_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print(f"  {check_name}: {count:,}")

        print(f"\nFindings saved to: {OUTPUT_FILE}")

        section("VALIDATION COMPLETE")
        print("Database modified: NO")
        print("Database connection: READ-ONLY")
        print("Findings are review leads, not automatic verdicts.")

        if not findings:
            print("No findings were generated by the configured checks.")

    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nVALIDATION FAILED: {error}", file=sys.stderr)
        sys.exit(1)
