
from pathlib import Path
from datetime import datetime
import json

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"

SOURCE_FILES = [
    "dns_query_logs.jsonl",
    "app_sec_audit.log",
    "firewall_traffic.log",
    "linux_syslog.log",
    "windows_security_events.log",
]

TABLES = [
    "normalized_events",
    "normalized_app_events",
    "normalized_firewall_events",
    "normalized_linux_events",
]


def print_section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def locate_source_file(filename):
    candidates = [
        PROJECT_ROOT / filename,
        PROJECT_ROOT / "logs" / filename,
        PROJECT_ROOT / "data" / filename,
    ]

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    # Search the project if the file is stored elsewhere.
    # Avoid common directories containing unrelated or generated files.
    excluded = {
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
    }

    for path in PROJECT_ROOT.rglob(filename):
        if any(part in excluded for part in path.parts):
            continue
        if path.is_file():
            return path

    return None


def read_line_at(handle, offset):
    handle.seek(offset)

    # If the offset falls inside a line, skip to the next line.
    if offset > 0:
        handle.readline()

    line = handle.readline()
    return line.decode("utf-8", errors="replace").strip()


def inspect_source_file(filename):
    path = locate_source_file(filename)

    print(f"\nFILE: {filename}")

    if path is None:
        print("  Status: NOT FOUND")
        return

    stat = path.stat()

    print(f"  Path: {path}")
    print(f"  Size: {stat.st_size:,} bytes")
    print(
        "  Last modified: "
        + datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(
            timespec="seconds"
        )
    )

    if stat.st_size == 0:
        print("  File is empty.")
        return

    # Read samples at different positions without loading the whole file.
    offsets = [
        0,
        stat.st_size // 4,
        stat.st_size // 2,
        (stat.st_size * 3) // 4,
        max(0, stat.st_size - 4096),
    ]

    samples = []
    seen = set()

    with path.open("rb") as handle:
        for offset in offsets:
            line = read_line_at(handle, offset)

            if line and line not in seen:
                seen.add(line)
                samples.append((offset, line))

    for index, (offset, line) in enumerate(samples, start=1):
        print(f"\n  Sample {index} (byte offset {offset:,}):")

        # For JSON Lines, show keys separately when parsing succeeds.
        if path.suffix.lower() == ".jsonl":
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    print(f"    JSON keys: {list(record.keys())}")
            except json.JSONDecodeError:
                print("    JSON parsing: sample is not a complete JSON object")

        display = line if len(line) <= 500 else line[:500] + "...[truncated]"
        print(f"    {display}")


def inspect_database_schema():
    print_section("DATABASE SCHEMA AND SOURCE METADATA FIELDS")

    if not DB_FILE.is_file():
        print(f"Database not found: {DB_FILE}")
        return

    with duckdb.connect(str(DB_FILE), read_only=True) as connection:
        existing_tables = {
            row[0]
            for row in connection.execute("SHOW TABLES").fetchall()
        }

        for table in TABLES:
            print(f"\nTABLE: {table}")

            if table not in existing_tables:
                print("  Status: NOT FOUND")
                continue

            columns = connection.execute(
                f'DESCRIBE "{table}"'
            ).fetchall()

            for column in columns:
                name, data_type = column[0], column[1]
                print(f"  {name}: {data_type}")


def main():
    print("=" * 78)
    print("SPLUNK THREAT HUNT ENGINE")
    print("ORIGINAL SOURCE METADATA REVIEW")
    print("=" * 78)
    print(f"Project: {PROJECT_ROOT}")
    print("Mode: READ ONLY")
    print("Original log files and database will not be modified.")

    print_section("1. ORIGINAL LOG FILE SAMPLES")

    for filename in SOURCE_FILES:
        inspect_source_file(filename)

    inspect_database_schema()

    print_section("REVIEW COMPLETED")
    print("No source files or database records were changed.")
    print(
        "Note: file modification times describe the local copies, "
        "not necessarily when the original events occurred."
    )


if __name__ == "__main__":
    main()
