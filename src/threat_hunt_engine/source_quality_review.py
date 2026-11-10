
from pathlib import Path
from ipaddress import ip_address
from collections import Counter

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"

TABLES = [
    "normalized_events",
    "normalized_app_events",
    "normalized_firewall_events",
    "normalized_linux_events",
]


def classify_ip(value):
    if value is None or not str(value).strip():
        return "missing"

    try:
        address = ip_address(str(value).strip())
    except ValueError:
        return "invalid"

    if address.version != 4:
        return "non_ipv4"

    if address.is_loopback:
        return "loopback"

    if address.is_link_local:
        return "link_local"

    if address.is_multicast:
        return "multicast"

    if address.is_unspecified:
        return "unspecified"

    if address.is_private:
        return "private"

    if not address.is_global:
        return "non_global_other"

    return "global"


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def review_ip_field(connection, table, field):
    quoted_table = '"' + table.replace('"', '""') + '"'

    available_columns = {
        row[0]
        for row in connection.execute(
            f"DESCRIBE {quoted_table}"
        ).fetchall()
    }

    if field not in available_columns:
        return

    values = connection.execute(
        f"""
        SELECT DISTINCT "{field}"
        FROM {quoted_table}
        WHERE "{field}" IS NOT NULL
        """
    ).fetchall()

    counts = Counter(classify_ip(row[0]) for row in values)

    print(f"\n{table}.{field}")
    print(f"  Distinct non-null values checked: {len(values):,}")

    for category, count in sorted(counts.items()):
        print(f"  {category}: {count:,}")

    invalid_examples = [
        str(row[0])
        for row in values
        if classify_ip(row[0]) == "invalid"
    ][:10]

    if invalid_examples:
        print(f"  Invalid examples: {invalid_examples}")


def main():
    if not DB_FILE.exists():
        raise FileNotFoundError(f"Database not found: {DB_FILE}")

    print("=" * 70)
    print("SPLUNK THREAT HUNT ENGINE")
    print("SOURCE QUALITY AND TIMELINE REVIEW")
    print("=" * 70)
    print(f"Database: {DB_FILE}")
    print("Mode: READ ONLY")

    with duckdb.connect(str(DB_FILE), read_only=True) as connection:
        existing_tables = {
            row[0] for row in connection.execute("SHOW TABLES").fetchall()
        }

        print_section("1. SOURCE TIMELINE RANGES")

        ranges = {}

        for table in TABLES:
            if table not in existing_tables:
                print(f"{table}: NOT FOUND")
                continue

            quoted_table = '"' + table.replace('"', '""') + '"'

            result = connection.execute(
                f"""
                SELECT
                    COUNT(*),
                    MIN(event_timestamp),
                    MAX(event_timestamp),
                    COUNT(event_timestamp)
                FROM {quoted_table}
                """
            ).fetchone()

            total, earliest, latest, timestamped = result
            ranges[table] = (earliest, latest)

            print(f"\n{table}")
            print(f"  Records: {total:,}")
            print(f"  Timestamped records: {timestamped:,}")
            print(f"  Earliest: {earliest}")
            print(f"  Latest: {latest}")

        print_section("2. TIMELINE OVERLAP CHECK")

        timestamped_tables = [
            (table, start, end)
            for table, (start, end) in ranges.items()
            if start is not None and end is not None
        ]

        if len(timestamped_tables) < 2:
            print("Not enough timestamped tables to compare.")
        else:
            for index, (table_a, start_a, end_a) in enumerate(
                timestamped_tables
            ):
                for table_b, start_b, end_b in timestamped_tables[index + 1:]:
                    overlap_start = max(start_a, start_b)
                    overlap_end = min(end_a, end_b)

                    if overlap_start <= overlap_end:
                        print(
                            f"{table_a} <-> {table_b}: "
                            f"overlapping range "
                            f"{overlap_start} to {overlap_end}"
                        )
                    else:
                        if end_a < start_b:
                            gap = start_b - end_a
                        else:
                            gap = start_a - end_b

                        print(
                            f"{table_a} <-> {table_b}: "
                            f"NO OVERLAP; gap between recorded ranges "
                            f"is {gap}"
                        )

        print_section("3. DISTINCT IP ADDRESS QUALITY")

        for table in TABLES:
            if table not in existing_tables:
                continue

            review_ip_field(connection, table, "src_ip")
            review_ip_field(connection, table, "dst_ip")

        print_section("4. FIREWALL PROTOCOL AND FLAG COMBINATIONS")

        if "normalized_firewall_events" in existing_tables:
            show = connection.execute(
                """
                SELECT
                    fw_protocol,
                    fw_tcp_flags,
                    COUNT(*) AS records
                FROM normalized_firewall_events
                GROUP BY fw_protocol, fw_tcp_flags
                ORDER BY records DESC
                LIMIT 25
                """
            ).fetchall()

            print("Most common combinations:")
            for protocol, flags, count in show:
                print(
                    f"  protocol={protocol!r}, "
                    f"flags={flags!r}: {count:,}"
                )

            print("\nNon-TCP records with TCP-style flags:")
            mismatches = connection.execute(
                """
                SELECT
                    fw_protocol,
                    fw_tcp_flags,
                    COUNT(*) AS records
                FROM normalized_firewall_events
                WHERE UPPER(COALESCE(fw_protocol, '')) <> 'TCP'
                  AND UPPER(COALESCE(fw_tcp_flags, ''))
                      NOT IN ('', 'NONE', 'NULL')
                GROUP BY fw_protocol, fw_tcp_flags
                ORDER BY records DESC
                LIMIT 20
                """
            ).fetchall()

            if mismatches:
                for protocol, flags, count in mismatches:
                    print(
                        f"  protocol={protocol!r}, "
                        f"flags={flags!r}: {count:,}"
                    )
            else:
                print("  No such combinations found.")

    print("\n" + "=" * 70)
    print("SOURCE QUALITY REVIEW COMPLETED")
    print("No database records or source files were changed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
