
from pathlib import Path

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"


def main():
    if not DB_FILE.exists():
        raise FileNotFoundError(f"Database not found: {DB_FILE}")

    print("=" * 65)
    print("SPLUNK THREAT HUNT ENGINE")
    print("PERSISTED DATABASE VALIDATION")
    print("=" * 65)
    print(f"Database: {DB_FILE}")
    print("Mode: READ ONLY")

    with duckdb.connect(str(DB_FILE), read_only=True) as connection:
        tables = [
            row[0]
            for row in connection.execute("SHOW TABLES").fetchall()
        ]

        expected_tables = {
            "normalized_events",
            "normalized_app_events",
            "normalized_firewall_events",
            "normalized_linux_events",
        }

        print("\nTABLE INVENTORY")
        print("-" * 65)

        for table in tables:
            # Table names come from DuckDB's own table inventory.
            quoted_table = '"' + table.replace('"', '""') + '"'

            count = connection.execute(
                f"SELECT COUNT(*) FROM {quoted_table}"
            ).fetchone()[0]

            print(f"{table}: {count:,} records")

            print("\nColumns:")
            schema = connection.execute(
                f"DESCRIBE {quoted_table}"
            ).fetchall()

            for column in schema:
                print(f"  {column[0]}: {column[1]}")

            print()

        missing_tables = expected_tables - set(tables)
        unexpected_tables = set(tables) - expected_tables

        print("TABLE INVENTORY CHECK")
        print("-" * 65)
        print(f"Missing expected tables: {sorted(missing_tables)}")
        print(f"Unexpected tables: {sorted(unexpected_tables)}")

        print("\nINTERNAL ID QUALITY")
        print("-" * 65)

        for table in sorted(expected_tables.intersection(tables)):
            quoted_table = '"' + table.replace('"', '""') + '"'

            result = connection.execute(
                f"""
                SELECT
                    COUNT(*) AS total_records,
                    COUNT(*) FILTER (
                        WHERE event_id IS NULL OR TRIM(event_id) = ''
                    ) AS missing_internal_ids,
                    COUNT(DISTINCT event_id) AS distinct_internal_ids,
                    COUNT(*) FILTER (
                        WHERE raw_event IS NULL
                    ) AS missing_raw_events
                FROM {quoted_table}
                """
            ).fetchone()

            total, missing_ids, distinct_ids, missing_raw = result

            duplicate_excess = total - missing_ids - distinct_ids

            print(f"\n{table}")
            print(f"  Total records: {total:,}")
            print(f"  Missing internal IDs: {missing_ids:,}")
            print(f"  Distinct internal IDs: {distinct_ids:,}")
            print(f"  Duplicate ID excess: {duplicate_excess:,}")
            print(f"  Missing raw events: {missing_raw:,}")

        print("\nAPPLICATION SOURCE ID REVIEW")
        print("-" * 65)

        if "normalized_app_events" in tables:
            result = connection.execute(
                """
                SELECT
                    COUNT(*) AS records,
                    COUNT(*) FILTER (
                        WHERE source_event_id IS NULL
                           OR TRIM(source_event_id) = ''
                    ) AS missing_source_ids,
                    COUNT(DISTINCT source_event_id) AS distinct_source_ids
                FROM normalized_app_events
                """
            ).fetchone()

            records, missing_source_ids, distinct_source_ids = result

            print(f"Application records: {records:,}")
            print(f"Missing source IDs: {missing_source_ids:,}")
            print(f"Distinct non-null source IDs: {distinct_source_ids:,}")

            print("\nMost repeated source IDs:")
            repeated = connection.execute(
                """
                SELECT source_event_id, COUNT(*) AS occurrences
                FROM normalized_app_events
                WHERE source_event_id IS NOT NULL
                  AND TRIM(source_event_id) <> ''
                GROUP BY source_event_id
                HAVING COUNT(*) > 1
                ORDER BY occurrences DESC, source_event_id
                LIMIT 10
                """
            ).fetchall()

            if repeated:
                for source_id, occurrences in repeated:
                    print(f"  {source_id}: {occurrences:,} records")
            else:
                print("  No repeated non-empty source IDs found.")

        print("\nFIREWALL ACTION/RULE REVIEW")
        print("-" * 65)

        if "normalized_firewall_events" in tables:
            columns = {
                row[0]
                for row in connection.execute(
                    "DESCRIBE normalized_firewall_events"
                ).fetchall()
            }

            required = {"fw_action", "fw_rule"}

            if required.issubset(columns):
                result = connection.execute(
                    """
                    SELECT fw_action, fw_rule, COUNT(*) AS records
                    FROM normalized_firewall_events
                    WHERE UPPER(COALESCE(fw_rule, ''))
                          LIKE '%DENY%'
                    GROUP BY fw_action, fw_rule
                    ORDER BY records DESC
                    LIMIT 20
                    """
                ).fetchall()

                if result:
                    for action, rule, count in result:
                        print(
                            f"  action={action!r}, "
                            f"rule={rule!r}: {count:,} records"
                        )
                else:
                    print("No rules containing DENY were found.")
            else:
                print(
                    "Skipped: expected firewall columns were not found. "
                    f"Available columns: {sorted(columns)}"
                )

    print("\n" + "=" * 65)
    print("READ-ONLY VALIDATION COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
