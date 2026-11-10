
from pathlib import Path
from time import perf_counter

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_FILE = PROJECT_ROOT / "logs" / "app_sec_audit.log"


def sql_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def main():
    started = perf_counter()

    print("=" * 65)
    print("APPLICATION EVENT ID DUPLICATE INVESTIGATION")
    print("=" * 65)

    if not APP_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {APP_FILE}")

    file_size_mb = APP_FILE.stat().st_size / (1024 * 1024)
    print(f"Source: {APP_FILE.name}")
    print(f"File size: {file_size_mb:.2f} MB")

    app_path = APP_FILE.resolve().as_posix().replace("'", "''")

    # Read original log lines without modifying the source file.
    with duckdb.connect(":memory:") as connection:
        print("\nLoading application logs...", flush=True)

        connection.execute(f"""
            CREATE TEMP TABLE app_raw AS
            SELECT raw_event
            FROM read_csv(
                '{app_path}',
                delim='\\x01',
                header=false,
                columns={{'raw_event': 'VARCHAR'}},
                quote='',
                escape='',
                auto_detect=false,
                strict_mode=false,
                null_padding=true
            )
        """)

        # Extract request_id while retaining each original line.
        quoted_pattern = '(^|[[:space:]])request_id="([^"]*)"'
        plain_pattern = '(^|[[:space:]])request_id=([^[:space:]]+)'

        connection.execute(f"""
            CREATE TEMP TABLE app_with_ids AS
            SELECT
                raw_event,
                COALESCE(
                    NULLIF(
                        regexp_extract(
                            raw_event,
                            {sql_string(quoted_pattern)},
                            2
                        ),
                        ''
                    ),
                    NULLIF(
                        regexp_extract(
                            raw_event,
                            {sql_string(plain_pattern)},
                            2
                        ),
                        ''
                    )
                ) AS request_id
            FROM app_raw
        """)

        total_records, missing_ids = connection.execute("""
            SELECT
                COUNT(*),
                COUNT(*) FILTER (
                    WHERE request_id IS NULL OR request_id = ''
                )
            FROM app_with_ids
        """).fetchone()

        print(f"Total records: {total_records:,}")
        print(f"Records without request IDs: {missing_ids:,}")

        # Summarize only IDs that occur more than once.
        connection.execute("""
            CREATE TEMP TABLE duplicate_groups AS
            SELECT
                request_id,
                COUNT(*) AS record_count,
                COUNT(DISTINCT raw_event) AS distinct_raw_lines
            FROM app_with_ids
            WHERE request_id IS NOT NULL
              AND request_id <> ''
            GROUP BY request_id
            HAVING COUNT(*) > 1
        """)

        summary = connection.execute("""
            SELECT
                COUNT(*) AS repeated_id_count,
                COALESCE(SUM(record_count - 1), 0)
                    AS excess_occurrences,
                COUNT(*) FILTER (
                    WHERE distinct_raw_lines = 1
                ) AS identical_line_groups,
                COUNT(*) FILTER (
                    WHERE distinct_raw_lines > 1
                ) AS differing_line_groups,
                COALESCE(MAX(record_count), 0) AS largest_group
            FROM duplicate_groups
        """).fetchone()

        (
            repeated_id_count,
            excess_occurrences,
            identical_line_groups,
            differing_line_groups,
            largest_group,
        ) = summary

        print("\nDUPLICATE SUMMARY")
        print("-" * 65)
        print(f"Distinct IDs occurring more than once: {repeated_id_count:,}")
        print(f"Excess repeated occurrences:           {excess_occurrences:,}")
        print(f"Groups with identical raw lines:       {identical_line_groups:,}")
        print(f"Groups with different raw lines:       {differing_line_groups:,}")
        print(f"Largest number of records for one ID:  {largest_group:,}")

        # Show the most repeated IDs first.
        examples = connection.execute("""
            SELECT
                request_id,
                record_count,
                distinct_raw_lines
            FROM duplicate_groups
            ORDER BY record_count DESC, request_id
            LIMIT 10
        """).fetchall()

        print("\nTOP DUPLICATE EVENT IDs")
        print("-" * 65)

        if not examples:
            print("No duplicate IDs found.")
        else:
            for request_id, count, distinct_lines in examples:
                classification = (
                    "identical raw lines"
                    if distinct_lines == 1
                    else "different raw lines"
                )
                print(
                    f"ID={request_id} | records={count} | "
                    f"distinct lines={distinct_lines} | {classification}"
                )

        # Display actual evidence for up to three duplicate IDs.
        print("\nRAW RECORD EXAMPLES")
        print("-" * 65)

        for request_id, count, distinct_lines in examples[:3]:
            print(
                f"\nEvent ID: {request_id} "
                f"(records={count}, distinct lines={distinct_lines})"
            )

            records = connection.execute("""
                SELECT raw_event
                FROM app_with_ids
                WHERE request_id = ?
                ORDER BY raw_event
                LIMIT 5
            """, [request_id]).fetchall()

            for index, (raw_event,) in enumerate(records, start=1):
                display = raw_event
                if len(display) > 350:
                    display = display[:350] + "... [truncated for display]"
                print(f"  Record {index}: {display}")

    print("\n" + "=" * 65)
    print(f"Investigation runtime: {perf_counter() - started:.2f} seconds")
    print("Original log file was not modified.")
    print("=" * 65)


if __name__ == "__main__":
    main()
