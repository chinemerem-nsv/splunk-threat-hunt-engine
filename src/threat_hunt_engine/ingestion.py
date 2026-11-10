
import argparse
from pathlib import Path
from time import perf_counter

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = PROJECT_ROOT / "logs"
DB_FILE = PROJECT_ROOT / "threat_hunt.duckdb"

DNS_FILE = LOG_DIR / "dns_query_logs.jsonl"
APP_FILE = LOG_DIR / "app_sec_audit.log"
FIREWALL_FILE = LOG_DIR / "firewall_traffic.log"
LINUX_FILE = LOG_DIR / "linux_syslog.log"
WINDOWS_FILE = LOG_DIR / "windows_security_events.log"


def elapsed(seconds):
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    return f"{int(seconds // 60)} min {seconds % 60:.2f} sec"


def sql_string(value):
    return "'" + str(value).replace("'", "''") + "'"


def print_stage(name, started):
    print(f"{name}: {elapsed(perf_counter() - started)}", flush=True)


def list_log_files():
    print("\nINPUT LOG FILES")
    print("-" * 55)

    for path in sorted(LOG_DIR.glob("*")):
        if path.is_file():
            print(
                f"{path.name:<35}"
                f"{path.stat().st_size / 1048576:>8.2f} MB"
            )


def get_duckdb_source(path):
    safe_path = path.resolve().as_posix().replace("'", "''")
    return f"read_json_auto('{safe_path}', format='newline_delimited')"


def report_id_quality(connection, table):
    """Report internal-ID uniqueness and source-ID reuse separately."""

    total, internal_duplicates, missing_internal = connection.execute(
        f"""
        SELECT
            COUNT(*),
            COUNT(*) - COUNT(DISTINCT event_id),
            COUNT(*) FILTER (
                WHERE event_id IS NULL OR event_id = ''
            )
        FROM {table}
        """
    ).fetchone()

    source_groups, source_excess = connection.execute(f"""
        SELECT
            COUNT(*) FILTER (WHERE occurrences > 1),
            COALESCE(SUM(GREATEST(occurrences - 1, 0)), 0)
        FROM (
            SELECT source_event_id, COUNT(*) AS occurrences
            FROM {table}
            WHERE source_event_id IS NOT NULL
              AND source_event_id <> ''
            GROUP BY source_event_id
        ) AS ids
    """).fetchone()

    print(f"Records:                       {total:,}")
    print(f"Duplicate internal IDs:        {internal_duplicates:,}")
    print(f"Missing internal IDs:          {missing_internal:,}")
    print(f"Repeated source-ID groups:     {source_groups:,}")
    print(f"Excess source-ID occurrences:  {source_excess:,}")


def ingest_dns(connection):
    print("\nDNS LOG INGESTION")
    print("-" * 55)
    started = perf_counter()
    source = get_duckdb_source(DNS_FILE)

    connection.execute(f"""
        CREATE OR REPLACE TABLE normalized_events AS
        WITH dns_raw AS (
            SELECT
                dns.*,
                TO_JSON(STRUCT_PACK(
                    ts := dns.timestamp,
                    client_ip := dns.client_ip,
                    query := dns.query,
                    qtype := dns.qtype,
                    rcode := dns.rcode,
                    answer := dns.answer,
                    query_length := dns.query_length,
                    subdomain_entropy := dns.subdomain_entropy,
                    labels := dns.labels,
                    tags := dns.tags,
                    resolver := dns.resolver,
                    duration_ms := dns.duration_ms,
                    log_id := dns.log_id
                )) AS raw_event
            FROM {source} AS dns
        ),
        numbered AS (
            SELECT
                ROW_NUMBER() OVER () AS source_line_number,
                *
            FROM dns_raw
        )
        SELECT
            SHA256(
                'dns_query_logs.jsonl|' ||
                CAST(source_line_number AS VARCHAR) || '|' ||
                raw_event
            ) AS event_id,
            CAST(log_id AS VARCHAR) AS source_event_id,
            source_line_number,
            'dns' AS source_type,
            'dns_query_logs.jsonl' AS source_file,
            'dns_query' AS event_category,
            CAST(timestamp AS VARCHAR) AS source_timestamp,
            TRY_CAST(timestamp AS TIMESTAMP) AS event_timestamp,
            CAST(client_ip AS VARCHAR) AS src_ip,
            CAST(NULL AS VARCHAR) AS dst_ip,
            CAST(NULL AS VARCHAR) AS host,
            CAST(NULL AS VARCHAR) AS username,
            CAST(NULL AS VARCHAR) AS event_action,
            CAST(NULL AS VARCHAR) AS severity,
            CAST(tags AS VARCHAR[]) AS source_labels,
            CAST(query AS VARCHAR) AS dns_query,
            CAST(qtype AS VARCHAR) AS dns_query_type,
            CAST(rcode AS VARCHAR) AS dns_response_code,
            CAST(answer AS VARCHAR) AS dns_answer,
            TRY_CAST(query_length AS BIGINT) AS dns_query_length,
            TRY_CAST(subdomain_entropy AS DOUBLE)
                AS dns_subdomain_entropy,
            TRY_CAST(labels AS BIGINT) AS dns_label_count,
            CAST(resolver AS VARCHAR) AS dns_resolver,
            TRY_CAST(duration_ms AS DOUBLE) AS dns_duration_ms,
            raw_event,
            CAST(NULL AS VARCHAR) AS app_service,
            CAST(NULL AS VARCHAR) AS app_method,
            CAST(NULL AS VARCHAR) AS app_uri,
            CAST(NULL AS BIGINT) AS app_status,
            CAST(NULL AS BIGINT) AS app_bytes,
            CAST(NULL AS DOUBLE) AS app_latency_ms,
            CAST(NULL AS VARCHAR) AS app_user_agent,
            CAST(NULL AS VARCHAR) AS app_auth,
            CAST(NULL AS VARCHAR) AS app_attack_type,
            CAST(NULL AS VARCHAR) AS app_detection,
            CAST(NULL AS VARCHAR) AS app_rule_id,
            CAST(NULL AS VARCHAR) AS app_request_id,
            CAST(NULL AS VARCHAR) AS source_level
        FROM numbered
    """)

    print("\nDNS ID validation:")
    report_id_quality(connection, "normalized_events")

    checks = connection.execute("""
        SELECT
            COUNT(*) FILTER (WHERE event_timestamp IS NULL),
            COUNT(DISTINCT src_ip),
            COUNT(*) FILTER (
                WHERE raw_event IS NULL
                   OR CAST(raw_event AS VARCHAR) = ''
            )
        FROM normalized_events
    """).fetchone()

    print(f"Timestamp parse failures:      {checks[0]:,}")
    print(f"Unique client IPs:              {checks[1]:,}")
    print(f"Missing raw events:             {checks[2]:,}")

    print("\nMost common source labels:")
    labels = connection.execute("""
        SELECT tag, COUNT(*) AS occurrences
        FROM normalized_events,
             UNNEST(source_labels) AS label_table(tag)
        GROUP BY tag
        ORDER BY occurrences DESC
        LIMIT 10
    """).fetchall()

    for tag, count in labels:
        print(f"  {tag}: {count:,}")

    print_stage("DNS ingestion completed in", started)


def field_expression(field_name):
    quoted_pattern = f'(^|[[:space:]]){field_name}="([^"]*)"'
    plain_pattern = f'(^|[[:space:]]){field_name}=([^[:space:]]+)'

    quoted = (
        f"NULLIF(regexp_extract(raw_event, "
        f"{sql_string(quoted_pattern)}, 2), '')"
    )
    plain = (
        f"NULLIF(regexp_extract(raw_event, "
        f"{sql_string(plain_pattern)}, 2), '')"
    )

    return f"COALESCE({quoted}, {plain})"


def ingest_application_logs(connection):
    print("\nAPPLICATION SECURITY LOG INGESTION")
    print("-" * 55)
    overall_start = perf_counter()

    stage_start = perf_counter()
    app_path = APP_FILE.resolve().as_posix().replace("'", "''")

    print("Loading raw application lines...", flush=True)

    connection.execute(f"""
        CREATE OR REPLACE TEMP TABLE raw_app_lines AS
        SELECT
            ROW_NUMBER() OVER () AS source_line_number,
            raw_event
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

    raw_count = connection.execute("""
        SELECT COUNT(*) FROM raw_app_lines
    """).fetchone()[0]

    print(f"Raw lines loaded: {raw_count:,}")
    print_stage("Raw loading completed in", stage_start)

    stage_start = perf_counter()
    print("\nNormalizing application events...", flush=True)

    field = field_expression
    timestamp = "regexp_extract(raw_event, '^([^[:space:]]+)', 1)"

    expressions = [
        (
            "SHA256('app_sec_audit.log|' || "
            "CAST(source_line_number AS VARCHAR) || '|' || raw_event) "
            "AS event_id"
        ),
        f"{field('request_id')} AS source_event_id",
        "source_line_number",
        "'application' AS source_type",
        "'app_sec_audit.log' AS source_file",
        f"COALESCE({field('event')}, 'unknown') AS event_category",
        f"{timestamp} AS source_timestamp",
        f"TRY_CAST({timestamp} AS TIMESTAMP) AS event_timestamp",
        f"{field('src_ip')} AS src_ip",
        f"{field('dst_ip')} AS dst_ip",
        f"{field('host')} AS host",
        f"{field('user')} AS username",
        f"{field('event')} AS event_action",
        f"{field('severity')} AS severity",
        "CAST(NULL AS VARCHAR[]) AS source_labels",
        "CAST(NULL AS VARCHAR) AS dns_query",
        "CAST(NULL AS VARCHAR) AS dns_query_type",
        "CAST(NULL AS VARCHAR) AS dns_response_code",
        "CAST(NULL AS VARCHAR) AS dns_answer",
        "CAST(NULL AS BIGINT) AS dns_query_length",
        "CAST(NULL AS DOUBLE) AS dns_subdomain_entropy",
        "CAST(NULL AS BIGINT) AS dns_label_count",
        "CAST(NULL AS VARCHAR) AS dns_resolver",
        "CAST(NULL AS DOUBLE) AS dns_duration_ms",
        "raw_event AS raw_event",
        f"{field('service')} AS app_service",
        f"{field('method')} AS app_method",
        f"{field('uri')} AS app_uri",
        f"TRY_CAST({field('status')} AS BIGINT) AS app_status",
        f"TRY_CAST({field('bytes')} AS BIGINT) AS app_bytes",
        f"TRY_CAST({field('latency_ms')} AS DOUBLE) AS app_latency_ms",
        f"{field('user_agent')} AS app_user_agent",
        f"{field('auth')} AS app_auth",
        f"{field('attack_type')} AS app_attack_type",
        f"{field('detection')} AS app_detection",
        f"{field('rule_id')} AS app_rule_id",
        f"{field('request_id')} AS app_request_id",
        f"{field('level')} AS source_level",
    ]

    connection.execute(f"""
        CREATE OR REPLACE TABLE normalized_app_events AS
        SELECT {', '.join(expressions)}
        FROM raw_app_lines
    """)

    print_stage("Field normalization completed in", stage_start)

    stage_start = perf_counter()

    print("\nAPPLICATION ID VALIDATION")
    print("-" * 55)
    report_id_quality(connection, "normalized_app_events")

    checks = connection.execute("""
        SELECT
            COUNT(*) FILTER (WHERE event_timestamp IS NULL),
            COUNT(DISTINCT src_ip),
            COUNT(*) FILTER (
                WHERE raw_event IS NULL OR raw_event = ''
            )
        FROM normalized_app_events
    """).fetchone()

    print(f"Timestamp parse failures:      {checks[0]:,}")
    print(f"Unique source IPs:              {checks[1]:,}")
    print(f"Missing raw events:             {checks[2]:,}")

    print("\nEvents by category:")
    categories = connection.execute("""
        SELECT event_category, COUNT(*)
        FROM normalized_app_events
        GROUP BY event_category
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """).fetchall()

    for category, count in categories:
        print(f"  {category}: {count:,}")

    print("\nSample events:")
    samples = connection.execute("""
        SELECT
            event_id,
            source_event_id,
            event_timestamp,
            src_ip,
            username,
            event_category,
            app_attack_type
        FROM normalized_app_events
        LIMIT 5
    """).fetchall()

    for row in samples:
        print(f"  {row}")

    print("\nExample repeated source IDs:")
    repeated = connection.execute("""
        SELECT source_event_id, COUNT(*) AS occurrences
        FROM normalized_app_events
        WHERE source_event_id IS NOT NULL
          AND source_event_id <> ''
        GROUP BY source_event_id
        HAVING COUNT(*) > 1
        ORDER BY occurrences DESC, source_event_id
        LIMIT 5
    """).fetchall()

    for source_id, occurrences in repeated:
        internal_ids = connection.execute("""
            SELECT event_id
            FROM normalized_app_events
            WHERE source_event_id = ?
            ORDER BY source_line_number
            LIMIT 5
        """, [source_id]).fetchall()

        print(f"  Source ID {source_id}: {occurrences} records")
        for (internal_id,) in internal_ids:
            print(f"    Internal ID: {internal_id}")

    print_stage("Validation completed in", stage_start)

    duration = perf_counter() - overall_start
    rate = raw_count / duration if duration else 0

    print(f"\nApplication records: {raw_count:,}")
    print(f"Application processing time: {elapsed(duration)}")
    print(f"Average processing rate: {rate:,.0f} records/second")


def ingest_firewall_logs(connection):
    print("\nFIREWALL LOG INGESTION")
    print("-" * 55)
    overall_start = perf_counter()

    stage_start = perf_counter()
    firewall_path = FIREWALL_FILE.resolve().as_posix().replace("'", "''")

    print("Loading raw firewall lines...", flush=True)

    connection.execute(f"""
        CREATE OR REPLACE TEMP TABLE raw_firewall_lines AS
        SELECT
            ROW_NUMBER() OVER () AS source_line_number,
            raw_event
        FROM read_csv(
            '{firewall_path}',
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

    raw_count = connection.execute("""
        SELECT COUNT(*) FROM raw_firewall_lines
    """).fetchone()[0]

    print(f"Raw lines loaded: {raw_count:,}")
    print_stage("Firewall raw loading completed in", stage_start)

    stage_start = perf_counter()
    print("Normalizing firewall fields...", flush=True)

    field = field_expression

    timestamp = (
        "regexp_extract(raw_event, "
        "'^([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.+-]+Z?)', 1)"
    )

    source_id = (
        f"COALESCE({field('event_id')}, "
        f"{field('log_id')}, {field('request_id')})"
    )

    expressions = [
        (
            "SHA256('firewall_traffic.log|' || "
            "CAST(source_line_number AS VARCHAR) || '|' || raw_event) "
            "AS event_id"
        ),
        f"{source_id} AS source_event_id",
        "source_line_number",
        "'firewall' AS source_type",
        "'firewall_traffic.log' AS source_file",
        f"COALESCE({field('event')}, 'firewall_traffic') AS event_category",
        f"{timestamp} AS source_timestamp",
        f"TRY_CAST({timestamp} AS TIMESTAMP) AS event_timestamp",
        f"{field('src_ip')} AS src_ip",
        f"{field('dst_ip')} AS dst_ip",
        f"{field('host')} AS host",
        f"{field('user')} AS username",
        f"{field('action')} AS event_action",
        f"{field('severity')} AS severity",
        "CAST(NULL AS VARCHAR[]) AS source_labels",
        "CAST(NULL AS VARCHAR) AS dns_query",
        "CAST(NULL AS VARCHAR) AS dns_query_type",
        "CAST(NULL AS VARCHAR) AS dns_response_code",
        "CAST(NULL AS VARCHAR) AS dns_answer",
        "CAST(NULL AS BIGINT) AS dns_query_length",
        "CAST(NULL AS DOUBLE) AS dns_subdomain_entropy",
        "CAST(NULL AS BIGINT) AS dns_label_count",
        "CAST(NULL AS VARCHAR) AS dns_resolver",
        "CAST(NULL AS DOUBLE) AS dns_duration_ms",
        "raw_event AS raw_event",
        "CAST(NULL AS VARCHAR) AS app_service",
        "CAST(NULL AS VARCHAR) AS app_method",
        "CAST(NULL AS VARCHAR) AS app_uri",
        "CAST(NULL AS BIGINT) AS app_status",
        "CAST(NULL AS BIGINT) AS app_bytes",
        "CAST(NULL AS DOUBLE) AS app_latency_ms",
        "CAST(NULL AS VARCHAR) AS app_user_agent",
        "CAST(NULL AS VARCHAR) AS app_auth",
        "CAST(NULL AS VARCHAR) AS app_attack_type",
        "CAST(NULL AS VARCHAR) AS app_detection",
        "CAST(NULL AS VARCHAR) AS app_rule_id",
        "CAST(NULL AS VARCHAR) AS app_request_id",
        f"{field('level')} AS source_level",
        f"{field('action')} AS fw_action",
        f"{field('protocol')} AS fw_protocol",
        f"TRY_CAST({field('src_port')} AS BIGINT) AS fw_src_port",
        f"TRY_CAST({field('dst_port')} AS BIGINT) AS fw_dst_port",
        f"{field('rule')} AS fw_rule",
        f"{field('tcp_flags')} AS fw_tcp_flags",
        f"TRY_CAST({field('bytes')} AS BIGINT) AS fw_bytes",
        f"TRY_CAST({field('packets')} AS BIGINT) AS fw_packets",
        f"{field('direction')} AS fw_direction",
        f"{field('interface')} AS fw_interface",
    ]

    connection.execute(f"""
        CREATE OR REPLACE TABLE normalized_firewall_events AS
        SELECT {', '.join(expressions)}
        FROM raw_firewall_lines
    """)

    print_stage("Firewall normalization completed in", stage_start)

    stage_start = perf_counter()
    print("\nFIREWALL ID VALIDATION")
    print("-" * 55)

    report_id_quality(connection, "normalized_firewall_events")

    checks = connection.execute("""
        SELECT
            COUNT(*) FILTER (WHERE event_timestamp IS NULL),
            COUNT(*) FILTER (WHERE src_ip IS NULL),
            COUNT(*) FILTER (WHERE dst_ip IS NULL),
            COUNT(*) FILTER (WHERE fw_action IS NULL),
            COUNT(*) FILTER (WHERE fw_protocol IS NULL),
            COUNT(*) FILTER (WHERE fw_rule IS NULL),
            COUNT(*) FILTER (WHERE raw_event IS NULL OR raw_event = '')
        FROM normalized_firewall_events
    """).fetchone()

    print(f"Timestamp parse failures:      {checks[0]:,}")
    print(f"Missing source IP:              {checks[1]:,}")
    print(f"Missing destination IP:         {checks[2]:,}")
    print(f"Missing action:                 {checks[3]:,}")
    print(f"Missing protocol:               {checks[4]:,}")
    print(f"Missing rule:                   {checks[5]:,}")
    print(f"Missing raw events:             {checks[6]:,}")

    print("\nAction and protocol summaries:")
    summaries = connection.execute("""
        SELECT fw_action, fw_protocol, COUNT(*) AS occurrences
        FROM normalized_firewall_events
        GROUP BY fw_action, fw_protocol
        ORDER BY occurrences DESC
        LIMIT 10
    """).fetchall()

    for action, protocol, count in summaries:
        print(f"  action={action!r}, protocol={protocol!r}: {count:,}")

    print("\nPotential field conflicts (source values preserved):")

    conflict_condition = """
        (
            UPPER(COALESCE(fw_action, '')) = 'ALLOW'
            AND UPPER(COALESCE(fw_rule, '')) LIKE '%DENY%'
        )
        OR
        (
            UPPER(COALESCE(fw_protocol, '')) = 'ICMP'
            AND UPPER(COALESCE(fw_tcp_flags, '')) LIKE '%SYN%'
        )
    """

    conflict_count = connection.execute(f"""
        SELECT COUNT(*)
        FROM normalized_firewall_events
        WHERE {conflict_condition}
    """).fetchone()[0]

    print(f"Records matching conflict checks: {conflict_count:,}")

    samples = connection.execute(f"""
        SELECT
            source_line_number,
            fw_action,
            fw_protocol,
            fw_rule,
            fw_tcp_flags,
            raw_event
        FROM normalized_firewall_events
        WHERE {conflict_condition}
        ORDER BY source_line_number
        LIMIT 5
    """).fetchall()

    for line_number, action, protocol, rule, flags, raw in samples:
        print(
            f"  Line {line_number}: action={action!r}, "
            f"protocol={protocol!r}, rule={rule!r}, "
            f"tcp_flags={flags!r}"
        )
        print(f"    Raw evidence: {raw}")

    print("\nSample normalized firewall events:")
    samples = connection.execute("""
        SELECT
            event_id,
            source_event_id,
            event_timestamp,
            src_ip,
            dst_ip,
            fw_action,
            fw_protocol,
            fw_rule
        FROM normalized_firewall_events
        LIMIT 5
    """).fetchall()

    for row in samples:
        print(f"  {row}")

    print_stage("Firewall validation completed in", stage_start)

    duration = perf_counter() - overall_start
    rate = raw_count / duration if duration else 0

    print(f"\nFirewall records: {raw_count:,}")
    print(f"Firewall processing time: {elapsed(duration)}")
    print(f"Average processing rate: {rate:,.0f} records/second")


def ingest_linux_syslog(connection):
    print("\nLINUX SYSLOG INGESTION")
    print("-" * 55)
    overall_start = perf_counter()

    stage_start = perf_counter()
    linux_path = LINUX_FILE.resolve().as_posix().replace("'", "''")

    print("Loading raw Linux syslog lines...", flush=True)

    connection.execute(f"""
        CREATE OR REPLACE TEMP TABLE raw_linux_lines AS
        SELECT
            ROW_NUMBER() OVER () AS source_line_number,
            raw_event
        FROM read_csv(
            '{linux_path}',
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

    raw_count = connection.execute("""
        SELECT COUNT(*) FROM raw_linux_lines
    """).fetchone()[0]

    print(f"Raw lines loaded: {raw_count:,}")
    print_stage("Linux raw loading completed in", stage_start)

    stage_start = perf_counter()
    print("Normalizing Linux syslog fields...", flush=True)

    connection.execute("""
        CREATE OR REPLACE TABLE normalized_linux_events AS
        WITH header_parsed AS (
            SELECT
                source_line_number,
                raw_event,

                regexp_extract(
                    raw_event,
                    '^([A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2})\\s+',
                    1
                ) AS source_timestamp,

                regexp_extract(
                    raw_event,
                    '^[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+([^ ]+)\\s+',
                    1
                ) AS linux_hostname,

                regexp_extract(
                    raw_event,
                    '^[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+[^ ]+\\s+([^ ]+)',
                    1
                ) AS linux_process_token

            FROM raw_linux_lines
        ),
        token_parsed AS (
            SELECT
                *,
                NULLIF(
                    regexp_extract(
                        linux_process_token,
                        '\\[([0-9]+)\\]',
                        1
                    ),
                    ''
                ) AS linux_pid,

                regexp_replace(
                    linux_process_token,
                    '\\[[0-9]+\\]:?$|:$',
                    ''
                ) AS linux_process
            FROM header_parsed
        ),
        message_parsed AS (
            SELECT
                *,
                CASE
                    WHEN linux_process_token IS NOT NULL
                     AND linux_process_token <> ''
                    THEN regexp_replace(
                        raw_event,
                        '^[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+[^ ]+\\s+[^ ]+\\s*',
                        ''
                    )
                    ELSE raw_event
                END AS linux_message
            FROM token_parsed
        ),
        classified AS (
            SELECT
                *,
                CASE
                    WHEN regexp_matches(
                        LOWER(COALESCE(linux_message, raw_event)),
                        'authentication failure|failed password|failed publickey|authentication failed|invalid user'
                    )
                    THEN 'failure'

                    WHEN regexp_matches(
                        LOWER(COALESCE(linux_message, raw_event)),
                        'accepted password|accepted publickey|authentication success'
                    )
                    THEN 'success'

                    ELSE NULL
                END AS linux_auth_result
            FROM message_parsed
        ),
        network_parsed AS (
            SELECT
                *,
                CASE
                    WHEN regexp_matches(
                        LOWER(COALESCE(linux_message, raw_event)),
                        '(failed password|accepted (password|publickey)).* from [0-9]{1,3}(\\.[0-9]{1,3}){3}'
                    )
                    THEN NULLIF(regexp_extract(
                        LOWER(COALESCE(linux_message, raw_event)),
                        '(?:failed password|accepted (?:password|publickey)).* from ([0-9]{1,3}(\\.[0-9]{1,3}){3})',
                        1
                    ), '')

                    WHEN regexp_matches(
                        LOWER(COALESCE(linux_message, raw_event)),
                        'rhost=[0-9]{1,3}(\\.[0-9]{1,3}){3}'
                    )
                    THEN NULLIF(regexp_extract(
                        LOWER(COALESCE(linux_message, raw_event)),
                        'rhost=([0-9]{1,3}(\\.[0-9]{1,3}){3})',
                        1
                    ), '')

                    WHEN regexp_matches(
                        LOWER(COALESCE(linux_message, raw_event)),
                        '(connection closed by|received disconnect from) [0-9]{1,3}(\\.[0-9]{1,3}){3}'
                    )
                    THEN NULLIF(regexp_extract(
                        LOWER(COALESCE(linux_message, raw_event)),
                        '(?:connection closed by|received disconnect from) ([0-9]{1,3}(\\.[0-9]{1,3}){3})',
                        1
                    ), '')

                    WHEN regexp_matches(
                        COALESCE(linux_message, raw_event),
                        '(?:^|\\s)SRC=[0-9]{1,3}(\\.[0-9]{1,3}){3}(?:\\s|$)'
                    )
                    THEN NULLIF(regexp_extract(
                        COALESCE(linux_message, raw_event),
                        '(?:^|\\s)SRC=([0-9]{1,3}(\\.[0-9]{1,3}){3})(?:\\s|$)',
                        1
                    ), '')

                    ELSE NULL
                END AS src_ip,

                CASE
                    WHEN regexp_matches(
                        COALESCE(linux_message, raw_event),
                        '(?:^|\\s)DST=[0-9]{1,3}(\\.[0-9]{1,3}){3}(?:\\s|$)'
                    )
                    THEN NULLIF(regexp_extract(
                        COALESCE(linux_message, raw_event),
                        '(?:^|\\s)DST=([0-9]{1,3}(\\.[0-9]{1,3}){3})(?:\\s|$)',
                        1
                    ), '')
                    ELSE NULL
                END AS dst_ip
            FROM classified
        )
        SELECT
            SHA256(
                'linux_syslog.log|'
                || CAST(source_line_number AS VARCHAR)
                || '|'
                || COALESCE(raw_event, '')
            ) AS event_id,

            CAST(NULL AS VARCHAR) AS source_event_id,
            source_line_number,
            'linux_syslog' AS source_type,
            'linux_syslog.log' AS source_file,

            CASE
                WHEN linux_auth_result IS NOT NULL
                    THEN 'AUTHENTICATION'
                ELSE 'LINUX_SYSLOG'
            END AS event_category,

            source_timestamp,

            -- The source timestamp has no year.
            -- Do not invent one or assign a normalized timestamp.
            CAST(NULL AS TIMESTAMP) AS event_timestamp,

            src_ip,
            dst_ip,
            linux_hostname AS host,

            regexp_extract(
                COALESCE(linux_message, raw_event),
                '(?:^|[ ;])user=([^ ;]+)',
                1
            ) AS username,

            linux_auth_result AS event_action,
            CAST(NULL AS VARCHAR) AS severity,
            CAST(NULL AS VARCHAR[]) AS source_labels,
            raw_event,

            linux_hostname,
            linux_process,
            linux_pid,
            linux_message,
            linux_auth_result,

            CASE
                WHEN LOWER(COALESCE(linux_process, '')) LIKE '%sshd%'
                    THEN 'authentication'
                WHEN LOWER(COALESCE(linux_process, '')) LIKE '%sudo%'
                    THEN 'privilege'
                WHEN LOWER(COALESCE(linux_process, '')) LIKE '%polkit%'
                    THEN 'authorization'
                ELSE NULL
            END AS linux_facility

        FROM network_parsed
    """)

    print_stage("Linux normalization completed in", stage_start)

    stage_start = perf_counter()
    print("\nLINUX ID VALIDATION")
    print("-" * 55)

    report_id_quality(connection, "normalized_linux_events")

    checks = connection.execute("""
        SELECT
            COUNT(*) FILTER (WHERE source_timestamp IS NULL),
            COUNT(*) FILTER (WHERE event_timestamp IS NULL),
            COUNT(*) FILTER (
                WHERE raw_event IS NULL OR raw_event = ''
            ),
            COUNT(DISTINCT host),
            COUNT(DISTINCT linux_process),
            COUNT(*) FILTER (
                WHERE linux_process IS NULL OR linux_process = ''
            )
        FROM normalized_linux_events
    """).fetchone()

    print(f"Missing source timestamps:      {checks[0]:,}")
    print(f"Unnormalized timestamps:        {checks[1]:,}")
    print(f"Missing raw events:             {checks[2]:,}")
    print(f"Distinct hosts:                  {checks[3]:,}")
    print(f"Distinct processes:              {checks[4]:,}")
    print(f"Missing process names:           {checks[5]:,}")

    print("\nLinux process summary:")
    processes = connection.execute("""
        SELECT linux_process, COUNT(*) AS records
        FROM normalized_linux_events
        GROUP BY linux_process
        ORDER BY records DESC
        LIMIT 15
    """).fetchall()

    for process, count in processes:
        print(f"  {process}: {count:,}")

    print("\nAuthentication-pattern summary:")
    auth_summary = connection.execute("""
        SELECT
            COALESCE(linux_auth_result, 'unclassified') AS result,
            COUNT(*) AS records
        FROM normalized_linux_events
        GROUP BY result
        ORDER BY records DESC
    """).fetchall()

    for result, count in auth_summary:
        print(f"  {result}: {count:,}")

    auth_failure_count = connection.execute("""
        SELECT COUNT(*)
        FROM normalized_linux_events
        WHERE linux_auth_result = 'failure'
    """).fetchone()[0]

    auth_success_count = connection.execute("""
        SELECT COUNT(*)
        FROM normalized_linux_events
        WHERE linux_auth_result = 'success'
    """).fetchone()[0]

    print(
        "\nMessages matching authentication-failure patterns: "
        f"{auth_failure_count:,}"
    )
    print(
        "Messages matching authentication-success patterns: "
        f"{auth_success_count:,}"
    )

    print("\nSample Linux events:")
    samples = connection.execute("""
        SELECT
            source_line_number,
            source_timestamp,
            linux_hostname,
            linux_process,
            linux_pid,
            username,
            linux_auth_result,
            raw_event
        FROM normalized_linux_events
        ORDER BY source_line_number
        LIMIT 5
    """).fetchall()

    for row in samples:
        print(f"  {row}")

    print(
        "\nAuthentication labels are pattern matches, not proof "
        "of a successful or failed login by themselves."
    )
    print("Source timestamps are preserved without adding a year.")

    print_stage("Linux validation completed in", stage_start)

    duration = perf_counter() - overall_start
    rate = raw_count / duration if duration else 0

    print(f"\nLinux records: {raw_count:,}")
    print(f"Linux processing time: {elapsed(duration)}")
    print(f"Average processing rate: {rate:,.0f} records/second")



def ingest_windows_security_logs(connection):
    print("\nWINDOWS SECURITY LOG INGESTION")
    print("-" * 55)
    overall_start = perf_counter()

    windows_path = WINDOWS_FILE.resolve().as_posix().replace("'", "''")

    print("Loading raw Windows security lines...", flush=True)
    stage_start = perf_counter()

    connection.execute(f"""
        CREATE OR REPLACE TEMP TABLE raw_windows_lines AS
        SELECT
            ROW_NUMBER() OVER () AS source_line_number,
            raw_event
        FROM read_csv(
            '{windows_path}',
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

    raw_count = connection.execute(
        "SELECT COUNT(*) FROM raw_windows_lines"
    ).fetchone()[0]

    print(f"Raw lines loaded: {raw_count:,}")
    print_stage("Windows raw loading completed in", stage_start)

    print("\nNormalizing Windows security fields...", flush=True)
    stage_start = perf_counter()

    field = field_expression

    # The source uses key=value-style fields. These aliases cover common
    # Windows Event Log naming variations without altering the raw line.
    def first_field(*names):
        candidates = [field(name) for name in names]
        return "COALESCE(" + ", ".join(candidates) + ")"

    timestamp_field = first_field(
        "timestamp", "time_created", "TimeCreated", "event_timestamp"
    )
    iso_timestamp = (
        "regexp_extract(raw_event, "
        "'([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}"
        "(?:\\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)', 1)"
    )
    timestamp_expression = (
        f"COALESCE(NULLIF({iso_timestamp}, ''), "
        f"NULLIF({timestamp_field}, ''))"
    )

    event_id_field = first_field("event_id", "EventID", "EventId", "eventid")
    source_id_field = first_field(
        "record_id", "event_record_id", "log_id", "request_id"
    )
    host_field = first_field("host", "hostname", "computer", "Computer")
    username_field = first_field("username", "user", "account_name", "subject_user")
    action_field = first_field("event_action", "event", "action", "event_name")
    event_type_field = first_field("event_type", "EventType", "category", "event_category")
    severity_field = first_field("severity", "level", "log_level")
    src_ip_field = first_field("source_ip", "src_ip", "ip_address", "IpAddress")
    dst_ip_field = first_field("destination_ip", "dst_ip", "dest_ip")
    src_port_field = first_field("source_port", "src_port")
    dst_port_field = first_field("destination_port", "dst_port", "dest_port")
    process_field = first_field("process", "process_name", "image")
    command_line_field = first_field("command_line", "process_command_line", "CommandLine")
    label_field = first_field("label", "event_label", "classification", "tag")
    channel_field = first_field("channel", "log_name", "provider")

    connection.execute(f"""
        CREATE OR REPLACE TABLE normalized_windows_events AS
        WITH parsed AS (
            SELECT
                source_line_number,
                raw_event,
                {timestamp_expression} AS parsed_source_timestamp,
                {event_id_field} AS parsed_event_id,
                {source_id_field} AS parsed_source_id,
                {host_field} AS parsed_host,
                {username_field} AS parsed_username,
                {action_field} AS parsed_action,
                {event_type_field} AS parsed_event_type,
                {severity_field} AS parsed_severity,
                {src_ip_field} AS parsed_src_ip,
                {dst_ip_field} AS parsed_dst_ip,
                {src_port_field} AS parsed_src_port,
                {dst_port_field} AS parsed_dst_port,
                {process_field} AS parsed_process,
                {command_line_field} AS parsed_command_line,
                {label_field} AS parsed_label,
                {channel_field} AS parsed_channel
            FROM raw_windows_lines
        )
        SELECT
            SHA256(
                'windows_security_events.log|'
                || CAST(source_line_number AS VARCHAR)
                || '|'
                || COALESCE(raw_event, '')
            ) AS event_id,
            NULLIF(parsed_source_id, '') AS source_event_id,
            source_line_number,
            'windows_security' AS source_type,
            'windows_security_events.log' AS source_file,
            COALESCE(
                NULLIF(parsed_event_type, ''),
                NULLIF(parsed_action, ''),
                CASE
                    WHEN TRY_CAST(parsed_event_id AS BIGINT) = 4624
                        THEN 'LOGON_EVENT'
                    WHEN TRY_CAST(parsed_event_id AS BIGINT) = 5157
                        THEN 'NETWORK_BLOCKED_EVENT'
                    WHEN TRY_CAST(parsed_event_id AS BIGINT) = 4104
                        THEN 'POWERSHELL_SCRIPT_EVENT'
                    ELSE 'WINDOWS_SECURITY_EVENT'
                END
            ) AS event_category,
            parsed_source_timestamp AS source_timestamp,
            TRY_CAST(parsed_source_timestamp AS TIMESTAMP) AS event_timestamp,
            NULLIF(parsed_src_ip, '') AS src_ip,
            NULLIF(parsed_dst_ip, '') AS dst_ip,
            NULLIF(parsed_host, '') AS host,
            NULLIF(parsed_username, '') AS username,
            COALESCE(
                NULLIF(parsed_action, ''),
                NULLIF(parsed_event_type, '')
            ) AS event_action,
            NULLIF(parsed_severity, '') AS severity,
            CAST(NULL AS VARCHAR[]) AS source_labels,
            raw_event,
            TRY_CAST(parsed_event_id AS BIGINT) AS win_event_id,
            NULLIF(parsed_process, '') AS win_process,
            NULLIF(parsed_command_line, '') AS win_command_line,
            NULLIF(parsed_label, '') AS win_recorded_label,
            NULLIF(parsed_channel, '') AS win_channel,
            TRY_CAST(parsed_src_port AS BIGINT) AS win_source_port,
            TRY_CAST(parsed_dst_port AS BIGINT) AS win_destination_port,
            NULLIF(parsed_event_type, '') AS win_event_type
        FROM parsed
    """)

    print_stage("Windows normalization completed in", stage_start)

    stage_start = perf_counter()
    print("\nWINDOWS SECURITY ID VALIDATION")
    print("-" * 55)
    report_id_quality(connection, "normalized_windows_events")

    checks = connection.execute("""
        SELECT
            COUNT(*) FILTER (WHERE source_timestamp IS NULL OR source_timestamp = ''),
            COUNT(*) FILTER (WHERE event_timestamp IS NULL),
            COUNT(*) FILTER (WHERE host IS NULL OR host = ''),
            COUNT(*) FILTER (WHERE win_event_id IS NULL),
            COUNT(*) FILTER (WHERE event_action IS NULL OR event_action = ''),
            COUNT(*) FILTER (WHERE username IS NULL OR username = ''),
            COUNT(*) FILTER (WHERE raw_event IS NULL OR raw_event = '')
        FROM normalized_windows_events
    """).fetchone()

    labels = (
        "Missing source timestamps",
        "Timestamp parse failures",
        "Missing host values",
        "Missing/unparsed Windows event IDs",
        "Missing event action/name",
        "Missing usernames",
        "Missing raw events",
    )
    for label, value in zip(labels, checks):
        print(f"{label + ':':<36} {value:,}")

    print("\nWindows Event ID distribution:")
    event_ids = connection.execute("""
        SELECT win_event_id, COUNT(*) AS records
        FROM normalized_windows_events
        GROUP BY win_event_id
        ORDER BY records DESC
        LIMIT 15
    """).fetchall()
    for event_id, count in event_ids:
        print(f"  Event ID {event_id}: {count:,}")

    print("\nWindows host distribution:")
    hosts = connection.execute("""
        SELECT host, COUNT(*) AS records
        FROM normalized_windows_events
        GROUP BY host
        ORDER BY records DESC
        LIMIT 15
    """).fetchall()
    for host, count in hosts:
        print(f"  {host}: {count:,}")

    print("\nRepresentative Windows events:")
    samples = connection.execute("""
        SELECT
            source_line_number,
            source_timestamp,
            host,
            win_event_id,
            event_action,
            username,
            src_ip,
            win_recorded_label,
            win_command_line,
            raw_event
        FROM normalized_windows_events
        ORDER BY source_line_number
        LIMIT 5
    """).fetchall()
    for row in samples:
        print(f"  {row}")

    print(
        "\nInterpretation: Windows event IDs and recorded labels are "
        "source evidence. They do not independently prove malicious activity."
    )
    print_stage("Windows validation completed in", stage_start)

    duration = perf_counter() - overall_start
    rate = raw_count / duration if duration else 0
    print(f"\nWindows records: {raw_count:,}")
    print(f"Windows processing time: {elapsed(duration)}")
    print(f"Average processing rate: {rate:,.0f} records/second")


def main():
    parser = argparse.ArgumentParser(
        description="Ingest and normalize the project's security log sources."
    )
    parser.add_argument(
        "--linux-only",
        action="store_true",
        help="Rebuild only normalized_linux_events from linux_syslog.log.",
    )
    args = parser.parse_args()

    overall_start = perf_counter()

    print("=" * 65)
    print("SPLUNK THREAT HUNT ENGINE")
    print("Ingestion, Normalization and ID Validation")
    print("=" * 65)

    if not LOG_DIR.exists():
        raise FileNotFoundError(f"Log directory not found: {LOG_DIR}")

    if args.linux_only:
        if not LINUX_FILE.is_file():
            raise FileNotFoundError(f"Linux log file not found: {LINUX_FILE}")

        print(f"\nPersistent database: {DB_FILE}")
        print("\nStarting Linux-only ingestion...", flush=True)
        print("Only normalized_linux_events will be replaced.", flush=True)

        with duckdb.connect(str(DB_FILE)) as connection:
            connection.execute("SET preserve_insertion_order = true")
            ingest_linux_syslog(connection)
            count = connection.execute(
                "SELECT COUNT(*) FROM normalized_linux_events"
            ).fetchone()[0]
            print(f"\nnormalized_linux_events: {count:,} records")

        print("\nLINUX-ONLY INGESTION COMPLETED")
        print(f"Database file: {DB_FILE}")
        print(f"Total runtime: {elapsed(perf_counter() - overall_start)}")
        print("Other normalized source tables were not rebuilt.")
        return

    required_files = (
        DNS_FILE,
        APP_FILE,
        FIREWALL_FILE,
        LINUX_FILE,
        WINDOWS_FILE,
    )

    for path in required_files:
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {path}")

    list_log_files()

    print(f"\nPersistent database: {DB_FILE}")
    print("\nStarting ingestion...", flush=True)

    # A file-backed connection preserves tables after the process exits.
    # CREATE OR REPLACE TABLE refreshes the normalized tables on each run.
    with duckdb.connect(str(DB_FILE)) as connection:
        connection.execute("SET preserve_insertion_order = true")

        ingest_dns(connection)
        ingest_application_logs(connection)
        ingest_firewall_logs(connection)
        ingest_linux_syslog(connection)
        ingest_windows_security_logs(connection)

        print("\nFINAL TABLE COUNTS")
        print("-" * 55)

        total_records = 0

        for table in (
            "normalized_events",
            "normalized_app_events",
            "normalized_firewall_events",
            "normalized_linux_events",
            "normalized_windows_events",
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]

            total_records += count
            print(f"{table}: {count:,} records")

        print(f"Total ingested records: {total_records:,}")

    print("\n" + "=" * 65)
    print("INGESTION RUN COMPLETED")
    print(f"Database file: {DB_FILE}")
    print(f"Database size: {DB_FILE.stat().st_size / 1048576:.2f} MB")
    print(f"Total runtime: {elapsed(perf_counter() - overall_start)}")
    print("=" * 65)
    print("Normalized tables are saved to disk and should remain available")
    print("after this script exits.")


if __name__ == "__main__":
    main()
