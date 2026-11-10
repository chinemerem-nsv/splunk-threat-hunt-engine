# SOC Threat Hunting and Investigation Engine

A Python and DuckDB project for ingesting, normalizing, validating, and investigating security events from DNS, application-security, firewall, Linux syslog, and Windows Security logs.

The engine converts source logs into queryable tables, applies explainable source-specific investigation checks, and generates a unified investigation register for analyst review.

> **Important:** A finding is a review lead, not proof of compromise or successful exploitation. The current implementation performs source-by-source checks; cross-source correlation is not implemented.

## What It Does

- Ingests five types of security log data.
- Normalizes common event fields while retaining source-specific fields and raw event context where available.
- Stores normalized records in a persistent DuckDB database.
- Provides database, identifier, metadata, source-quality, and Windows event validation scripts.
- Runs rule-based investigation checks across the supported sources.
- Produces a CSV investigation register and a summary report.
- Preserves analyst updates when the register is regenerated.

## Architecture

```text
DNS / AppSec / Firewall / Linux / Windows logs
                    |
                    v
             Python ingestion
                    |
                    v
          Normalization and parsing
                    |
                    v
             DuckDB database
                    |
          +---------+----------+
          |                    |
          v                    v
   Validation scripts   Investigation checks
          |                    |
          v                    v
  Windows findings CSV  Source-specific findings
          |                    |
          +---------+----------+
                    |
                    v
       Unified investigation register
                    |
                CSV + summary
```

## Current Implementation Results

The current reviewed database contains **2,472,228 normalized records**.

| Source | Normalized table | Records |
|---|---|---:|
| DNS | `normalized_events` | 350,000 |
| Application security | `normalized_app_events` | 438,739 |
| Firewall | `normalized_firewall_events` | 394,170 |
| Linux syslog | `normalized_linux_events` | 977,509 |
| Windows Security | `normalized_windows_events` | 311,810 |
| **Total** | | **2,472,228** |

The reviewed unified investigation register contains **767,672 finding rows**.

| Source | Findings |
|---|---:|
| DNS | 65,825 |
| Application security | 159,792 |
| Firewall | 275,111 |
| Linux syslog | 218,002 |
| Windows Security | 48,942 |
| **Total** | **767,672** |

Finding totals are not unique attack or incident counts. Checks can overlap, and one event can generate more than one finding.

## Technology

- Python 3.14.6 (development environment)
- DuckDB 1.5.4
- Python standard library

## Repository Layout

```text
.
├── docs/
│   └── SOC_Threat_Hunting_Engine_Technical_Documentation.pdf
├── logs/                         # Downloaded input datasets
├── reports/                      # Generated investigation outputs
├── src/
│   └── threat_hunt_engine/
│       ├── __init__.py
│       ├── ingestion.py
│       ├── investigation_checks.py
│       ├── investigation_register.py
│       ├── database_validation.py
│       ├── duplicate_id_check.py
│       ├── source_metadata_review.py
│       ├── source_quality_review.py
│       └── validate_windows_events.py
├── requirements.txt
├── README.md
└── TECHNICAL_DOCUMENTATION.md
```

The DuckDB database, raw logs, and generated reports are local project data and are not required to be committed to GitHub.

## Setup

### 1. Prerequisites

- Windows, Linux, or macOS
- Python installed and available as `python` or `py`
- The project source code
- The required input datasets

### 2. Clone the Repository

```bash
git clone https://github.com/chinemerem-nsv/splunk-threat-hunt-engine.git
cd splunk-threat-hunt-engine
```

### 3. Install Dependencies

From the repository root:

```powershell
py -m pip install -r requirements.txt
```

The current tested DuckDB dependency is pinned in `requirements.txt`.

### 4. Download the Raw Datasets

The raw log files are hosted separately on Google Drive to avoid placing large dataset files directly in the GitHub repository.

**[Download the SOC Threat Hunting Engine Raw Datasets](https://drive.google.com/drive/folders/1niRhwSo0ZjvK1m56-cSASloZ8NzCHpXz?usp=sharing)**

Download all five files and place them inside a folder named `logs` in the project root.

Required files:

- `dns_query_logs.jsonl`
- `app_sec_audit.log`
- `firewall_traffic.log`
- `linux_syslog.log`
- `windows_security_events.log`

Keep the original filenames unchanged. The ingestion scripts expect these exact filenames and directory locations.

After downloading, your project should contain:

```text
splunk-threat-hunt-engine/
├── logs/
│   ├── dns_query_logs.jsonl
│   ├── app_sec_audit.log
│   ├── firewall_traffic.log
│   ├── linux_syslog.log
│   └── windows_security_events.log
├── src/
├── docs/
├── requirements.txt
└── README.md
```

Obtain and use the datasets only in accordance with their applicable access, licensing, and handling requirements.

### 5. Run Ingestion

Run from the repository root:

```powershell
py -m src.threat_hunt_engine.ingestion
```

The full ingestion command rebuilds the normalized tables in `threat_hunt.duckdb`. It uses `CREATE OR REPLACE TABLE`; rerunning it replaces the existing normalized tables.

To rebuild only the Linux table:

```powershell
py -m src.threat_hunt_engine.ingestion --linux-only
```

Use Linux-only mode when you intentionally want to refresh the Linux table while retaining the other existing tables in the database.

## Run Validation

Run the validation scripts from the repository root:

```powershell
py -m src.threat_hunt_engine.source_metadata_review
py -m src.threat_hunt_engine.source_quality_review
py -m src.threat_hunt_engine.database_validation
py -m src.threat_hunt_engine.duplicate_id_check
```

## Generate Investigation Outputs

First, generate or refresh the Windows validation findings:

```powershell
py -m src.threat_hunt_engine.validate_windows_events
```

Then generate the unified investigation register:

```powershell
py -m src.threat_hunt_engine.investigation_register
```

The register generator writes:

- `reports/investigation_register.csv`
- `reports/investigation_register_summary.txt`

A separate timestamped investigation report can be generated with:

```powershell
py -m src.threat_hunt_engine.investigation_checks
```

## Important Interpretation Notes

- A matching rule means that a record met a check condition; it does not prove malicious activity.
- Severity is a triage priority, not a confirmed incident verdict.
- Multiple checks can match the same event. Finding totals must not be interpreted as unique event totals.
- The current workflow does not correlate activity across different log sources.
- Linux source timestamps do not include a year. The original timestamp text is retained, but the normalized `event_timestamp` field is NULL for the current Linux dataset.
- Windows findings are imported from a separate validation CSV. That CSV does not include the raw event text, so the raw-event field is blank for Windows rows in the unified register. The normalized Windows table retains the raw event text and source-line reference.

For implementation details, schema information, check logic, observed findings, known limitations, and reproducibility notes, see [TECHNICAL_DOCUMENTATION.md](TECHNICAL_DOCUMENTATION.md) and the PDF in [`docs/`](docs/SOC_Threat_Hunting_Engine_Technical_Documentation.pdf).

## Data Handling and Licensing

The code licence and dataset licences are separate. A licence for the source code does not grant permission to redistribute third-party logs or datasets.

Before publishing or sharing data:

- Confirm the provenance and redistribution terms for each dataset.
- Review records for credentials, tokens, personal information, internal hostnames, and sensitive network details.
- Keep the DuckDB database, raw source logs, and large generated reports out of Git unless there is a clear, authorized reason to include them.
- Prefer a small synthetic or explicitly redistributable sample for public testing.

## Project Status

The current implementation has been exercised against the datasets and environment described in the technical documentation. The recorded row counts are reference results for that reviewed dataset and code state; they are not guaranteed for other data, parser versions, or configurations.

## Licence

The intended code licence is MIT. Dataset and third-party content remain subject to their own licences and redistribution terms. See [`LICENSE`](LICENSE) when included in the repository.
