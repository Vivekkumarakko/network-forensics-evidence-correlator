# Network Forensics Evidence Correlator

A production-style starter project that ingests packet evidence, firewall logs, and IDS alerts, normalizes them into a shared schema, correlates suspicious activity into attack stories, and produces a timeline, MITRE ATT&CK mapping, risk scores, a forensic report, a static SOC dashboard, and an interactive upload-driven web console.

## Features

- Multi-source ingestion for:
  - PCAP-derived CSV exports
  - Firewall logs in CSV
  - IDS alerts in JSON
- Common event normalization model
- Correlation using IP, port, protocol, and time-window proximity
- Attack phase classification:
  - Reconnaissance
  - Exploitation
  - Exfiltration
- MITRE ATT&CK enrichment
- Risk scoring
- CLI report generator
- Static HTML dashboard for SOC analysts
- Flask web console with file uploads and saved runs
- Drag-and-drop evidence uploads, filters, and JSON export
- Attack-chain visualizations, CSV exports, and printable executive summary
- Analyst login, persistent case notes, and multi-run comparison
- Production deployment support via Waitress, Docker, and Render config

## Project Structure

```text
network_forensics_correlator/
  dashboard/
  data/
    sample/
  src/
    correlator/
  web/
```

## Quick Start

1. Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Generate a forensic report from bundled sample data:

```powershell
python -m src.correlator.cli analyze --sample
```

3. Generate the dashboard:

```powershell
python dashboard/app.py
```

4. Start the interactive web console:

```powershell
python web/app.py
```

5. Start the production server locally:

```powershell
waitress-serve --host=0.0.0.0 --port=8000 web.app:app
```

Default local demo login:

- Username: `analyst`
- Password: `correlator123`

For production, set environment variables from `.env.example` and change the demo password.

## Input Formats

### PCAP CSV

Expected columns:

- `timestamp`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `packet_count`
- `bytes`
- `notes`

### Firewall CSV

Expected columns:

- `timestamp`
- `action`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `rule`

### IDS JSON

Expected top-level JSON array of objects with fields like:

- `timestamp`
- `signature`
- `severity`
- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `category`

## Outputs

- Unified timeline
- Correlated incidents
- MITRE ATT&CK mapping
- Risk scoring summary
- Markdown forensic report in `reports/`
- Static HTML dashboard in `reports/dashboard.html`
- Per-run saved artifacts in `reports/runs/<run_id>/`
- Timeline CSV and incident summary CSV
- Printable executive summary HTML
- Saved analyst notes per run
- Protected comparison view across multiple investigations
- `/healthz` readiness endpoint for hosting platforms

## Why This Matters

Traditional SIEM systems focus on real-time alerting. This project focuses on post-incident reconstruction, making it easier for investigators to understand how an attack unfolded across multiple evidence sources.
