from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from src.correlator.analysis import correlate_events
from src.correlator.normalization import load_firewall_csv, load_ids_json, load_pcap_csv
from src.correlator.reporting import (
    build_timeline_rows,
    render_csv_exports,
    render_executive_summary,
    render_html_dashboard,
    render_markdown_report,
)


def load_sample_data_dir() -> Path:
    return Path("data") / "sample"


def _serialize_incident(incident) -> dict:
    payload = asdict(incident)
    payload["start_time"] = incident.start_time.isoformat()
    payload["end_time"] = incident.end_time.isoformat()
    payload["phases"] = [phase.value for phase in incident.phases]
    payload["events"] = []
    for event in incident.events:
        payload["events"].append(
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source.value,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "action": event.action,
                "severity": event.severity,
                "summary": event.summary,
                "raw": event.raw,
                "bytes_transferred": event.bytes_transferred,
                "packet_count": event.packet_count,
                "signature": event.signature,
                "category": event.category,
            }
        )
    return payload


def _build_timeline(events, incidents) -> list[dict]:
    timeline = build_timeline_rows(events)
    incident_map: dict[str, dict] = {}
    for incident in incidents:
        phase_names = [phase.value for phase in incident.phases]
        for event in incident.events:
            incident_map[event.event_id] = {
                "incident_id": incident.incident_id,
                "risk_score": incident.risk_score,
                "phases": phase_names,
            }

    for row in timeline:
        incident_data = incident_map.get(row["event_id"], {})
        row["incident_id"] = incident_data.get("incident_id")
        row["risk_score"] = incident_data.get("risk_score", 0)
        row["phases"] = incident_data.get("phases", [])
    return timeline


def _render_json_export(result: dict, output_dir: str | Path) -> Path:
    output_path = Path(output_dir) / "analysis.json"
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return output_path


def run_analysis(
    pcap_path: str | Path | None = None,
    firewall_path: str | Path | None = None,
    ids_path: str | Path | None = None,
    sample: bool = False,
    output_dir: str | Path = "reports",
) -> dict:
    if sample:
        sample_dir = load_sample_data_dir()
        pcap_path = sample_dir / "pcap_events.csv"
        firewall_path = sample_dir / "firewall_logs.csv"
        ids_path = sample_dir / "ids_alerts.json"

    if not all([pcap_path, firewall_path, ids_path]):
        raise ValueError("PCAP, firewall, and IDS inputs are all required.")

    events = []
    events.extend(load_pcap_csv(pcap_path))
    events.extend(load_firewall_csv(firewall_path))
    events.extend(load_ids_json(ids_path))

    incidents = correlate_events(events)
    report_path = render_markdown_report(incidents, output_dir=output_dir)
    timeline = _build_timeline(events, incidents)
    result = {
        "events": timeline,
        "timeline": timeline,
        "incidents": [_serialize_incident(incident) for incident in incidents],
        "report_path": str(report_path),
    }
    dashboard_path = render_html_dashboard(result, output_dir=output_dir)
    csv_paths = render_csv_exports(result, output_dir=output_dir)
    executive_summary_path = render_executive_summary(result, output_dir=output_dir)
    result["dashboard_path"] = str(dashboard_path)
    result["json_path"] = str(Path(output_dir) / "analysis.json")
    result["timeline_csv_path"] = str(csv_paths["timeline_csv_path"])
    result["incidents_csv_path"] = str(csv_paths["incidents_csv_path"])
    result["executive_summary_path"] = str(executive_summary_path)
    _render_json_export(result, output_dir=output_dir)
    return result
