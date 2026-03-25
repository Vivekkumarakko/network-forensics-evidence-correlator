from __future__ import annotations

import csv
import html
from collections import Counter
from pathlib import Path

from src.correlator.models import CorrelatedIncident, NormalizedEvent
from src.correlator.utils import ensure_directory


def build_timeline_rows(events: list[NormalizedEvent]) -> list[dict]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    return [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source.value,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "protocol": event.protocol,
            "action": event.action,
            "summary": event.summary,
            "severity": event.severity,
        }
        for event in ordered
    ]


def render_markdown_report(incidents: list[CorrelatedIncident], output_dir: str | Path = "reports") -> Path:
    ensure_directory(output_dir)
    output_path = Path(output_dir) / "forensic_report.md"
    lines = [
        "# Network Forensics Evidence Correlator Report",
        "",
        f"Total Incidents: {len(incidents)}",
        "",
    ]

    for incident in incidents:
        lines.extend(
            [
                f"## {incident.incident_id}",
                "",
                f"- Time Window: {incident.start_time.isoformat()} to {incident.end_time.isoformat()}",
                f"- Flow: {incident.src_ip} -> {incident.dst_ip} ({incident.protocol})",
                f"- Risk Score: {incident.risk_score}/100",
                f"- Attack Phases: {', '.join(phase.value for phase in incident.phases) or 'Unknown'}",
                f"- MITRE ATT&CK: {', '.join(incident.mitre_techniques) or 'None'}",
                f"- Narrative: {incident.narrative}",
                "",
                "### Evidence",
                "",
            ]
        )
        for event in incident.events:
            lines.append(
                f"- `{event.timestamp.isoformat()}` [{event.source.value}] {event.summary} "
                f"({event.src_ip}:{event.src_port or '-'} -> {event.dst_ip}:{event.dst_port or '-'})"
            )
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = []
    for row in rows:
        cols = "".join(f"<td>{html.escape(str(value))}</td>" for value in row)
        body.append(f"<tr>{cols}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_html_dashboard(analysis_result: dict, output_dir: str | Path = "reports") -> Path:
    reports_dir = ensure_directory(output_dir)
    output_path = Path(output_dir) / "dashboard.html"

    incidents = analysis_result["incidents"]
    timeline = analysis_result["timeline"]
    highest_risk = max((incident["risk_score"] for incident in incidents), default=0)
    mitre_total = len({tech for incident in incidents for tech in incident["mitre_techniques"]})

    metric_cards = f"""
    <section class="metrics">
      <div class="card"><span>Total Events</span><strong>{len(analysis_result['events'])}</strong></div>
      <div class="card"><span>Incidents</span><strong>{len(incidents)}</strong></div>
      <div class="card"><span>Highest Risk</span><strong>{highest_risk}/100</strong></div>
      <div class="card"><span>MITRE Techniques</span><strong>{mitre_total}</strong></div>
    </section>
    """

    timeline_rows = [
        [
            row["timestamp"],
            row["source"],
            row["src_ip"],
            row["dst_ip"],
            row["protocol"],
            row["action"],
            row["summary"],
            row["severity"],
        ]
        for row in timeline
    ]
    timeline_table = _render_table(
        ["Timestamp", "Source", "Source IP", "Destination IP", "Protocol", "Action", "Summary", "Severity"],
        timeline_rows,
    )

    incident_sections = []
    for incident in incidents:
        evidence_rows = [
            [
                event["timestamp"],
                event["source"],
                event["summary"],
                event["src_ip"],
                event["dst_ip"],
                event["protocol"],
                event["action"],
                event["severity"],
            ]
            for event in incident["events"]
        ]
        evidence_table = _render_table(
            ["Timestamp", "Source", "Summary", "Source IP", "Destination IP", "Protocol", "Action", "Severity"],
            evidence_rows,
        )
        incident_sections.append(
            f"""
            <article class="incident">
              <div class="incident-header">
                <h3>{html.escape(incident['incident_id'])}</h3>
                <span class="risk">Risk {incident['risk_score']}/100</span>
              </div>
              <p>{html.escape(incident['src_ip'])} to {html.escape(incident['dst_ip'])} over {html.escape(incident['protocol'])}</p>
              <p>{html.escape(incident['narrative'])}</p>
              <p><strong>Phases:</strong> {html.escape(', '.join(incident['phases']) or 'Unknown')}</p>
              <p><strong>MITRE ATT&CK:</strong> {html.escape(', '.join(incident['mitre_techniques']) or 'None')}</p>
              {evidence_table}
            </article>
            """
        )

    markup = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Network Forensics Evidence Correlator</title>
  <style>
    :root {{
      --bg: #07111a;
      --panel: #102332;
      --panel-soft: #f7f4ee;
      --text: #e7f1f5;
      --text-dark: #102332;
      --accent: #ff6d00;
      --accent-soft: #1a8bb2;
      --border: rgba(173, 212, 225, 0.2);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Trebuchet MS", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(26, 139, 178, 0.22), transparent 30%),
        linear-gradient(180deg, var(--bg) 0%, #102332 52%, #f3efe8 52%, #f8f5ef 100%);
      color: var(--text);
    }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px 60px; }}
    .hero {{ padding: 18px 0 28px; }}
    .hero h1 {{ margin: 0 0 8px; font-size: 2.3rem; }}
    .hero p {{ margin: 0; max-width: 760px; line-height: 1.5; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin: 18px 0 28px;
    }}
    .card, .panel, .incident {{
      background: rgba(10, 24, 35, 0.82);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 18px 40px rgba(5, 11, 17, 0.2);
    }}
    .card span {{ display: block; color: #9fc0cc; margin-bottom: 8px; }}
    .card strong {{ font-size: 1.9rem; }}
    .panel {{
      margin-bottom: 24px;
      overflow-x: auto;
    }}
    .panel.light, .incident {{
      background: rgba(247, 244, 238, 0.96);
      color: var(--text-dark);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.95rem;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(16, 35, 50, 0.12);
      vertical-align: top;
    }}
    th {{
      background: rgba(26, 139, 178, 0.12);
    }}
    .incident-list {{
      display: grid;
      gap: 18px;
    }}
    .incident-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
    }}
    .risk {{
      display: inline-block;
      background: #102332;
      color: #f7f4ee;
      border-radius: 999px;
      padding: 6px 12px;
      font-weight: 700;
    }}
    .footer {{
      margin-top: 22px;
      color: #dce8ec;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Network Forensics Evidence Correlator</h1>
      <p>Unified post-incident reconstruction across PCAP traffic, firewall activity, and IDS alerts with attack phase mapping, MITRE enrichment, risk scoring, and evidence-backed narratives.</p>
    </section>
    {metric_cards}
    <section class="panel light">
      <h2>Attack Timeline</h2>
      {timeline_table}
    </section>
    <section class="incident-list">
      {''.join(incident_sections)}
    </section>
    <p class="footer">Markdown report: {html.escape(analysis_result['report_path'])}</p>
  </div>
</body>
</html>
"""
    output_path.write_text(markup, encoding="utf-8")
    return output_path


def render_csv_exports(analysis_result: dict, output_dir: str | Path = "reports") -> dict[str, Path]:
    ensure_directory(output_dir)
    timeline_path = Path(output_dir) / "timeline.csv"
    incidents_path = Path(output_dir) / "incidents.csv"

    timeline_rows = analysis_result["timeline"]
    if timeline_rows:
        serialized_timeline_rows = []
        for row in timeline_rows:
            serialized_timeline_rows.append(
                {
                    **row,
                    "phases": " | ".join(row["phases"]) if isinstance(row.get("phases"), list) else row.get("phases", ""),
                }
            )
        with timeline_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(serialized_timeline_rows[0].keys()))
            writer.writeheader()
            writer.writerows(serialized_timeline_rows)
    else:
        timeline_path.write_text("", encoding="utf-8")

    incident_rows = []
    for incident in analysis_result["incidents"]:
        incident_rows.append(
            {
                "incident_id": incident["incident_id"],
                "start_time": incident["start_time"],
                "end_time": incident["end_time"],
                "src_ip": incident["src_ip"],
                "dst_ip": incident["dst_ip"],
                "protocol": incident["protocol"],
                "risk_score": incident["risk_score"],
                "phases": " | ".join(incident["phases"]) or "Unknown",
                "mitre_techniques": " | ".join(incident["mitre_techniques"]) or "None",
                "event_count": len(incident["events"]),
                "narrative": incident["narrative"],
            }
        )

    if incident_rows:
        with incidents_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(incident_rows[0].keys()))
            writer.writeheader()
            writer.writerows(incident_rows)
    else:
        incidents_path.write_text("", encoding="utf-8")

    return {
        "timeline_csv_path": timeline_path,
        "incidents_csv_path": incidents_path,
    }


def render_executive_summary(analysis_result: dict, output_dir: str | Path = "reports") -> Path:
    ensure_directory(output_dir)
    output_path = Path(output_dir) / "executive_summary.html"

    incidents = analysis_result["incidents"]
    timeline = analysis_result["timeline"]
    total_events = len(timeline)
    total_incidents = len(incidents)
    highest_risk = max((incident["risk_score"] for incident in incidents), default=0)
    average_risk = round(sum(incident["risk_score"] for incident in incidents) / total_incidents, 1) if incidents else 0

    phase_counts = Counter()
    technique_counts = Counter()
    target_counts = Counter()
    for incident in incidents:
        phase_counts.update(incident["phases"] or ["Unknown"])
        technique_counts.update(incident["mitre_techniques"])
        target_counts.update([incident["dst_ip"]])

    top_target = target_counts.most_common(1)[0][0] if target_counts else "None"
    dominant_phase = phase_counts.most_common(1)[0][0] if phase_counts else "Unknown"
    top_techniques = technique_counts.most_common(4)

    phase_rows = "".join(
        f"<tr><td>{html.escape(phase)}</td><td>{count}</td></tr>"
        for phase, count in phase_counts.items()
    ) or "<tr><td>Unknown</td><td>0</td></tr>"

    technique_items = "".join(
        f"<li>{html.escape(name)} <strong>{count}</strong></li>"
        for name, count in top_techniques
    ) or "<li>No MITRE techniques inferred.</li>"

    chain_cards = []
    for incident in incidents:
        phase_nodes = incident["phases"] or ["Unknown"]
        phase_markup = "".join(
            f'<div class="phase-node">{html.escape(phase)}</div><div class="arrow">→</div>'
            for phase in phase_nodes
        )
        if phase_markup.endswith('<div class="arrow">→</div>'):
            phase_markup = phase_markup[: -len('<div class="arrow">→</div>')]
        chain_cards.append(
            f"""
            <div class="chain-card">
              <div class="chain-head">
                <h3>{html.escape(incident['incident_id'])}</h3>
                <span>Risk {incident['risk_score']}/100</span>
              </div>
              <div class="chain-line">
                <div class="endpoint attacker">{html.escape(incident['src_ip'])}</div>
                <div class="arrow">→</div>
                {phase_markup}
                <div class="arrow">→</div>
                <div class="endpoint victim">{html.escape(incident['dst_ip'])}</div>
              </div>
              <p>{html.escape(incident['narrative'])}</p>
            </div>
            """
        )

    recommendations = [
        "Contain or isolate the most affected destination assets and validate whether outbound channels remain active.",
        "Review exposed services and patch paths associated with the exploitation phase before restoring access.",
        "Hunt for additional activity tied to the same source or destination IPs across DNS, proxy, and endpoint telemetry.",
    ]
    recommendation_markup = "".join(f"<li>{html.escape(item)}</li>" for item in recommendations)

    markup = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Executive Summary</title>
  <style>
    :root {{
      --ink: #14222c;
      --muted: #4d6472;
      --paper: #fffdfa;
      --accent: #d95f02;
      --accent-soft: #e9f5f8;
      --border: #d8e3e8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background: #eef4f6;
    }}
    .page {{
      max-width: 980px;
      margin: 0 auto;
      padding: 24px;
    }}
    .sheet {{
      background: var(--paper);
      border-radius: 20px;
      padding: 28px;
      box-shadow: 0 18px 48px rgba(20, 34, 44, 0.08);
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      margin-bottom: 24px;
      border-bottom: 2px solid var(--border);
      padding-bottom: 18px;
    }}
    .header h1 {{
      margin: 0 0 8px;
      font-size: 2.2rem;
    }}
    .meta {{
      color: var(--muted);
      text-align: right;
    }}
    .hero-grid, .section-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }}
    .stat {{
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
      background: linear-gradient(180deg, white, #f7fafb);
    }}
    .stat span {{
      display: block;
      color: var(--muted);
      margin-bottom: 8px;
    }}
    .stat strong {{
      font-size: 1.8rem;
      color: var(--accent);
    }}
    .section {{
      margin-bottom: 24px;
    }}
    .section h2 {{
      margin: 0 0 12px;
      font-size: 1.25rem;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: 1.25fr 0.75fr;
      gap: 18px;
    }}
    .panel {{
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
      background: white;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: var(--accent-soft);
    }}
    .chain-list {{
      display: grid;
      gap: 16px;
    }}
    .chain-card {{
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
      background: linear-gradient(180deg, white, #fbfcfd);
    }}
    .chain-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .chain-head h3 {{
      margin: 0;
    }}
    .chain-head span {{
      border-radius: 999px;
      padding: 6px 12px;
      background: var(--ink);
      color: white;
      font-weight: 700;
    }}
    .chain-line {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin-bottom: 10px;
    }}
    .endpoint, .phase-node {{
      border-radius: 999px;
      padding: 8px 12px;
      font-weight: 700;
    }}
    .endpoint.attacker {{
      background: #fff1e8;
      color: #a14300;
    }}
    .endpoint.victim {{
      background: #ecf6fa;
      color: #135b76;
    }}
    .phase-node {{
      background: #edf3f5;
    }}
    .arrow {{
      color: var(--muted);
      font-weight: 700;
    }}
    .print-bar {{
      margin-top: 24px;
      display: flex;
      justify-content: flex-end;
    }}
    .print-bar button {{
      border: 0;
      border-radius: 999px;
      padding: 11px 16px;
      background: var(--accent);
      color: white;
      font-weight: 700;
      cursor: pointer;
    }}
    @media print {{
      body {{
        background: white;
      }}
      .page {{
        max-width: none;
        padding: 0;
      }}
      .sheet {{
        box-shadow: none;
        border-radius: 0;
      }}
      .print-bar {{
        display: none;
      }}
    }}
    @media (max-width: 820px) {{
      .hero-grid, .section-grid, .summary-grid {{
        grid-template-columns: 1fr 1fr;
      }}
      .header {{
        flex-direction: column;
      }}
      .meta {{
        text-align: left;
      }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <div class="sheet">
      <div class="header">
        <div>
          <h1>Executive Attack Summary</h1>
          <p>Condensed briefing for leadership, incident management, and post-incident review.</p>
        </div>
        <div class="meta">
          <div>Total Events: {total_events}</div>
          <div>Total Incidents: {total_incidents}</div>
          <div>Top Target: {html.escape(top_target)}</div>
        </div>
      </div>

      <section class="hero-grid">
        <div class="stat"><span>Highest Risk</span><strong>{highest_risk}/100</strong></div>
        <div class="stat"><span>Average Risk</span><strong>{average_risk}</strong></div>
        <div class="stat"><span>Dominant Phase</span><strong>{html.escape(dominant_phase)}</strong></div>
        <div class="stat"><span>Most Targeted Asset</span><strong>{html.escape(top_target)}</strong></div>
      </section>

      <section class="section summary-grid">
        <div class="panel">
          <h2>Executive Narrative</h2>
          <p>The evidence set indicates {total_incidents} correlated incident threads reconstructed from {total_events} normalized events. The highest assessed risk reached {highest_risk}/100, with {html.escape(dominant_phase)} appearing as the dominant attack phase across the observed chain.</p>
          <p>The most affected destination asset was <strong>{html.escape(top_target)}</strong>. This suggests investigative focus should prioritize containment, retrospective log review, and validation of any residual outbound activity from that asset group.</p>
        </div>
        <div class="panel">
          <h2>Top MITRE Techniques</h2>
          <ul>{technique_items}</ul>
        </div>
      </section>

      <section class="section summary-grid">
        <div class="panel">
          <h2>Phase Distribution</h2>
          <table>
            <thead><tr><th>Phase</th><th>Count</th></tr></thead>
            <tbody>{phase_rows}</tbody>
          </table>
        </div>
        <div class="panel">
          <h2>Recommended Actions</h2>
          <ol>{recommendation_markup}</ol>
        </div>
      </section>

      <section class="section">
        <h2>Attack Chains</h2>
        <div class="chain-list">
          {''.join(chain_cards) or '<p>No incidents available.</p>'}
        </div>
      </section>

      <div class="print-bar">
        <button onclick="window.print()">Print Executive Summary</button>
      </div>
    </div>
  </div>
</body>
</html>
"""
    output_path.write_text(markup, encoding="utf-8")
    return output_path
