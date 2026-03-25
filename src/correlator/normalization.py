from __future__ import annotations

import json
import csv
from pathlib import Path

from src.correlator.models import EvidenceSource, NormalizedEvent
from src.correlator.utils import new_event_id, parse_timestamp


def _safe_int(value) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def load_pcap_csv(path: str | Path) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            events.append(
                NormalizedEvent(
                    event_id=new_event_id("pcap"),
                    timestamp=parse_timestamp(str(row["timestamp"])),
                    source=EvidenceSource.PCAP,
                    src_ip=str(row["src_ip"]),
                    dst_ip=str(row["dst_ip"]),
                    src_port=_safe_int(row.get("src_port")),
                    dst_port=_safe_int(row.get("dst_port")),
                    protocol=str(row.get("protocol", "unknown")).upper(),
                    action="observed",
                    severity=2,
                    summary=str(row.get("notes", "PCAP network event")),
                    raw=row,
                    bytes_transferred=int(row.get("bytes", 0) or 0),
                    packet_count=int(row.get("packet_count", 0) or 0),
                )
            )
    return events


def load_firewall_csv(path: str | Path) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            action = str(row.get("action", "unknown")).lower()
            severity = 4 if action == "blocked" else 2
            events.append(
                NormalizedEvent(
                    event_id=new_event_id("fw"),
                    timestamp=parse_timestamp(str(row["timestamp"])),
                    source=EvidenceSource.FIREWALL,
                    src_ip=str(row["src_ip"]),
                    dst_ip=str(row["dst_ip"]),
                    src_port=_safe_int(row.get("src_port")),
                    dst_port=_safe_int(row.get("dst_port")),
                    protocol=str(row.get("protocol", "unknown")).upper(),
                    action=action,
                    severity=severity,
                    summary=f"Firewall {action} by rule {row.get('rule', 'n/a')}",
                    raw=row,
                )
            )
    return events


def load_ids_json(path: str | Path) -> list[NormalizedEvent]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    events: list[NormalizedEvent] = []
    for row in payload:
        severity = int(row.get("severity", 3))
        events.append(
            NormalizedEvent(
                event_id=new_event_id("ids"),
                timestamp=parse_timestamp(str(row["timestamp"])),
                source=EvidenceSource.IDS,
                src_ip=str(row["src_ip"]),
                dst_ip=str(row["dst_ip"]),
                src_port=_safe_int(row.get("src_port")),
                dst_port=_safe_int(row.get("dst_port")),
                protocol=str(row.get("protocol", "unknown")).upper(),
                action="alert",
                severity=severity,
                summary=str(row.get("signature", "IDS alert")),
                raw=row,
                signature=row.get("signature"),
                category=row.get("category"),
            )
        )
    return events
