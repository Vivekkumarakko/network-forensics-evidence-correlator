from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class EvidenceSource(str, Enum):
    PCAP = "pcap"
    FIREWALL = "firewall"
    IDS = "ids"


class AttackPhase(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    EXPLOITATION = "Exploitation"
    EXFILTRATION = "Exfiltration"
    UNKNOWN = "Unknown"


@dataclass(slots=True)
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    source: EvidenceSource
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    protocol: str
    action: str
    severity: int
    summary: str
    raw: dict
    bytes_transferred: int = 0
    packet_count: int = 0
    signature: str | None = None
    category: str | None = None


@dataclass(slots=True)
class CorrelatedIncident:
    incident_id: str
    start_time: datetime
    end_time: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    events: list[NormalizedEvent] = field(default_factory=list)
    phases: list[AttackPhase] = field(default_factory=list)
    risk_score: int = 0
    mitre_techniques: list[str] = field(default_factory=list)
    narrative: str = ""
