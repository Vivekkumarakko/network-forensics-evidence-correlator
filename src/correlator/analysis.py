from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from src.correlator.mitre import infer_mitre_techniques
from src.correlator.models import AttackPhase, CorrelatedIncident, EvidenceSource, NormalizedEvent
from src.correlator.scoring import calculate_risk_score


TIME_WINDOW = timedelta(minutes=5)


def infer_attack_phase(event: NormalizedEvent) -> AttackPhase:
    text = " ".join(
        [
            event.summary or "",
            event.signature or "",
            event.category or "",
            event.action or "",
        ]
    ).lower()

    if any(keyword in text for keyword in ["scan", "sweep", "recon", "probe"]):
        return AttackPhase.RECONNAISSANCE
    if any(keyword in text for keyword in ["exploit", "injection", "rce", "shell", "web attack"]):
        return AttackPhase.EXPLOITATION
    if any(keyword in text for keyword in ["exfil", "large transfer", "dns tunnel", "data staging"]):
        return AttackPhase.EXFILTRATION

    if event.source == EvidenceSource.PCAP and event.bytes_transferred > 50_000 and event.dst_port in {53, 443, 8080}:
        return AttackPhase.EXFILTRATION
    if event.source == EvidenceSource.FIREWALL and event.action == "blocked":
        return AttackPhase.RECONNAISSANCE

    return AttackPhase.UNKNOWN


def correlate_events(events: list[NormalizedEvent]) -> list[CorrelatedIncident]:
    ordered = sorted(events, key=lambda item: item.timestamp)
    clusters: dict[tuple[str, str, str], list[list[NormalizedEvent]]] = defaultdict(list)

    for event in ordered:
        key = (event.src_ip, event.dst_ip, event.protocol)
        if not clusters[key]:
            clusters[key].append([event])
            continue

        current_cluster = clusters[key][-1]
        last_event = current_cluster[-1]
        if event.timestamp - last_event.timestamp <= TIME_WINDOW:
            current_cluster.append(event)
        else:
            clusters[key].append([event])

    incidents: list[CorrelatedIncident] = []
    counter = 1

    for (src_ip, dst_ip, protocol), event_groups in clusters.items():
        for group in event_groups:
            phases = [infer_attack_phase(event) for event in group]
            filtered_phases = sorted(set(phase for phase in phases if phase != AttackPhase.UNKNOWN), key=lambda item: item.value)
            score = calculate_risk_score(group, filtered_phases)
            mitre = infer_mitre_techniques(filtered_phases, group)
            narrative = build_narrative(group, filtered_phases, score)
            incidents.append(
                CorrelatedIncident(
                    incident_id=f"INC-{counter:04d}",
                    start_time=group[0].timestamp,
                    end_time=group[-1].timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    events=group,
                    phases=filtered_phases,
                    risk_score=score,
                    mitre_techniques=mitre,
                    narrative=narrative,
                )
            )
            counter += 1

    return sorted(incidents, key=lambda item: item.start_time)


def build_narrative(events: list[NormalizedEvent], phases: list[AttackPhase], score: int) -> str:
    sources = ", ".join(sorted({event.source.value for event in events}))
    phase_text = " -> ".join(phase.value for phase in phases) if phases else "Unclassified activity"
    return (
        f"Correlated {len(events)} events from {sources}. "
        f"Observed attack path: {phase_text}. "
        f"Assigned risk score: {score}/100."
    )
