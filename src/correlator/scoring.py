from __future__ import annotations

from src.correlator.models import AttackPhase, NormalizedEvent


def calculate_risk_score(events: list[NormalizedEvent], phases: list[AttackPhase]) -> int:
    score = 0
    severity_total = sum(event.severity for event in events)
    ids_events = sum(1 for event in events if event.source.value == "ids")
    blocked = sum(1 for event in events if event.action.lower() == "blocked")
    bytes_sent = sum(event.bytes_transferred for event in events)

    score += min(severity_total * 4, 40)
    score += min(ids_events * 6, 18)
    score += min(blocked * 2, 8)

    if AttackPhase.EXFILTRATION in phases:
        score += 25
    if AttackPhase.EXPLOITATION in phases:
        score += 15
    if AttackPhase.RECONNAISSANCE in phases:
        score += 10
    if bytes_sent > 100_000:
        score += 10
    elif bytes_sent > 25_000:
        score += 6

    return min(score, 100)
