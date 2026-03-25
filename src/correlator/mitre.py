from __future__ import annotations

from src.correlator.models import AttackPhase, NormalizedEvent


PHASE_TO_MITRE = {
    AttackPhase.RECONNAISSANCE: [
        "T1046 - Network Service Scanning",
        "T1595 - Active Scanning",
    ],
    AttackPhase.EXPLOITATION: [
        "T1190 - Exploit Public-Facing Application",
        "T1059 - Command and Scripting Interpreter",
    ],
    AttackPhase.EXFILTRATION: [
        "T1041 - Exfiltration Over C2 Channel",
        "T1048 - Exfiltration Over Alternative Protocol",
    ],
}


def infer_mitre_techniques(phases: list[AttackPhase], events: list[NormalizedEvent]) -> list[str]:
    techniques: list[str] = []
    for phase in phases:
        techniques.extend(PHASE_TO_MITRE.get(phase, []))

    for event in events:
        text = " ".join(
            [
                event.summary,
                event.signature or "",
                event.category or "",
            ]
        ).lower()
        if "sql" in text:
            techniques.append("T1190 - Exploit Public-Facing Application")
        if "scan" in text or "port sweep" in text:
            techniques.append("T1046 - Network Service Scanning")
        if "dns" in text and event.bytes_transferred > 0:
            techniques.append("T1048 - Exfiltration Over Alternative Protocol")

    return sorted(set(techniques))
