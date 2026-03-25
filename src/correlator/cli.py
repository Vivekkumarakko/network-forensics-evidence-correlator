from __future__ import annotations

import argparse
import json
from pathlib import Path

from tabulate import tabulate

from src.correlator.pipeline import run_analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Network Forensics Evidence Correlator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze network evidence")
    analyze.add_argument("--pcap", type=Path, help="Path to PCAP CSV export")
    analyze.add_argument("--firewall", type=Path, help="Path to firewall CSV log")
    analyze.add_argument("--ids", type=Path, help="Path to IDS JSON alerts")
    analyze.add_argument("--sample", action="store_true", help="Use bundled sample evidence")
    analyze.add_argument("--json", action="store_true", help="Print JSON output")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        result = run_analysis(
            pcap_path=args.pcap,
            firewall_path=args.firewall,
            ids_path=args.ids,
            sample=args.sample,
        )
        if args.json:
            print(json.dumps(result, default=str, indent=2))
            return

        rows = [
            [
                incident["incident_id"],
                incident["src_ip"],
                incident["dst_ip"],
                incident["protocol"],
                incident["risk_score"],
                ", ".join(phase for phase in incident["phases"]) or "Unknown",
            ]
            for incident in result["incidents"]
        ]
        print(
            tabulate(
                rows,
                headers=["Incident", "Source", "Destination", "Proto", "Risk", "Phases"],
                tablefmt="github",
            )
        )
        print()
        print(f"Report written to: {result['report_path']}")


if __name__ == "__main__":
    main()
