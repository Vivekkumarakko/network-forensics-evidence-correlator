from __future__ import annotations

import html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.correlator.pipeline import run_analysis


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = []
    for row in rows:
        cols = "".join(f"<td>{html.escape(str(value))}</td>" for value in row)
        body.append(f"<tr>{cols}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def build_dashboard() -> Path:
    result = run_analysis(sample=True)
    return Path(result["dashboard_path"])


if __name__ == "__main__":
    path = build_dashboard()
    print(f"Dashboard written to: {path}")
