from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from dateutil import parser


def parse_timestamp(value: str) -> datetime:
    return parser.parse(value)


def new_event_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def ensure_directory(path: str | Path) -> Path:
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory
