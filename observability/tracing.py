"""One JSON line per model call: who asked, which model, how long, how many tokens, did it work.

Prompt and answer text are NOT logged (they contain server names and scan output);
only their sizes are. Logs live in observability/logs/llm_calls.jsonl.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pandas as pd

import settings

LOG_FILE = settings.LOG_DIR / "llm_calls.jsonl"


def record(event: dict[str, Any]) -> None:
    settings.LOG_DIR.mkdir(parents=True, exist_ok=True)
    event = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), **event}
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")


def recent(limit: int = 200) -> pd.DataFrame:
    if not LOG_FILE.exists():
        return pd.DataFrame()
    with LOG_FILE.open(encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return pd.DataFrame(rows).iloc[::-1].reset_index(drop=True)
