"""Append-only audit logger. Only decision metadata is persisted — never the
ephemeral network_context / crypto_context fields (privacy-by-design)."""
from __future__ import annotations
import json
import threading
from pathlib import Path
from src import config

_LOCK = threading.Lock()
LOG_PATH = Path(__file__).resolve().parents[2] / config.AUDIT_LOG_PATH


def log_decision(entry: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")


def read_entries(limit: int = 100, offset: int = 0, decision_filter: str | None = None) -> list[dict]:
    if not LOG_PATH.exists():
        return []
    lines = LOG_PATH.read_text().strip().splitlines()
    entries = [json.loads(l) for l in lines if l.strip()]
    entries.reverse()  # most recent first
    if decision_filter:
        entries = [e for e in entries if e.get("decision") == decision_filter]
    return entries[offset:offset + limit]
