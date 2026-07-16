"""Device reputation cache.

Prototype uses an in-memory dict with the exact same get/set interface Redis
would expose (GET device:{id} -> JSON). Swapping to real Redis later means
changing only this file's internals, not any caller code.
"""
from __future__ import annotations
import json
import threading
from pathlib import Path

_LOCK = threading.Lock()
_STORE: dict[str, dict] = {}

CACHE_FILE = Path(__file__).resolve().parents[2] / "data" / "device_cache.json"


def _load():
    global _STORE
    if CACHE_FILE.exists():
        _STORE = json.loads(CACHE_FILE.read_text())


def _persist():
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(_STORE, indent=2))


def get_device(device_id: str) -> dict | None:
    with _LOCK:
        if not _STORE:
            _load()
        return _STORE.get(device_id)


def set_device(device_id: str, reputation: dict):
    with _LOCK:
        _STORE[device_id] = reputation
        _persist()


def all_devices() -> dict:
    with _LOCK:
        if not _STORE:
            _load()
        return dict(_STORE)
