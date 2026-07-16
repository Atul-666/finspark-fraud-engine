"""Silo A — IT & Network Security data store.
Owned conceptually by Infosec. Only login_events + crypto_telemetry live here.
The Correlator Service is the only thing allowed to read this file.
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "silo_a.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS login_events (
    event_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    event_type TEXT,
    timestamp TEXT NOT NULL,
    device_id TEXT,
    device_first_seen INTEGER,
    ip_address TEXT,
    ip_country TEXT,
    ip_asn TEXT,
    is_vpn INTEGER,
    is_proxy INTEGER,
    user_agent TEXT,
    auth_method TEXT,
    credential_compromised INTEGER,
    mfa_success INTEGER,
    risk_flags TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_user_ts ON login_events(user_id, timestamp);

CREATE TABLE IF NOT EXISTS crypto_telemetry (
    event_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    server_name TEXT,
    tls_version TEXT,
    cipher_suite TEXT,
    key_exchange TEXT,
    key_size_bits INTEGER,
    certificate_issuer TEXT,
    certificate_age_days INTEGER,
    certificate_self_signed INTEGER,
    ocsp_stapled INTEGER,
    data_egress_bytes INTEGER,
    is_historical_baseline_violation INTEGER,
    hndl_risk_score REAL
);
CREATE INDEX IF NOT EXISTS idx_crypto_user_ts ON crypto_telemetry(user_id, timestamp);
"""


def get_conn(read_only: bool = False) -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if read_only and DB_PATH.exists():
        uri = f"file:{DB_PATH}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn(read_only=False)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def insert_login_event(ev: dict):
    conn = get_conn(read_only=False)
    conn.execute(
        """INSERT INTO login_events
        (event_id,user_id,session_token,event_type,timestamp,device_id,device_first_seen,
         ip_address,ip_country,ip_asn,is_vpn,is_proxy,user_agent,auth_method,
         credential_compromised,mfa_success,risk_flags)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ev["event_id"], ev["user_id"], ev["session_token"], ev["event_type"], ev["timestamp"],
            ev["device_id"], int(ev["device_first_seen"]), ev["ip_address"], ev["ip_country"],
            ev["ip_asn"], int(ev["is_vpn"]), int(ev["is_proxy"]), ev["user_agent"],
            ev["auth_method"], int(ev["credential_compromised"]), int(ev["mfa_success"]),
            json.dumps(ev["risk_flags"]),
        ),
    )
    conn.commit()
    conn.close()


def insert_crypto_telemetry(ev: dict):
    conn = get_conn(read_only=False)
    conn.execute(
        """INSERT INTO crypto_telemetry
        (event_id,user_id,session_token,timestamp,server_name,tls_version,cipher_suite,
         key_exchange,key_size_bits,certificate_issuer,certificate_age_days,
         certificate_self_signed,ocsp_stapled,data_egress_bytes,
         is_historical_baseline_violation,hndl_risk_score)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ev["event_id"], ev["user_id"], ev["session_token"], ev["timestamp"], ev["server_name"],
            ev["tls_version"], ev["cipher_suite"], ev["key_exchange"], ev["key_size_bits"],
            ev["certificate_issuer"], ev["certificate_age_days"], int(ev["certificate_self_signed"]),
            int(ev["ocsp_stapled"]), ev["data_egress_bytes"], int(ev["is_historical_baseline_violation"]),
            ev["hndl_risk_score"],
        ),
    )
    conn.commit()
    conn.close()


def recent_login_events(user_id: str, since_seconds: int = 300, limit: int = 3, read_only: bool = True) -> list[dict]:
    conn = get_conn(read_only=read_only)
    rows = conn.execute(
        """SELECT * FROM login_events WHERE user_id = ?
           AND datetime(timestamp) > datetime('now', ?)
           ORDER BY timestamp DESC LIMIT ?""",
        (user_id, f"-{since_seconds} seconds", limit),
    ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["risk_flags"] = json.loads(d["risk_flags"] or "[]")
        out.append(d)
    return out


def recent_crypto_telemetry(user_id: str, since_seconds: int = 900, limit: int = 3, read_only: bool = True) -> list[dict]:
    conn = get_conn(read_only=read_only)
    rows = conn.execute(
        """SELECT * FROM crypto_telemetry WHERE user_id = ?
           AND datetime(timestamp) > datetime('now', ?)
           ORDER BY timestamp DESC LIMIT ?""",
        (user_id, f"-{since_seconds} seconds", limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def cipher_suite_changes_last_60s(user_id: str, read_only: bool = True) -> int:
    """Count distinct cipher suites seen for this user in the last 60s window (R-HNDL-5)."""
    conn = get_conn(read_only=read_only)
    rows = conn.execute(
        """SELECT DISTINCT cipher_suite FROM crypto_telemetry WHERE user_id = ?
           AND datetime(timestamp) > datetime('now', '-60 seconds')""",
        (user_id,),
    ).fetchall()
    conn.close()
    return len(rows)
