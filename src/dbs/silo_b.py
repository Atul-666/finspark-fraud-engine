"""Silo B — Fraud & Transactions data store.
Owned conceptually by the Fraud team. Transactions + fraud_decisions live here.
Never contains raw network/crypto data from Silo A (that's ephemeral, discarded post-decision).
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "silo_b.sqlite"

SCHEMA = """
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_token TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT,
    beneficiary_account TEXT,
    beneficiary_new INTEGER,
    device_id TEXT,
    timestamp TEXT NOT NULL,
    fraud_decision TEXT
);
CREATE INDEX IF NOT EXISTS idx_txn_user_ts ON transactions(user_id, timestamp);

CREATE TABLE IF NOT EXISTS fraud_decisions (
    decision_id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL,
    model_score REAL,
    threshold REAL,
    decision TEXT,
    enrichment_status TEXT,
    fallback INTEGER,
    model_version TEXT,
    latency_ms REAL,
    timestamp TEXT NOT NULL,
    triggered_rules TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_txn ON fraud_decisions(transaction_id);
"""


def get_conn(read_only: bool = False) -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    if read_only and DB_PATH.exists():
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn(read_only=False)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def insert_transaction(txn: dict):
    conn = get_conn(read_only=False)
    conn.execute(
        """INSERT INTO transactions
        (transaction_id,user_id,session_token,amount,currency,beneficiary_account,
         beneficiary_new,device_id,timestamp,fraud_decision)
        VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            txn["transaction_id"], txn["user_id"], txn["session_token"], txn["amount"],
            txn["currency"], txn["beneficiary_account"], int(txn["beneficiary_new"]),
            txn["device_id"], txn["timestamp"], txn.get("fraud_decision"),
        ),
    )
    conn.commit()
    conn.close()


def update_transaction_decision(transaction_id: str, decision: str):
    conn = get_conn(read_only=False)
    conn.execute("UPDATE transactions SET fraud_decision = ? WHERE transaction_id = ?", (decision, transaction_id))
    conn.commit()
    conn.close()


def insert_fraud_decision(fd: dict):
    conn = get_conn(read_only=False)
    conn.execute(
        """INSERT INTO fraud_decisions
        (decision_id,transaction_id,model_score,threshold,decision,enrichment_status,
         fallback,model_version,latency_ms,timestamp,triggered_rules)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            fd["decision_id"], fd["transaction_id"], fd["model_score"], fd["threshold"],
            fd["decision"], fd["enrichment_status"], int(fd["fallback"]), fd["model_version"],
            fd["latency_ms"], fd["timestamp"], json.dumps(fd["triggered_rules"]),
        ),
    )
    conn.commit()
    conn.close()


def user_avg_transaction(user_id: str, exclude_txn_id: str | None = None, read_only: bool = True) -> float:
    conn = get_conn(read_only=read_only)
    if exclude_txn_id:
        row = conn.execute(
            "SELECT AVG(amount) as avg_amt FROM transactions WHERE user_id = ? AND transaction_id != ?",
            (user_id, exclude_txn_id),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT AVG(amount) as avg_amt FROM transactions WHERE user_id = ?", (user_id,)
        ).fetchone()
    conn.close()
    avg = row["avg_amt"] if row and row["avg_amt"] is not None else 0.0
    return float(avg)


def recent_decisions(limit: int = 100, decision_filter: str | None = None) -> list[dict]:
    conn = get_conn(read_only=True)
    if decision_filter:
        rows = conn.execute(
            "SELECT * FROM fraud_decisions WHERE decision = ? ORDER BY timestamp DESC LIMIT ?",
            (decision_filter, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM fraud_decisions ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["triggered_rules"] = json.loads(d["triggered_rules"] or "[]")
        out.append(d)
    return out


def recent_decisions_with_user(limit: int = 100, decision_filter: str | None = None) -> list[dict]:
    """Same as recent_decisions but JOINs transactions to include user_id.
    This is the single source of truth for the /audit endpoint — reading
    from SQLite (proven reliable) instead of a separate JSONL file that can
    silently fail to write on some hosting environments."""
    conn = get_conn(read_only=True)
    base_query = """
        SELECT fd.*, t.user_id as user_id
        FROM fraud_decisions fd
        LEFT JOIN transactions t ON fd.transaction_id = t.transaction_id
    """
    if decision_filter:
        rows = conn.execute(
            base_query + " WHERE fd.decision = ? ORDER BY fd.timestamp DESC LIMIT ?",
            (decision_filter, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            base_query + " ORDER BY fd.timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["triggered_rules"] = json.loads(d["triggered_rules"] or "[]")
        d["user_id"] = d.get("user_id") or "unknown"
        out.append(d)
    return out


def stats_summary() -> dict:
    conn = get_conn(read_only=True)
    total = conn.execute("SELECT COUNT(*) c FROM fraud_decisions").fetchone()["c"]
    by_decision = conn.execute(
        "SELECT decision, COUNT(*) c FROM fraud_decisions GROUP BY decision"
    ).fetchall()
    avg_latency = conn.execute("SELECT AVG(latency_ms) a FROM fraud_decisions").fetchone()["a"]
    fallback_count = conn.execute("SELECT COUNT(*) c FROM fraud_decisions WHERE fallback = 1").fetchone()["c"]
    conn.close()
    counts = {r["decision"]: r["c"] for r in by_decision}
    return {
        "total_decisions": total,
        "approved": counts.get("approve", 0),
        "flagged": counts.get("flag", 0),
        "blocked": counts.get("block", 0),
        "step_up": counts.get("step_up", 0),
        "fallback_rate": round(fallback_count / total, 4) if total else 0.0,
        "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0.0,
    }
