"""GET /audit, /health, /stats — observability endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Query
from src.api.schemas import AuditResponse, HealthResponse, StatsResponse
from src.audit import logger
from src.dbs import silo_a, silo_b, device_cache
from src.dbs.silo_b import DB_PATH as SILO_B_PATH
from src.dbs.silo_a import DB_PATH as SILO_A_PATH

router = APIRouter(tags=["admin"])


@router.get("/audit", response_model=AuditResponse)
def get_audit(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
              decision: str | None = None):
    # Reads from SQLite (same source as /stats) rather than the JSONL audit
    # file, so the two endpoints can never disagree with each other.
    rows = silo_b.recent_decisions_with_user(limit=limit + offset, decision_filter=decision)
    entries = rows[offset:offset + limit]
    return AuditResponse(entries=entries, total=len(entries))


@router.get("/health", response_model=HealthResponse)
def health():
    services = {}
    services["silo_a"] = "connected" if SILO_A_PATH.exists() else "not_initialized"
    services["silo_b"] = "connected" if SILO_B_PATH.exists() else "not_initialized"
    services["device_cache"] = "connected"  # in-memory, always available in this prototype
    all_ok = all(v in ("connected",) for v in services.values())
    return HealthResponse(status="ok" if all_ok else "degraded", services=services)


@router.get("/stats", response_model=StatsResponse)
def stats():
    s = silo_b.stats_summary()
    decisions = silo_b.recent_decisions(limit=1000)
    rule_counts: dict[str, int] = {}
    for d in decisions:
        for r in d["triggered_rules"]:
            rule_counts[r] = rule_counts.get(r, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
    top_rules_fmt = [f"{r}: {c}" for r, c in top_rules]

    return StatsResponse(
        total_decisions=s["total_decisions"],
        blocked=s["blocked"],
        flagged=s["flagged"],
        approved=s["approved"],
        fallback_rate=s["fallback_rate"],
        avg_latency_ms=s["avg_latency_ms"],
        top_rules=top_rules_fmt,
    )
