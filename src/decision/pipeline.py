"""Decision Engine — the orchestration described in README section 8.

1. Receive transaction
2. Call Correlator -> ephemeral enriched vector
3. Run Rules Engine
4. Store transaction + fraud_decision in Silo B
5. Write audit log entry (decision metadata only)
6. DISCARD the enriched vector (never returned to caller, never persisted)
"""
from __future__ import annotations
import time

from src.dbs import silo_b
from src.correlator.service import correlate
from src.decision.engine import build_flat_context, evaluate, score_to_decision
from src.models.transaction import Transaction, FraudDecision
from src.audit import logger
from src import config


def process_transaction(txn: Transaction, user_home_country: str = "India") -> dict:
    t0 = time.perf_counter()

    # Step 1: persist the transaction itself first (pre-decision state)
    silo_b.insert_transaction(txn.to_dict())

    # Step 2: correlate with Silo A (ephemeral)
    enriched = correlate(
        user_id=txn.user_id,
        session_token=txn.session_token,
        device_id=txn.device_id,
        user_home_country=user_home_country,
    )

    # Step 3: rules engine
    user_avg = silo_b.user_avg_transaction(txn.user_id, exclude_txn_id=txn.transaction_id)
    ctx = build_flat_context(txn.to_dict(), enriched, user_avg)
    score, triggered_rules = evaluate(ctx)
    decision = score_to_decision(score)

    latency_ms = (time.perf_counter() - t0) * 1000

    fd = FraudDecision(
        transaction_id=txn.transaction_id,
        model_score=score,
        threshold=config.BLOCK_THRESHOLD,
        decision=decision,
        enrichment_status=enriched["enrichment_status"],
        triggered_rules=triggered_rules,
        fallback=enriched["fallback_used"],
        latency_ms=latency_ms,
    )

    # Step 4: store decision + update transaction, Step 5: audit
    silo_b.insert_fraud_decision(fd.to_dict())
    silo_b.update_transaction_decision(txn.transaction_id, decision)
    try:
        logger.log_decision({
            "timestamp": fd.timestamp,
            "decision_id": fd.decision_id,
            "transaction_id": txn.transaction_id,
            "user_id": txn.user_id,
            "decision": decision,
            "model_score": round(score, 4),
            "triggered_rules": triggered_rules,
            "enrichment_status": enriched["enrichment_status"],
            "fallback": enriched["fallback_used"],
            "latency_ms": round(latency_ms, 2),
        })
    except Exception:
        # Best-effort secondary log only — /audit now reads from SQLite
        # (via recent_decisions_with_user), so a failure here must never
        # take down the request after the authoritative DB write succeeded.
        pass

    # Step 6: ephemeral `enriched` vector goes out of scope here — discarded.
    return fd.to_dict()
