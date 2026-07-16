"""Rule evaluator: runs all rules against the flattened context, sums deltas,
applies the fallback-mode penalty table, and returns (score, triggered_rules)."""
from __future__ import annotations
from src.decision.rules import ALL_RULES
from src import config

# Extra additive penalty for token mismatch specifically (README section 8,
# Fallback Modes table) — distinct from the general R-006 enrichment penalty.
TOKEN_MISMATCH_PENALTY = 0.25


def build_flat_context(transaction: dict, enriched: dict, user_avg_transaction: float) -> dict:
    """Merge transaction + enriched network/crypto fields into one flat dict
    for rule evaluation."""
    ctx = {
        "amount": transaction["amount"],
        "beneficiary_new": transaction["beneficiary_new"],
        "user_avg_transaction": user_avg_transaction,
        "enrichment_status": enriched["enrichment_status"],
    }
    ctx.update(enriched["network_context"]["fields"])
    ctx.update(enriched["crypto_context"]["fields"])
    return ctx


def evaluate(ctx: dict) -> tuple[float, list[str]]:
    score = 0.0
    triggered: list[str] = []
    for rule in ALL_RULES:
        try:
            if rule.condition(ctx):
                score += rule.delta_score
                triggered.append(rule.id)
        except Exception:
            # A single malformed rule shouldn't crash the whole decision;
            # skip it and keep evaluating the rest.
            continue

    if ctx.get("enrichment_status") == "token_mismatch":
        score += TOKEN_MISMATCH_PENALTY
        if "R-TOKEN-MISMATCH" not in triggered:
            triggered.append("R-TOKEN-MISMATCH")

    score = min(score, 1.0)
    return score, triggered


def score_to_decision(score: float) -> str:
    if score >= config.BLOCK_THRESHOLD:
        return "block"
    if score >= config.FLAG_THRESHOLD:
        return "flag"
    return "approve"
