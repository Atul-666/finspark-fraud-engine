"""Silo B models: Transaction (input) and FraudDecision (output)."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class Decision(str, Enum):
    APPROVE = "approve"
    BLOCK = "block"
    FLAG = "flag"
    STEP_UP = "step_up"


class EnrichmentStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    NO_DATA = "no_data"
    TOKEN_MISMATCH = "token_mismatch"
    NOT_ATTEMPTED = "not_attempted"
    CIRCUIT_OPEN = "circuit_open"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class Transaction:
    user_id: str
    session_token: str
    amount: float
    beneficiary_account: str
    device_id: str
    beneficiary_new: bool = False
    currency: str = "USD"
    transaction_id: str = field(default_factory=lambda: new_id("txn"))
    timestamp: str = field(default_factory=now_iso)
    fraud_decision: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "user_id": self.user_id,
            "session_token": self.session_token,
            "amount": self.amount,
            "currency": self.currency,
            "beneficiary_account": self.beneficiary_account,
            "beneficiary_new": self.beneficiary_new,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "fraud_decision": self.fraud_decision,
        }


@dataclass
class FraudDecision:
    transaction_id: str
    model_score: float
    threshold: float
    decision: str
    enrichment_status: str
    triggered_rules: list[str]
    fallback: bool = False
    model_version: str = "rules-v1.0"
    latency_ms: float = 0.0
    decision_id: str = field(default_factory=lambda: new_id("dec"))
    timestamp: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "transaction_id": self.transaction_id,
            "model_score": round(self.model_score, 4),
            "threshold": self.threshold,
            "decision": self.decision,
            "enrichment_status": self.enrichment_status,
            "fallback": self.fallback,
            "model_version": self.model_version,
            "latency_ms": round(self.latency_ms, 2),
            "timestamp": self.timestamp,
            "triggered_rules": self.triggered_rules,
        }
