"""Pydantic schemas for API request/response validation — matches README section 12 exactly."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional


class TransactionRequest(BaseModel):
    user_id: str
    session_token: str
    amount: float = Field(gt=0)
    currency: str = "USD"
    beneficiary_account: str
    beneficiary_new: bool = False
    device_id: str


class TransactionResponse(BaseModel):
    decision_id: str
    transaction_id: str
    decision: str
    confidence: float
    triggered_rules: list[str]
    enrichment_status: str
    fallback: bool
    latency_ms: float


class LoginEventRequest(BaseModel):
    user_id: str
    session_token: str
    device_id: str
    device_first_seen: bool = False
    ip_address: str
    ip_country: str
    ip_asn: str = ""
    is_vpn: bool = False
    is_proxy: bool = False
    user_agent: str = ""
    auth_method: str = "password"
    credential_compromised: bool = False
    mfa_success: bool = True
    risk_flags: list[str] = []


class CryptoTelemetryRequest(BaseModel):
    user_id: str
    session_token: str
    server_name: str
    tls_version: str
    cipher_suite: str
    key_exchange: str
    key_size_bits: int = 2048
    certificate_issuer: str = ""
    certificate_age_days: int = 0
    certificate_self_signed: bool = False
    ocsp_stapled: bool = True
    data_egress_bytes: int = 0
    is_historical_baseline_violation: bool = False


class AuditEntry(BaseModel):
    timestamp: str
    decision_id: str
    transaction_id: str
    user_id: str
    decision: str
    model_score: float
    triggered_rules: list[str]
    enrichment_status: str
    fallback: bool
    latency_ms: float


class AuditResponse(BaseModel):
    entries: list[AuditEntry]
    total: int


class HealthResponse(BaseModel):
    status: str
    services: dict[str, str]


class StatsResponse(BaseModel):
    total_decisions: int
    blocked: int
    flagged: int
    approved: int
    fallback_rate: float
    avg_latency_ms: float
    top_rules: list[str]
