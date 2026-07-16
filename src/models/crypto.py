"""Silo A model: CryptoTelemetry (TLS/HNDL detection)."""
from __future__ import annotations
from dataclasses import dataclass, field
from .transaction import now_iso, new_id

# Cipher suites broken by Shor's algorithm era quantum computers if key exchange
# relies on RSA/DH/ECDH without a PQ-hybrid handshake.
QUANTUM_VULNERABLE_KEY_EXCHANGE = {"RSA", "DH", "ECDH", "ECDHE", "unknown"}
QUANTUM_SAFE_KEY_EXCHANGE = {"PQ-HYBRID", "KYBER"}

TLS_VERSION_ORDER = ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3", "unknown"]


@dataclass
class CryptoTelemetry:
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
    event_id: str = field(default_factory=lambda: new_id("crypto"))
    timestamp: str = field(default_factory=now_iso)

    def is_quantum_vulnerable(self) -> bool:
        """True if cipher/key exchange is breakable by a sufficiently large
        quantum computer running Shor's algorithm (classic RSA/DH/EC families)."""
        return self.key_exchange in QUANTUM_VULNERABLE_KEY_EXCHANGE

    def is_downgrade_attack(self, baseline_tls: str = "TLSv1.3") -> bool:
        """True if the observed TLS version is older than the user's baseline."""
        try:
            observed_idx = TLS_VERSION_ORDER.index(self.tls_version)
            baseline_idx = TLS_VERSION_ORDER.index(baseline_tls)
        except ValueError:
            return False
        return observed_idx < baseline_idx

    @property
    def data_egress_mb(self) -> float:
        return round(self.data_egress_bytes / (1024 * 1024), 2)

    def hndl_risk_score(self) -> float:
        """Composite 0-1 score used for reporting; the rules engine recomputes
        its own weighted contributions independently, this is a summary field."""
        score = 0.0
        if self.is_quantum_vulnerable():
            score += 0.4
        if self.is_downgrade_attack():
            score += 0.2
        if self.certificate_self_signed:
            score += 0.15
        if self.data_egress_mb > 50:
            score += 0.15
        if self.is_historical_baseline_violation:
            score += 0.1
        return min(round(score, 2), 1.0)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "user_id": self.user_id,
            "session_token": self.session_token,
            "timestamp": self.timestamp,
            "server_name": self.server_name,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "key_exchange": self.key_exchange,
            "key_size_bits": self.key_size_bits,
            "certificate_issuer": self.certificate_issuer,
            "certificate_age_days": self.certificate_age_days,
            "certificate_self_signed": self.certificate_self_signed,
            "ocsp_stapled": self.ocsp_stapled,
            "data_egress_bytes": self.data_egress_bytes,
            "is_historical_baseline_violation": self.is_historical_baseline_violation,
            "hndl_risk_score": self.hndl_risk_score(),
        }
