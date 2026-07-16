"""Rule definitions. Each rule: (id, condition_fn(ctx) -> bool, delta_score, note).

ctx is a flat dict merging: transaction fields + network_context.fields +
crypto_context.fields + a couple derived values (user_avg_transaction).
Rules are independent and additive per README section 7.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable


@dataclass
class Rule:
    id: str
    description: str
    delta_score: float
    condition: Callable[[dict], bool]


def _get(ctx: dict, key: str, default=None):
    return ctx.get(key, default)


def r001(ctx: dict) -> bool:
    return bool(_get(ctx, "credential_compromised", False)) and \
        _get(ctx, "seconds_since_last_login", 99999) < 300


def r002(ctx: dict) -> bool:
    return bool(_get(ctx, "geo_mismatch", False)) and bool(_get(ctx, "login_device_unrecognized", False))


def r003(ctx: dict) -> bool:
    return _get(ctx, "device_trust_score", 1.0) < 0.3 and _get(ctx, "amount", 0) > 2000


def r004(ctx: dict) -> bool:
    avg = _get(ctx, "user_avg_transaction", 0.0)
    if avg <= 0:
        return False
    return bool(_get(ctx, "beneficiary_new", False)) and _get(ctx, "amount", 0) > avg * 3


def r005(ctx: dict) -> bool:
    return (not _get(ctx, "mfa_success", True)) and _get(ctx, "auth_method") == "password" \
        and _get(ctx, "amount", 0) > 1000


def r006(ctx: dict) -> bool:
    return _get(ctx, "enrichment_status", "success") != "success"


def r007(ctx: dict) -> bool:
    return bool(_get(ctx, "is_vpn", False))


def r_hndl_1(ctx: dict) -> bool:
    return bool(_get(ctx, "is_quantum_vulnerable", False)) and bool(_get(ctx, "egress_above_baseline", False)) \
        and _get(ctx, "data_egress_mb", 0) > 50


def r_hndl_2(ctx: dict) -> bool:
    return _get(ctx, "key_exchange") in ("RSA", "DH") and bool(_get(ctx, "login_device_unrecognized", False))


def r_hndl_3(ctx: dict) -> bool:
    return _get(ctx, "cipher_suite") == "unknown" and _get(ctx, "data_egress_mb", 0) > 100


def r_hndl_4(ctx: dict) -> bool:
    return bool(_get(ctx, "certificate_self_signed", False)) and bool(_get(ctx, "egress_above_baseline", False))


def r_hndl_5(ctx: dict) -> bool:
    return _get(ctx, "cipher_suite_changes_60s", 0) >= 3


ALL_RULES: list[Rule] = [
    Rule("R-001", "Compromised credential + recent login", 0.90, r001),
    Rule("R-002", "Geo mismatch + unrecognized device", 0.85, r002),
    Rule("R-003", "Low device trust + amount > 2000", 0.75, r003),
    Rule("R-004", "New beneficiary + amount > 3x avg", 0.35, r004),
    Rule("R-005", "MFA failed + password auth + amount > 1000", 0.40, r005),
    Rule("R-006", "Enrichment not successful (fallback mode)", 0.15, r006),
    Rule("R-007", "VPN detected during login", 0.15, r007),
    Rule("R-HNDL-1", "Quantum-vulnerable crypto + egress spike", 0.90, r_hndl_1),
    Rule("R-HNDL-2", "RSA/DH key exchange + unrecognized device", 0.40, r_hndl_2),
    Rule("R-HNDL-3", "Unknown cipher + large egress", 0.85, r_hndl_3),
    Rule("R-HNDL-4", "Self-signed cert + egress spike", 0.55, r_hndl_4),
    Rule("R-HNDL-5", "Multiple cipher suite changes in 60s", 0.70, r_hndl_5),
]
