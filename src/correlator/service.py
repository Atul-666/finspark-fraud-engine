"""Correlator Service.

This is the ONLY component with read access to Silo A. It fetches network +
crypto context at decision time, builds an ephemeral enriched feature vector,
and hands it back. It holds no state between requests (stateless) and never
writes anything back to Silo A.

In the README's full architecture this runs as a separate FastAPI process
reached over HTTP. For the prototype it's called as a Python function within
the same process — the interface (input dict -> enriched vector dict) is
identical, so splitting it into a real microservice later is a drop-in change.
"""
from __future__ import annotations
import time
from datetime import datetime, timezone

from src.dbs import silo_a, device_cache
from src.models.crypto import CryptoTelemetry, QUANTUM_VULNERABLE_KEY_EXCHANGE
from src import config


def _seconds_since(ts_str: str) -> float:
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return 99999.0


def correlate(user_id: str, session_token: str, device_id: str,
              user_home_country: str = "India", baseline_tls: str = "TLSv1.3") -> dict:
    """Fetch Silo A context for a user/session/device and return the ephemeral
    enriched feature vector described in README section 6."""
    t0 = time.perf_counter()

    enrichment_status = "success"
    network_fields = {}
    crypto_fields = {}
    login_query_ms = 0.0
    crypto_query_ms = 0.0

    try:
        t_login_start = time.perf_counter()
        logins = silo_a.recent_login_events(user_id, since_seconds=config.LOGIN_LOOKBACK_SECONDS)
        login_query_ms = (time.perf_counter() - t_login_start) * 1000

        if logins:
            latest = logins[0]
            token_mismatch = latest["session_token"] != session_token
            geo_mismatch = latest["ip_country"] != user_home_country

            device_rep = device_cache.get_device(device_id) or {}
            device_trust_score = device_rep.get("trust_score", 0.1)  # unknown device = low trust

            network_fields = {
                "seconds_since_last_login": round(_seconds_since(latest["timestamp"]), 1),
                "login_device_unrecognized": bool(latest["device_first_seen"]),
                "login_device_first_seen": bool(latest["device_first_seen"]),
                "login_ip_country": latest["ip_country"],
                "user_home_country": user_home_country,
                "geo_mismatch": geo_mismatch,
                "is_vpn": bool(latest["is_vpn"]),
                "auth_method": latest["auth_method"],
                "credential_compromised": bool(latest["credential_compromised"]),
                "mfa_success": bool(latest["mfa_success"]),
                "device_trust_score": device_trust_score,
                "risk_flags": latest["risk_flags"],
            }
            if token_mismatch:
                enrichment_status = "token_mismatch"
        else:
            network_fields = {}
            enrichment_status = "no_data"

        t_crypto_start = time.perf_counter()
        cryptos = silo_a.recent_crypto_telemetry(user_id, since_seconds=config.CRYPTO_LOOKBACK_SECONDS)
        crypto_query_ms = (time.perf_counter() - t_crypto_start) * 1000

        if cryptos:
            latest_c = cryptos[0]
            is_quantum_vuln = latest_c["key_exchange"] in QUANTUM_VULNERABLE_KEY_EXCHANGE
            tls_downgraded = latest_c["tls_version"] in ("TLSv1.0", "TLSv1.1", "SSLv3")
            egress_mb = round(latest_c["data_egress_bytes"] / (1024 * 1024), 2)

            cipher_changes = silo_a.cipher_suite_changes_last_60s(user_id)

            crypto_fields = {
                "tls_version": latest_c["tls_version"],
                "tls_downgraded": tls_downgraded,
                "cipher_suite": latest_c["cipher_suite"],
                "key_exchange": latest_c["key_exchange"],
                "is_quantum_vulnerable": is_quantum_vuln,
                "certificate_self_signed": bool(latest_c["certificate_self_signed"]),
                "certificate_age_days": latest_c["certificate_age_days"],
                "data_egress_mb": egress_mb,
                "egress_above_baseline": egress_mb > 50,
                "hndl_risk_score": latest_c["hndl_risk_score"],
                "cipher_suite_changes_60s": cipher_changes,
            }
        else:
            crypto_fields = {}

    except Exception:
        enrichment_status = "error"
        network_fields = {}
        crypto_fields = {}

    elapsed_ms = (time.perf_counter() - t0) * 1000
    fallback_used = elapsed_ms > config.CORRELATOR_TIMEOUT_MS
    if fallback_used and enrichment_status == "success":
        enrichment_status = "timeout"

    return {
        "$schema": "transient-enrichment-v1",
        "network_context": {
            "source": "silo_a",
            "query_time_ms": round(login_query_ms, 2),
            "fields": network_fields,
        },
        "crypto_context": {
            "source": "silo_a",
            "query_time_ms": round(crypto_query_ms, 2),
            "fields": crypto_fields,
        },
        "enrichment_status": enrichment_status,
        "fallback_used": fallback_used,
        "correlation_latency_ms": round(elapsed_ms, 2),
    }
