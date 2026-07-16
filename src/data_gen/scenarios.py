"""The 8 test scenarios from README section 9, each returning:
(login_event_dict | None, crypto_telemetry_dict | None, transaction_kwargs, expected_decision, expected_rules)

Each scenario is self-contained: it seeds its own login/crypto events into
Silo A (with a fresh user_id so scenarios don't interfere with each other),
then returns the transaction to submit.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from src.models.network_log import LoginEvent
from src.models.crypto import CryptoTelemetry
from src.dbs import silo_a, device_cache

NOW = lambda: datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


def scenario_1_normal_user():
    """Known device, home IP, small transfer to known beneficiary. Expect APPROVE (~0.1)."""
    uid, dev = "usr_s1_normal", "dev_s1_trusted"
    login = LoginEvent(
        user_id=uid, session_token="sess_s1", device_id=dev,
        ip_address="49.36.10.5", ip_country="India", device_first_seen=False,
        auth_method="biometric", credential_compromised=False, mfa_success=True,
        timestamp=_iso(NOW() - timedelta(seconds=120)),
    )
    device_cache.set_device(dev, {"device_id": dev, "first_seen": "2024-01-01", "last_seen": "2026-07-14",
                                   "associated_users": [uid], "known_locations": ["India"],
                                   "trust_score": 0.95, "flags": []})
    txn_kwargs = dict(user_id=uid, session_token="sess_s1", amount=500.0,
                       beneficiary_account="acc_known_1", beneficiary_new=False, device_id=dev)
    return login, None, txn_kwargs, "approve", []


def scenario_2_compromised_account():
    """Unrecognized device in Russia, stolen password, new beneficiary. Expect BLOCK (~0.94)."""
    uid, dev = "usr_s2_compromised", "dev_s2_unknown"
    login = LoginEvent(
        user_id=uid, session_token="sess_s2", device_id=dev,
        ip_address="185.220.101.1", ip_country="Russia", device_first_seen=True,
        auth_method="password", credential_compromised=True, mfa_success=False,
        is_vpn=False, risk_flags=["new_device", "geo_anomaly", "known_breach"],
        timestamp=_iso(NOW() - timedelta(seconds=40)),
    )
    txn_kwargs = dict(user_id=uid, session_token="sess_s2", amount=5000.0,
                       beneficiary_account="acc_new_7890", beneficiary_new=True, device_id=dev)
    return login, None, txn_kwargs, "block", ["R-001", "R-002"]


def scenario_3_hndl_attack():
    """TLS downgraded, RSA key exchange, 250MB egress, self-signed cert. Expect BLOCK (~0.95)."""
    uid, dev = "usr_s3_hndl", "dev_s3_unknown"
    login = LoginEvent(
        user_id=uid, session_token="sess_s3", device_id=dev,
        ip_address="103.21.244.10", ip_country="India", device_first_seen=True,
        auth_method="password", credential_compromised=False, mfa_success=True,
        timestamp=_iso(NOW() - timedelta(seconds=200)),
    )
    crypto = CryptoTelemetry(
        user_id=uid, session_token="sess_s3", server_name="bank-api.example.com",
        tls_version="TLSv1.1", cipher_suite="TLS_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange="RSA", key_size_bits=2048, certificate_self_signed=True,
        certificate_age_days=3, data_egress_bytes=250_000_000,
        is_historical_baseline_violation=True,
        timestamp=_iso(NOW() - timedelta(seconds=25)),
    )
    txn_kwargs = dict(user_id=uid, session_token="sess_s3", amount=5000.0,
                       beneficiary_account="acc_new_hndl", beneficiary_new=True, device_id=dev)
    return login, crypto, txn_kwargs, "block", ["R-HNDL-1", "R-HNDL-2", "R-HNDL-4"]


def scenario_4_legit_large_payment():
    """Known device, home IP, biometric login, $15K to new beneficiary (car payment). Expect APPROVE (~0.35)."""
    uid, dev = "usr_s4_legit", "dev_s4_trusted"
    login = LoginEvent(
        user_id=uid, session_token="sess_s4", device_id=dev,
        ip_address="49.36.10.9", ip_country="India", device_first_seen=False,
        auth_method="biometric", credential_compromised=False, mfa_success=True,
        timestamp=_iso(NOW() - timedelta(seconds=90)),
    )
    device_cache.set_device(dev, {"device_id": dev, "first_seen": "2023-05-01", "last_seen": "2026-07-14",
                                   "associated_users": [uid], "known_locations": ["India"],
                                   "trust_score": 0.9, "flags": []})
    # Seed some transaction history so amount > avg*3 triggers R-004 (weak, alone not enough)
    txn_kwargs = dict(user_id=uid, session_token="sess_s4", amount=15000.0,
                       beneficiary_account="acc_car_dealer", beneficiary_new=True, device_id=dev,
                       _seed_avg_history=3000.0)
    # R-004 delta reduced to 0.35 (weak signal alone) so this correctly stays below FLAG threshold
    return login, None, txn_kwargs, "approve", ["R-004"]


def scenario_5_bruteforce_then_transfer():
    """3 failed logins (different devices), then transfer. Expect BLOCK (~0.85)."""
    uid = "usr_s5_bruteforce"
    devs = ["dev_s5_a", "dev_s5_b", "dev_s5_c"]
    base = NOW() - timedelta(seconds=250)
    logins = []
    for i, d in enumerate(devs):
        logins.append(LoginEvent(
            user_id=uid, session_token=f"sess_s5_fail{i}", device_id=d,
            ip_address="45.155.205.1", ip_country="Nigeria", device_first_seen=True,
            auth_method="password", credential_compromised=True, mfa_success=False,
            risk_flags=["new_device", "geo_anomaly"],
            timestamp=_iso(base + timedelta(seconds=i * 30)),
        ))
    final_dev = devs[-1]
    txn_kwargs = dict(user_id=uid, session_token=f"sess_s5_fail2", amount=2500.0,
                       beneficiary_account="acc_new_bf", beneficiary_new=True, device_id=final_dev)
    return logins, None, txn_kwargs, "block", ["R-001", "R-002", "R-005"]


def scenario_6_vpn_user():
    """VPN detected, geo mismatch, but known device. Expect FLAG (~0.55)."""
    uid, dev = "usr_s6_vpn", "dev_s6_known"
    login = LoginEvent(
        user_id=uid, session_token="sess_s6", device_id=dev,
        ip_address="102.129.145.2", ip_country="Netherlands", device_first_seen=False,
        auth_method="password", credential_compromised=False, mfa_success=False,
        is_vpn=True, risk_flags=["vpn_detected", "geo_anomaly"],
        timestamp=_iso(NOW() - timedelta(seconds=100)),
    )
    device_cache.set_device(dev, {"device_id": dev, "first_seen": "2024-06-01", "last_seen": "2026-07-14",
                                   "associated_users": [uid], "known_locations": ["India", "Netherlands"],
                                   "trust_score": 0.6, "flags": []})
    txn_kwargs = dict(user_id=uid, session_token="sess_s6", amount=1500.0,
                       beneficiary_account="acc_known_vpn", beneficiary_new=False, device_id=dev)
    return login, None, txn_kwargs, "flag", ["R-005", "R-007"]


def scenario_7_cipher_scanning():
    """5 different cipher suites in 60 seconds. Small transfer. Expect FLAG (~0.70)."""
    uid, dev = "usr_s7_cipher", "dev_s7_known"
    login = LoginEvent(
        user_id=uid, session_token="sess_s7", device_id=dev,
        ip_address="49.36.10.20", ip_country="India", device_first_seen=False,
        auth_method="biometric", credential_compromised=False, mfa_success=True,
        timestamp=_iso(NOW() - timedelta(seconds=100)),
    )
    device_cache.set_device(dev, {"device_id": dev, "first_seen": "2024-01-01", "last_seen": "2026-07-14",
                                   "associated_users": [uid], "known_locations": ["India"],
                                   "trust_score": 0.9, "flags": []})
    ciphers = [
        "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
    ]
    base = NOW() - timedelta(seconds=45)
    cryptos = []
    for i, c in enumerate(ciphers):
        cryptos.append(CryptoTelemetry(
            user_id=uid, session_token="sess_s7", server_name="bank-api.example.com",
            tls_version="TLSv1.3", cipher_suite=c, key_exchange="ECDHE",
            data_egress_bytes=1_000_000,
            timestamp=_iso(base + timedelta(seconds=i * 8)),
        ))
    txn_kwargs = dict(user_id=uid, session_token="sess_s7", amount=300.0,
                       beneficiary_account="acc_known_cipher", beneficiary_new=False, device_id=dev)
    return login, cryptos, txn_kwargs, "flag", ["R-HNDL-5"]


def scenario_8_correlator_unavailable():
    """Silo A has no data for this user at all -> no_data / fallback. Expect APPROVE with warning."""
    uid, dev = "usr_s8_nodata", "dev_s8_unseen"
    txn_kwargs = dict(user_id=uid, session_token="sess_s8", amount=800.0,
                       beneficiary_account="acc_new_s8", beneficiary_new=False, device_id=dev)
    return None, None, txn_kwargs, "approve", ["R-006"]


ALL_SCENARIOS = [
    ("Scenario 1: Normal user", scenario_1_normal_user),
    ("Scenario 2: Compromised account", scenario_2_compromised_account),
    ("Scenario 3: HNDL attack", scenario_3_hndl_attack),
    ("Scenario 4: Legitimate large payment", scenario_4_legit_large_payment),
    ("Scenario 5: Brute-force + transfer", scenario_5_bruteforce_then_transfer),
    ("Scenario 6: VPN user", scenario_6_vpn_user),
    ("Scenario 7: Cipher scanning", scenario_7_cipher_scanning),
    ("Scenario 8: Correlator unavailable / no data", scenario_8_correlator_unavailable),
]
