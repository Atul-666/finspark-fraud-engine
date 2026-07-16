"""Live traffic simulator for demo purposes.

Continuously sends a realistic mix of login events, crypto telemetry, and
transactions to a RUNNING FastAPI server (must already be up on BASE_URL).

Run: python -m src.data_gen.simulator
Stop: Ctrl+C

Profile mix (weighted):
  70% normal      - known device/country, small/medium amount -> approve
  10% new_device   - unrecognized device + geo mismatch        -> block
  8%  compromised  - stolen credential + failed MFA             -> block
  7%  vpn          - VPN + failed MFA, known device             -> flag
  5%  hndl         - quantum-vulnerable crypto + big egress     -> block
"""
from __future__ import annotations
import random
import sys
import time
import uuid
from datetime import datetime

import requests

sys.path.insert(0, ".")
from src.dbs import device_cache  # noqa: E402

BASE_URL = "https://finspark-fraud-engine.onrender.com"

NORMAL_COUNTRIES = ["India", "United States", "United Kingdom", "Germany", "Singapore"]
SUSPICIOUS_COUNTRIES = ["Russia", "Nigeria", "North Korea", "Belarus"]

NORMAL_USER_POOL = [f"usr_{i:04d}" for i in range(1, 26)]

# Each user is permanently assigned to exactly one behavioral profile so a
# single account never flips between "normal" and "attacker" mid-session —
# that cross-contamination confused the correlator (recent Silo A lookups
# are keyed per user_id) and made the demo narrative harder to explain.
USER_PROFILE_MAP = {}


def _assign_profiles():
    users = NORMAL_USER_POOL[:]
    random.shuffle(users)
    n = len(users)
    n_normal = int(n * 0.70)
    n_new_device = int(n * 0.10)
    n_compromised = int(n * 0.08)
    n_vpn = int(n * 0.07)
    # remaining -> hndl
    idx = 0
    for _ in range(n_normal):
        USER_PROFILE_MAP[users[idx]] = "normal"; idx += 1
    for _ in range(n_new_device):
        USER_PROFILE_MAP[users[idx]] = "new_device"; idx += 1
    for _ in range(n_compromised):
        USER_PROFILE_MAP[users[idx]] = "compromised"; idx += 1
    for _ in range(n_vpn):
        USER_PROFILE_MAP[users[idx]] = "vpn"; idx += 1
    while idx < n:
        USER_PROFILE_MAP[users[idx]] = "hndl"; idx += 1


_assign_profiles()


def seed_trusted_users(n: int = 25):
    """Pre-register known devices with high trust so 'normal' traffic actually looks normal."""
    print(f"Seeding {n} trusted users with known devices...")
    for uid in NORMAL_USER_POOL[:n]:
        dev = f"dev_trusted_{uid}"
        device_cache.set_device(dev, {
            "device_id": dev, "first_seen": "2024-01-01", "last_seen": datetime.now().isoformat(),
            "associated_users": [uid], "known_locations": ["India"],
            "trust_score": round(random.uniform(0.75, 0.98), 2), "flags": [],
        })
    print("Done seeding.\n")


def _post(path: str, payload: dict) -> dict | None:
    try:
        resp = requests.post(f"{BASE_URL}{path}", json=payload, timeout=5)
        if resp.status_code >= 400:
            print(f"  ! {path} -> {resp.status_code}: {resp.text[:150]}")
            return None
        return resp.json()
    except requests.exceptions.ConnectionError:
        print(f"  ! Could not reach {BASE_URL} — is the API server running?")
        return None


def _fmt_result(profile: str, decision: str, score: float, rules: list[str]) -> str:
    colors = {"approve": "\033[92m", "flag": "\033[93m", "block": "\033[91m", "step_up": "\033[93m"}
    reset = "\033[0m"
    c = colors.get(decision, "")
    rules_str = ",".join(rules) if rules else "-"
    return f"  {c}[{decision.upper():<8}]{reset} profile={profile:<12} score={score:.2f}  rules={rules_str}"


def simulate_normal(uid: str):
    dev = f"dev_trusted_{uid}"
    session = f"sess_{uuid.uuid4().hex[:8]}"
    _post("/login-event", {
        "user_id": uid, "session_token": session, "device_id": dev,
        "device_first_seen": False, "ip_address": "49.36.10.5", "ip_country": "India",
        "auth_method": "biometric", "credential_compromised": False, "mfa_success": True,
    })
    amount = round(random.uniform(50, 3000), 2)
    return _post("/transaction", {
        "user_id": uid, "session_token": session, "amount": amount,
        "beneficiary_account": f"acc_known_{random.randint(1,9)}", "beneficiary_new": random.random() < 0.15,
        "device_id": dev,
    })


def simulate_new_device(uid: str):
    dev = f"dev_unknown_{uuid.uuid4().hex[:6]}"
    country = random.choice(SUSPICIOUS_COUNTRIES)
    session = f"sess_{uuid.uuid4().hex[:8]}"
    _post("/login-event", {
        "user_id": uid, "session_token": session, "device_id": dev,
        "device_first_seen": True, "ip_address": "185.220.101.1", "ip_country": country,
        "auth_method": "password", "credential_compromised": False, "mfa_success": True,
        "risk_flags": ["new_device", "geo_anomaly"],
    })
    return _post("/transaction", {
        "user_id": uid, "session_token": session, "amount": round(random.uniform(1000, 8000), 2),
        "beneficiary_account": f"acc_new_{uuid.uuid4().hex[:6]}", "beneficiary_new": True, "device_id": dev,
    })


def simulate_compromised(uid: str):
    dev = f"dev_unknown_{uuid.uuid4().hex[:6]}"
    country = random.choice(SUSPICIOUS_COUNTRIES)
    session = f"sess_{uuid.uuid4().hex[:8]}"
    _post("/login-event", {
        "user_id": uid, "session_token": session, "device_id": dev,
        "device_first_seen": True, "ip_address": "45.155.205.1", "ip_country": country,
        "auth_method": "password", "credential_compromised": True, "mfa_success": False,
        "risk_flags": ["new_device", "geo_anomaly", "known_breach"],
    })
    return _post("/transaction", {
        "user_id": uid, "session_token": session, "amount": round(random.uniform(2000, 9000), 2),
        "beneficiary_account": f"acc_new_{uuid.uuid4().hex[:6]}", "beneficiary_new": True, "device_id": dev,
    })


def simulate_vpn(uid: str):
    dev = f"dev_trusted_{uid}"  # known device, just VPN + failed MFA
    session = f"sess_{uuid.uuid4().hex[:8]}"
    _post("/login-event", {
        "user_id": uid, "session_token": session, "device_id": dev,
        "device_first_seen": False, "ip_address": "102.129.145.2", "ip_country": "Netherlands",
        "auth_method": "password", "credential_compromised": False, "mfa_success": False,
        "is_vpn": True, "risk_flags": ["vpn_detected", "geo_anomaly"],
    })
    return _post("/transaction", {
        "user_id": uid, "session_token": session, "amount": round(random.uniform(500, 2500), 2),
        "beneficiary_account": f"acc_known_{random.randint(1,9)}", "beneficiary_new": False, "device_id": dev,
    })


def simulate_hndl(uid: str):
    dev = f"dev_unknown_{uuid.uuid4().hex[:6]}"
    session = f"sess_{uuid.uuid4().hex[:8]}"
    _post("/login-event", {
        "user_id": uid, "session_token": session, "device_id": dev,
        "device_first_seen": True, "ip_address": "103.21.244.10", "ip_country": "India",
        "auth_method": "password", "credential_compromised": False, "mfa_success": True,
    })
    _post("/crypto-telemetry", {
        "user_id": uid, "session_token": session, "server_name": "bank-api.example.com",
        "tls_version": "TLSv1.1", "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256", "key_exchange": "RSA",
        "certificate_self_signed": True, "certificate_age_days": 3, "data_egress_bytes": 250_000_000,
        "is_historical_baseline_violation": True,
    })
    return _post("/transaction", {
        "user_id": uid, "session_token": session, "amount": round(random.uniform(3000, 9000), 2),
        "beneficiary_account": f"acc_new_{uuid.uuid4().hex[:6]}", "beneficiary_new": True, "device_id": dev,
    })


PROFILE_FNS = {
    "normal": simulate_normal, "new_device": simulate_new_device,
    "compromised": simulate_compromised, "vpn": simulate_vpn, "hndl": simulate_hndl,
}


def run(min_interval: float = 1.0, max_interval: float = 2.5, max_ticks: int | None = None):
    seed_trusted_users()
    print(f"Starting live simulator against {BASE_URL} — Ctrl+C to stop\n")
    tick = 0
    try:
        while True:
            if max_ticks is not None and tick >= max_ticks:
                break
            profile = None
            uid = random.choice(NORMAL_USER_POOL)
            profile = USER_PROFILE_MAP[uid]
            fn = PROFILE_FNS[profile]
            result = fn(uid)
            ts = datetime.now().strftime("%H:%M:%S")
            if result:
                print(f"[{ts}] user={uid}" + _fmt_result(profile, result["decision"],
                      result["confidence"], result["triggered_rules"]))
            tick += 1
            time.sleep(random.uniform(min_interval, max_interval))
    except KeyboardInterrupt:
        print(f"\nStopped after {tick} simulated transactions.")


if __name__ == "__main__":
    run()
