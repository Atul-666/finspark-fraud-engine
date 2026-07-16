"""Seeds Silo A with each scenario's login/crypto events, submits the matching
transaction through the full Decision Engine pipeline, and checks the result
against the expected decision from README section 9.

Run: python -m src.data_gen.generate
"""
from __future__ import annotations
from src.dbs import silo_a, silo_b
from src.models.transaction import Transaction
from src.decision.pipeline import process_transaction
from src.data_gen.scenarios import ALL_SCENARIOS


def seed_and_run(name: str, scenario_fn) -> dict:
    login, crypto, txn_kwargs, expected_decision, expected_rules = scenario_fn()

    # Seed login event(s) — can be a single LoginEvent or a list (scenario 5)
    if login is not None:
        logins = login if isinstance(login, list) else [login]
        for le in logins:
            silo_a.insert_login_event(le.to_dict())

    # Seed crypto telemetry — single or list (scenario 7)
    if crypto is not None:
        cryptos = crypto if isinstance(crypto, list) else [crypto]
        for ce in cryptos:
            silo_a.insert_crypto_telemetry(ce.to_dict())

    # Optional: pre-seed transaction history so user_avg_transaction is meaningful
    seed_avg = txn_kwargs.pop("_seed_avg_history", None)
    if seed_avg:
        for i in range(3):
            hist_txn = Transaction(
                user_id=txn_kwargs["user_id"], session_token="sess_hist",
                amount=seed_avg, beneficiary_account="acc_hist", device_id=txn_kwargs["device_id"],
                beneficiary_new=False,
            )
            silo_b.insert_transaction(hist_txn.to_dict())

    txn = Transaction(**txn_kwargs)
    result = process_transaction(txn)

    passed = result["decision"] == expected_decision
    return {
        "scenario": name,
        "expected_decision": expected_decision,
        "actual_decision": result["decision"],
        "score": result["model_score"],
        "expected_rules": expected_rules,
        "triggered_rules": result["triggered_rules"],
        "passed": passed,
        "latency_ms": result["latency_ms"],
        "enrichment_status": result["enrichment_status"],
    }


def main():
    silo_a.init_db()
    silo_b.init_db()

    print(f"{'Scenario':<45} {'Expected':<9} {'Actual':<9} {'Score':<7} {'Rules Triggered':<40} {'Pass'}")
    print("-" * 130)
    results = []
    for name, fn in ALL_SCENARIOS:
        r = seed_and_run(name, fn)
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        rules_str = ",".join(r["triggered_rules"]) or "-"
        print(f"{name:<45} {r['expected_decision']:<9} {r['actual_decision']:<9} "
              f"{r['score']:<7.2f} {rules_str:<40} {status}")

    n_pass = sum(1 for r in results if r["passed"])
    print("-" * 130)
    print(f"{n_pass}/{len(results)} scenarios passed")
    return results


if __name__ == "__main__":
    main()
