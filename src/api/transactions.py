"""POST /transaction — submit a transaction for fraud evaluation."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from src.api.schemas import TransactionRequest, TransactionResponse
from src.models.transaction import Transaction
from src.decision.pipeline import process_transaction

router = APIRouter(tags=["transactions"])


@router.post("/transaction", response_model=TransactionResponse, status_code=200)
def submit_transaction(req: TransactionRequest):
    try:
        txn = Transaction(
            user_id=req.user_id,
            session_token=req.session_token,
            amount=req.amount,
            currency=req.currency,
            beneficiary_account=req.beneficiary_account,
            beneficiary_new=req.beneficiary_new,
            device_id=req.device_id,
        )
        result = process_transaction(txn)
        return TransactionResponse(
            decision_id=result["decision_id"],
            transaction_id=result["transaction_id"],
            decision=result["decision"],
            confidence=result["model_score"],
            triggered_rules=result["triggered_rules"],
            enrichment_status=result["enrichment_status"],
            fallback=result["fallback"],
            latency_ms=result["latency_ms"],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Transaction processing failed: {e}")
