"""POST /login-event, POST /crypto-telemetry — ingest Silo A data."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, status
from src.api.schemas import LoginEventRequest, CryptoTelemetryRequest
from src.models.network_log import LoginEvent
from src.models.crypto import CryptoTelemetry
from src.dbs import silo_a

router = APIRouter(tags=["telemetry"])


@router.post("/login-event", status_code=status.HTTP_201_CREATED)
def ingest_login_event(req: LoginEventRequest):
    try:
        ev = LoginEvent(
            user_id=req.user_id, session_token=req.session_token, device_id=req.device_id,
            device_first_seen=req.device_first_seen, ip_address=req.ip_address,
            ip_country=req.ip_country, ip_asn=req.ip_asn, is_vpn=req.is_vpn, is_proxy=req.is_proxy,
            user_agent=req.user_agent, auth_method=req.auth_method,
            credential_compromised=req.credential_compromised, mfa_success=req.mfa_success,
            risk_flags=req.risk_flags,
        )
        silo_a.insert_login_event(ev.to_dict())
        return {"event_id": ev.event_id, "status": "created"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest login event: {e}")


@router.post("/crypto-telemetry", status_code=status.HTTP_201_CREATED)
def ingest_crypto_telemetry(req: CryptoTelemetryRequest):
    try:
        ev = CryptoTelemetry(
            user_id=req.user_id, session_token=req.session_token, server_name=req.server_name,
            tls_version=req.tls_version, cipher_suite=req.cipher_suite, key_exchange=req.key_exchange,
            key_size_bits=req.key_size_bits, certificate_issuer=req.certificate_issuer,
            certificate_age_days=req.certificate_age_days,
            certificate_self_signed=req.certificate_self_signed, ocsp_stapled=req.ocsp_stapled,
            data_egress_bytes=req.data_egress_bytes,
            is_historical_baseline_violation=req.is_historical_baseline_violation,
        )
        silo_a.insert_crypto_telemetry(ev.to_dict())
        return {"event_id": ev.event_id, "status": "created"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest crypto telemetry: {e}")
