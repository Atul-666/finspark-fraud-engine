"""Silo A models: LoginEvent and DeviceReputation."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from .transaction import now_iso, new_id


class AuthMethod(str, Enum):
    PASSWORD = "password"
    BIOMETRIC = "biometric"
    OAUTH = "oauth"
    MFA = "mfa"
    API_KEY = "api_key"


class RiskFlag(str, Enum):
    NEW_DEVICE = "new_device"
    GEO_ANOMALY = "geo_anomaly"
    KNOWN_BREACH = "known_breach"
    VPN_DETECTED = "vpn_detected"
    UNUSUAL_HOUR = "unusual_hour"
    MULTIPLE_ACCOUNTS = "multiple_accounts"


@dataclass
class LoginEvent:
    user_id: str
    session_token: str
    device_id: str
    ip_address: str
    ip_country: str
    auth_method: str = AuthMethod.PASSWORD.value
    event_type: str = "login"
    device_first_seen: bool = False
    ip_asn: str = ""
    is_vpn: bool = False
    is_proxy: bool = False
    user_agent: str = ""
    credential_compromised: bool = False
    mfa_success: bool = True
    risk_flags: list[str] = field(default_factory=list)
    event_id: str = field(default_factory=lambda: new_id("evt"))
    timestamp: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "user_id": self.user_id,
            "session_token": self.session_token,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "device_first_seen": self.device_first_seen,
            "ip_address": self.ip_address,
            "ip_country": self.ip_country,
            "ip_asn": self.ip_asn,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "user_agent": self.user_agent,
            "auth_method": self.auth_method,
            "credential_compromised": self.credential_compromised,
            "mfa_success": self.mfa_success,
            "risk_flags": self.risk_flags,
        }


@dataclass
class DeviceReputation:
    device_id: str
    first_seen: str
    last_seen: str
    associated_users: list[str] = field(default_factory=list)
    known_locations: list[str] = field(default_factory=list)
    trust_score: float = 0.5
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "associated_users": self.associated_users,
            "known_locations": self.known_locations,
            "trust_score": self.trust_score,
            "flags": self.flags,
        }
