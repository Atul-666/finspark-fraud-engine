"""Settings. In .env.example form for later; hardcoded defaults for the prototype."""
import os

LOGIN_LOOKBACK_SECONDS = int(os.getenv("LOGIN_LOOKBACK_SECONDS", 300))
CRYPTO_LOOKBACK_SECONDS = int(os.getenv("CRYPTO_LOOKBACK_SECONDS", 900))
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", 0.80))
FLAG_THRESHOLD = float(os.getenv("FLAG_THRESHOLD", 0.50))
CORRELATOR_TIMEOUT_MS = int(os.getenv("CORRELATOR_TIMEOUT_MS", 50))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl")
