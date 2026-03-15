"""
config.py — Centralised configuration for Wi-Fi Bastion
========================================================
All settings are driven by environment variables with safe fallbacks,
so the same codebase runs in development, CI, and production without
any code changes — just set the appropriate env vars.

Usage:
    export MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net/"
    export DEBUG_MODE=false
    export CORS_ORIGINS="https://app.example.com,https://admin.example.com"
"""

from __future__ import annotations

import os
from typing import Final


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(key: str, default: str) -> str:
    """Return stripped env var or default."""
    return os.getenv(key, default).strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes")


def _env_list(key: str, default: str) -> list[str]:
    raw = os.getenv(key, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

MONGO_URI:        Final[str] = _env("MONGO_URI",        "mongodb://localhost:27017/")
MONGO_DB:         Final[str] = _env("MONGO_DB",         "wifi_bastion")
MONGO_COLLECTION: Final[str] = _env("MONGO_COLLECTION", "wifi_scans")

# Connection pool — tune for your deployment
MONGO_POOL_SIZE:    Final[int] = _env_int("MONGO_POOL_SIZE",    10)
MONGO_TIMEOUT_MS:   Final[int] = _env_int("MONGO_TIMEOUT_MS",  3000)   # 3 s connect timeout

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

DEBUG_MODE:     Final[bool] = _env_bool("DEBUG_MODE", True)
PORT:           Final[int]  = _env_int("PORT",        5000)
APP_VERSION:    Final[str]  = _env("APP_VERSION",     "1.0.0")

# How long to wait for the OS WiFi scan to settle before reading results
SCAN_WAIT_TIME: Final[int]  = _env_int("SCAN_WAIT_TIME", 3)   # seconds

# Directory where generated PDF reports are saved
REPORT_OUTPUT_DIR: Final[str] = _env("REPORT_OUTPUT_DIR", "/tmp/wifi_bastion_reports")

# Network interface used for monitor-mode packet capture
MONITOR_INTERFACE: Final[str] = _env("MONITOR_INTERFACE", "Wi-Fi")

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

ALLOWED_ORIGINS: Final[list[str]] = _env_list(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)

# Keep the old name as an alias so existing imports don't break
CORS_ORIGINS = ALLOWED_ORIGINS

# ---------------------------------------------------------------------------
# Rate limiting  (requests per minute per IP, 0 = disabled)
# ---------------------------------------------------------------------------

RATE_LIMIT_PER_MINUTE: Final[int] = _env_int("RATE_LIMIT_PER_MINUTE", 60)

# ---------------------------------------------------------------------------
# Threat Detection
# ---------------------------------------------------------------------------

# Encryption types considered dangerously weak
WEAK_ENCRYPTION_TYPES: Final[list[str]] = _env_list(
    "WEAK_ENCRYPTION_TYPES",
    "Open (No Encryption),WPA",
)

# Absolute dBm difference between two readings of the same BSSID that
# triggers a signal-anomaly (potential evil-twin / MITM) warning
SIGNAL_ANOMALY_THRESHOLD: Final[int] = _env_int("SIGNAL_ANOMALY_THRESHOLD", 30)

# Ports considered critical exposure on a gateway
CRITICAL_PORTS: Final[list[int]] = [21, 22, 23, 445, 3389, 5900]
HIGH_RISK_PORTS: Final[list[int]] = [80, 8080, 8443, 1433, 3306, 5432]

# ---------------------------------------------------------------------------
# AKM / Encryption Mapping
# ---------------------------------------------------------------------------

AKM_MAPPING: Final[dict[int, str]] = {
    0: "Open (No Encryption)",
    1: "WPA",
    2: "WPA2",
    3: "WPA3",
    4: "WPA2-PSK",
    5: "WPA3-PSK",
    6: "WPA2-Enterprise",
    7: "WPA3-Enterprise",
    8: "WPA2/WPA3-Transition",  # Mixed-mode APs increasingly common
}

# Reverse lookup: "WPA3" → 3  (useful in scanner / report logic)
AKM_REVERSE: Final[dict[str, int]] = {v: k for k, v in AKM_MAPPING.items()}

# ---------------------------------------------------------------------------
# Sanity check — warn loudly in production if unsafe defaults are active
# ---------------------------------------------------------------------------

if not DEBUG_MODE:
    import logging as _logging
    _log = _logging.getLogger("wifi_bastion.config")

    if MONGO_URI == "mongodb://localhost:27017/":
        _log.warning(
            "MONGO_URI is still the default localhost value — "
            "set the MONGO_URI environment variable in production."
        )
    if "*" in ALLOWED_ORIGINS or not ALLOWED_ORIGINS:
        _log.warning(
            "CORS_ORIGINS is unrestricted — "
            "set the CORS_ORIGINS environment variable to your frontend domain."
        )