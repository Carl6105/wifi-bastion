"""
auth.py — API Key Authentication & Rate Limiting
=================================================
Provides:
  - @require_api_key   decorator for protecting sensitive endpoints
  - Limiter instance   (flask-limiter) for per-IP rate limiting
  - AuditLogger        for append-only security audit trail

Setup:
    Set API_KEY in your .env file:
        API_KEY=your-secret-key-here
    
    Or generate one:
        python -c "import secrets; print(secrets.token_hex(32))"
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from functools import wraps
from http import HTTPStatus

from flask import Flask, jsonify, request, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from backend.config import RATE_LIMIT_PER_MINUTE
except ImportError:
    from config import RATE_LIMIT_PER_MINUTE          # type: ignore

logger = logging.getLogger("wifi_bastion.auth")

# ---------------------------------------------------------------------------
# API Key config
# ---------------------------------------------------------------------------

_API_KEY_HASH: str | None = None


def _load_api_key() -> None:
    """
    Load and hash the API key from the environment at startup.
    Storing only the hash means the raw key is never held in memory
    longer than this function's stack frame.
    """
    global _API_KEY_HASH
    raw = os.getenv("API_KEY", "").strip()
    if not raw:
        # Only warn once — use an env marker to suppress duplicate warnings
        # from werkzeug's reloader spawning a second process
        if not os.getenv("_BASTION_KEY_WARNED"):
            logger.warning(
                "API_KEY is not set — protected endpoints are OPEN in dev mode. "
                "Set API_KEY in your .env file before deploying."
            )
            os.environ["_BASTION_KEY_WARNED"] = "1"
        return
    _API_KEY_HASH = hashlib.sha256(raw.encode()).hexdigest()
    logger.info("API key loaded and hashed.")


_load_api_key()


def _verify_key(provided: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if not _API_KEY_HASH:
        return True     # No key configured — open mode (dev only)
    provided_hash = hashlib.sha256(provided.encode()).hexdigest()
    return hmac.compare_digest(_API_KEY_HASH, provided_hash)


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def require_api_key(f):
    """
    Protect an endpoint with API key authentication.

    - When API_KEY env var is set: enforces the key on every request.
    - When API_KEY is NOT set (dev mode): passes through without blocking.
      This allows local development without configuring a key, while
      production deployments are automatically protected.

    Clients must send:   X-API-Key: <your-key>
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Dev mode: no key configured → allow all requests through
        if _API_KEY_HASH is None:
            return f(*args, **kwargs)
        # Production mode: enforce key
        key = request.headers.get("X-API-Key", "").strip()
        if not key or not _verify_key(key):
            audit_logger.log_auth_failure(request.remote_addr, request.path)
            return (
                jsonify({"status": "error", "message": "Invalid or missing API key."}),
                HTTPStatus.UNAUTHORIZED.value,
            )
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{RATE_LIMIT_PER_MINUTE} per minute"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),   # Use Redis in production
    strategy="fixed-window",
    headers_enabled=True,     # Sends X-RateLimit-* headers to clients
)


def init_limiter(app: Flask) -> None:
    """Attach the limiter to the Flask app. Call from create_app()."""
    limiter.init_app(app)

    @app.errorhandler(429)
    def rate_limit_exceeded(exc):           # noqa: ANN001
        logger.warning(
            "Rate limit exceeded — IP=%s path=%s",
            request.remote_addr, request.path,
        )
        return (
            jsonify({
                "status":  "error",
                "message": "Too many requests. Please slow down.",
                "retry_after": getattr(exc, "retry_after", 60),
            }),
            429,
        )


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Append-only structured audit log for security-sensitive actions.

    Writes to a dedicated file (separate from the main app log) so the
    audit trail can be forwarded to a SIEM or archived independently.
    """

    AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "logs/audit.log")

    def __init__(self) -> None:
        os.makedirs(os.path.dirname(self.AUDIT_LOG_PATH), exist_ok=True)
        self._logger = logging.getLogger("wifi_bastion.audit")

        if not self._logger.handlers:
            handler = logging.FileHandler(self.AUDIT_LOG_PATH, mode="a")
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s  AUDIT  %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%SZ",
                )
            )
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False   # Don't duplicate to root logger

    def log(self, action: str, detail: str, ip: str = "") -> None:
        ip = ip or request.remote_addr
        rid = getattr(g, "request_id", "-")
        self._logger.info("action=%s ip=%s rid=%s detail=%s", action, ip, rid, detail)

    def log_auth_failure(self, ip: str, path: str) -> None:
        self.log("AUTH_FAILURE", f"path={path}", ip=ip)

    def log_deauth_sent(self, target_mac: str) -> None:
        self.log("DEAUTH_SENT", f"target={target_mac}")

    def log_network_blocked(self, ssid: str, bssid: str) -> None:
        self.log("NETWORK_BLOCKED", f"ssid={ssid} bssid={bssid}")

    def log_network_unblocked(self, ssid: str) -> None:
        self.log("NETWORK_UNBLOCKED", f"ssid={ssid}")

    def log_report_generated(self, path: str) -> None:
        self.log("REPORT_GENERATED", f"path={path}")

    def log_scan(self, network_count: int) -> None:
        self.log("SCAN_COMPLETED", f"networks={network_count}")


# Singleton — import and use anywhere
audit_logger = AuditLogger()