"""
alerts_dispatcher.py — Critical Threat Notification Dispatcher
===============================================================
Sends alerts to configured free notification channels when
CRITICAL security events are detected.

Supported channels (all free, no paid tiers required):
  1. Slack Webhook    — free incoming webhooks on any workspace
  2. Discord Webhook  — free on any Discord server
  3. Ntfy.sh          — free push notifications (no account needed)
  4. Email via Gmail  — free with app password

Configuration (set in .env):
    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
    DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
    NTFY_TOPIC=wifi-bastion-alerts     # your unique topic name
    ALERT_EMAIL=you@gmail.com
    ALERT_EMAIL_PASSWORD=xxxx-xxxx     # Gmail App Password
    ALERT_EMAIL_TO=you@gmail.com
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
import time
from email.mime.text import MIMEText
from typing import Any

try:
    import requests as _req
    _HTTP = True
except ImportError:
    _HTTP = False

logger = logging.getLogger("wifi_bastion.alerts_dispatcher")

# ---------------------------------------------------------------------------
# Rate limiting — avoid flooding on sustained attacks
# ---------------------------------------------------------------------------

_last_sent:  dict[str, float] = {}   # channel → last sent timestamp
_COOLDOWN    = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))  # 5 min default


def _throttled(channel: str) -> bool:
    """Return True if this channel is in cooldown."""
    last = _last_sent.get(channel, 0)
    if time.monotonic() - last < _COOLDOWN:
        return True
    _last_sent[channel] = time.monotonic()
    return False


# ---------------------------------------------------------------------------
# Channel implementations
# ---------------------------------------------------------------------------

def _send_slack(message: str, severity: str) -> bool:
    url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not url or not _HTTP:
        return False
    if _throttled("slack"):
        return False
    try:
        emoji = "🚨" if severity == "CRITICAL" else "⚠️"
        payload = {
            "text": f"{emoji} *Wi-Fi Bastion Alert*",
            "attachments": [{
                "color":  "#c0392b" if severity == "CRITICAL" else "#b45309",
                "fields": [{"title": "Threat", "value": message, "short": False}],
                "footer": "Wi-Fi Bastion",
                "ts":     int(time.time()),
            }],
        }
        resp = _req.post(url, json=payload, timeout=8)
        resp.raise_for_status()
        logger.info("Slack alert sent.")
        return True
    except Exception as e:
        logger.warning("Slack alert failed: %s", e)
        return False


def _send_discord(message: str, severity: str) -> bool:
    url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if not url or not _HTTP:
        return False
    if _throttled("discord"):
        return False
    try:
        colour = 0xC0392B if severity == "CRITICAL" else 0xB45309
        payload = {
            "embeds": [{
                "title":       "⚠ Wi-Fi Bastion Alert",
                "description": message,
                "color":       colour,
                "footer":      {"text": "Wi-Fi Bastion Threat Intelligence"},
                "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }]
        }
        resp = _req.post(url, json=payload, timeout=8)
        resp.raise_for_status()
        logger.info("Discord alert sent.")
        return True
    except Exception as e:
        logger.warning("Discord alert failed: %s", e)
        return False


def _send_ntfy(message: str, severity: str, alert_type: str) -> bool:
    """
    ntfy.sh — free push notifications.
    Install the ntfy app on Android/iOS and subscribe to your topic.
    No account required for basic use.
    """
    topic = os.getenv("NTFY_TOPIC", "").strip()
    if not topic or not _HTTP:
        return False
    if _throttled("ntfy"):
        return False
    try:
        priority = "urgent" if severity == "CRITICAL" else "high"
        resp = _req.post(
            f"https://ntfy.sh/{topic}",
            data=message.encode("utf-8"),
            headers={
                "Title":    f"Wi-Fi Bastion: {alert_type}",
                "Priority": priority,
                "Tags":     "warning,shield",
            },
            timeout=8,
        )
        resp.raise_for_status()
        logger.info("ntfy.sh alert sent to topic '%s'.", topic)
        return True
    except Exception as e:
        logger.warning("ntfy.sh alert failed: %s", e)
        return False


def _send_email(message: str, severity: str, alert_type: str) -> bool:
    """
    Send via Gmail SMTP with an App Password.
    Enable 2FA on your Google account, then generate an App Password at:
    myaccount.google.com/apppasswords
    """
    sender   = os.getenv("ALERT_EMAIL", "").strip()
    password = os.getenv("ALERT_EMAIL_PASSWORD", "").strip()
    to       = os.getenv("ALERT_EMAIL_TO", sender).strip()

    if not all([sender, password, to]):
        return False
    if _throttled("email"):
        return False
    try:
        subject = f"[Wi-Fi Bastion] {severity}: {alert_type}"
        body    = (
            f"Wi-Fi Bastion has detected a security event.\n\n"
            f"Severity:  {severity}\n"
            f"Type:      {alert_type}\n"
            f"Message:   {message}\n"
            f"Time:      {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n"
            f"Log in to the Bastion dashboard for full details."
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"]    = sender
        msg["To"]      = to

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as smtp:
            smtp.login(sender, password)
            smtp.send_message(msg)

        logger.info("Email alert sent to %s.", to)
        return True
    except Exception as e:
        logger.warning("Email alert failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def dispatch(alert: dict) -> None:
    """
    Fire all configured notification channels for a single alert.
    Runs in a daemon thread so it never blocks the request/scheduler thread.

    Only dispatches for CRITICAL and HIGH severity.
    """
    severity = (alert.get("severity") or "LOW").upper()
    if severity not in ("CRITICAL", "HIGH"):
        return

    message    = alert.get("message", "Unknown threat detected.")
    alert_type = alert.get("type",    "SECURITY_ALERT")

    def _run():
        _send_slack(message, severity)
        _send_discord(message, severity)
        _send_ntfy(message, severity, alert_type)
        _send_email(message, severity, alert_type)

    threading.Thread(target=_run, daemon=True, name="alert-dispatch").start()


def dispatch_many(alerts: list[dict]) -> None:
    """Dispatch all CRITICAL/HIGH alerts from a list."""
    for alert in alerts:
        dispatch(alert)


def channels_configured() -> dict[str, bool]:
    """Return which notification channels are configured."""
    return {
        "slack":   bool(os.getenv("SLACK_WEBHOOK_URL")),
        "discord": bool(os.getenv("DISCORD_WEBHOOK_URL")),
        "ntfy":    bool(os.getenv("NTFY_TOPIC")),
        "email":   bool(os.getenv("ALERT_EMAIL") and os.getenv("ALERT_EMAIL_PASSWORD")),
    }