"""
realtime.py — Scheduled Auto-Scanning & WebSocket Push
=======================================================
Combines APScheduler (background jobs) with Flask-SocketIO (real-time
push) so the frontend receives live updates without polling.

Events emitted to the frontend:
  - scan_complete      { networks: [...] }
  - threat_alert       { alerts: [...] }
  - health_update      { mongodb, packet_engine, last_scan }

Frontend usage (JavaScript):
    import { io } from "socket.io-client";
    const socket = io("http://localhost:5000");
    socket.on("scan_complete",  (data) => console.log(data.networks));
    socket.on("threat_alert",   (data) => console.log(data.alerts));
    socket.on("health_update",  (data) => console.log(data));
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask_socketio import SocketIO

if TYPE_CHECKING:
    from wifi_scanner import WiFiScanner
    from network_mapper import DeviceMapper
    from packet_engine import PacketEngine
    from database import DatabaseManager

logger = logging.getLogger("wifi_bastion.realtime")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# How often to auto-scan (seconds). Override with AUTO_SCAN_INTERVAL env var.
AUTO_SCAN_INTERVAL:   int = int(os.getenv("AUTO_SCAN_INTERVAL",   "120"))
# How often to check for active threats (seconds)
THREAT_CHECK_INTERVAL: int = int(os.getenv("THREAT_CHECK_INTERVAL", "15"))
# How often to emit health status (seconds)
HEALTH_CHECK_INTERVAL: int = int(os.getenv("HEALTH_CHECK_INTERVAL", "30"))

# ---------------------------------------------------------------------------
# SocketIO instance (created here, attached to app in init_realtime)
# ---------------------------------------------------------------------------

socketio = SocketIO(
    cors_allowed_origins="*",    # Tightened to ALLOWED_ORIGINS in init_realtime
    async_mode="threading",      # Compatible with Flask dev server + gunicorn
    logger=False,
    engineio_logger=False,
)


# ---------------------------------------------------------------------------
# RealtimeManager
# ---------------------------------------------------------------------------

class RealtimeManager:
    """
    Orchestrates background jobs and WebSocket event emission.

    Call ``init_realtime(app, ...)`` from your application factory —
    do not instantiate this class directly.
    """

    def __init__(
        self,
        wifi_scanner:  "WiFiScanner",
        device_mapper: "DeviceMapper",
        packet_engine: "PacketEngine",
        db_manager:    "DatabaseManager",
    ) -> None:
        self._scanner  = wifi_scanner
        self._mapper   = device_mapper
        self._engine   = packet_engine
        self._db       = db_manager
        self._scheduler = BackgroundScheduler(
            job_defaults={"misfire_grace_time": 30, "coalesce": True}
        )
        self._last_scan_time: float = 0.0
        self._last_network_count: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Register all jobs and start the scheduler."""
        self._scheduler.add_job(
            self._job_auto_scan,
            trigger=IntervalTrigger(seconds=AUTO_SCAN_INTERVAL),
            id="auto_scan",
            name="Automatic Wi-Fi scan",
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._job_threat_check,
            trigger=IntervalTrigger(seconds=THREAT_CHECK_INTERVAL),
            id="threat_check",
            name="Real-time threat aggregation",
            replace_existing=True,
        )
        self._scheduler.add_job(
            self._job_health_check,
            trigger=IntervalTrigger(seconds=HEALTH_CHECK_INTERVAL),
            id="health_check",
            name="Subsystem health broadcast",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(
            "Scheduler started — scan every %ds, threats every %ds, health every %ds.",
            AUTO_SCAN_INTERVAL, THREAT_CHECK_INTERVAL, HEALTH_CHECK_INTERVAL,
        )

    def stop(self) -> None:
        """Gracefully shut down the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped.")

    # ------------------------------------------------------------------
    # Background jobs
    # ------------------------------------------------------------------

    def _job_auto_scan(self) -> None:
        """Run a full Wi-Fi scan and push results to all connected clients."""
        logger.info("Auto-scan triggered.")
        try:
            networks = self._scanner.scan_networks()
            if not networks:
                return

            self._last_scan_time     = time.time()
            self._last_network_count = len(networks)

            # Sync to DB (mirrors the logic in app.py /api/scan)
            ssids    = [n["ssid"] for n in networks]
            existing = self._db.find_existing_networks(ssids)
            new_nets = [n for n in networks if n["ssid"] not in existing]
            if new_nets:
                ok, ids = self._db.insert_networks(new_nets)
                if ok:
                    for net, oid in zip(new_nets, ids):
                        net["_id"] = str(oid)
            for net in networks:
                if net["ssid"] in existing:
                    net["_id"] = str(existing[net["ssid"]]["_id"])

            socketio.emit("scan_complete", {"networks": networks})
            logger.info("scan_complete emitted — %d network(s).", len(networks))
        except Exception as exc:
            logger.exception("Auto-scan job failed: %s", exc)

    def _job_threat_check(self) -> None:
        """Aggregate real-time threats and push if anything is active."""
        try:
            alerts: list[dict] = []

            arp_alerts = self._mapper.detect_arp_spoofing() or []
            alerts.extend(arp_alerts)

            deauth = self._engine.get_alerts()
            if deauth.get("attack_active"):
                alerts.append({
                    "type":      "DEAUTH_FLOOD",
                    "severity":  "CRITICAL",
                    "message":   f"Deauth flood — {deauth.get('count', '?')} frames.",
                    "timestamp": time.time(),
                })

            dns = self._mapper.check_dns_hijack()
            dns_status = dns.get("status", "Safe")
            # Only alert on confirmed Danger (private IP redirect)
            # Warning = timeout (not actionable as a critical alert)
            # Info = ISP transparent proxy (normal, not an attack)
            if dns_status == "Danger":
                alerts.append({
                    "type":      "DNS_HIJACK",
                    "severity":  "CRITICAL",
                    "message":   dns.get("message", "DNS hijack detected."),
                    "timestamp": time.time(),
                })
            elif dns_status == "Warning":
                alerts.append({
                    "type":      "DNS_TIMEOUT",
                    "severity":  "MEDIUM",
                    "message":   dns.get("message", "DNS canaries timed out."),
                    "timestamp": time.time(),
                })

            if alerts:
                socketio.emit("threat_alert", {"alerts": alerts})
                logger.warning(
                    "threat_alert emitted — %d active threat(s).", len(alerts)
                )
        except Exception as exc:
            logger.exception("Threat check job failed: %s", exc)

    def _job_health_check(self) -> None:
        """Emit subsystem health status to all connected clients."""
        try:
            # MongoDB ping
            try:
                self._db.client.admin.command("ping")
                mongo_status = "ok"
            except Exception:
                mongo_status = "unreachable"

            payload = {
                "mongodb":        mongo_status,
                "packet_engine":  "running" if self._engine.is_monitoring else "stopped",
                "last_scan":      self._last_scan_time,
                "network_count":  self._last_network_count,
                "timestamp":      time.time(),
            }
            socketio.emit("health_update", payload)
        except Exception as exc:
            logger.exception("Health check job failed: %s", exc)

    # ------------------------------------------------------------------
    # Manual trigger (called by /api/scan so frontend gets the push too)
    # ------------------------------------------------------------------

    def emit_scan_result(self, networks: list[dict]) -> None:
        """Call this from the /api/scan route to push results immediately."""
        self._last_scan_time     = time.time()
        self._last_network_count = len(networks)
        socketio.emit("scan_complete", {"networks": networks})

    def emit_threat(self, alert: dict) -> None:
        """Push a single threat alert immediately (e.g. from packet engine callback)."""
        socketio.emit("threat_alert", {"alerts": [alert]})


# Global reference so SocketIO event handlers can reach the manager
_manager_instance: RealtimeManager | None = None


# ---------------------------------------------------------------------------
# Application factory helper
# ---------------------------------------------------------------------------

def init_realtime(
    app,
    wifi_scanner:  "WiFiScanner",
    device_mapper: "DeviceMapper",
    packet_engine: "PacketEngine",
    db_manager:    "DatabaseManager",
    allowed_origins: list[str] | None = None,
) -> RealtimeManager:
    """
    Attach SocketIO to the app and start the scheduler.
    Call this from create_app() after all blueprints are registered.

    Returns the RealtimeManager instance.
    """
    global _manager_instance

    # Pass CORS origins directly to init_app — socketio.server is None
    # until after init_app() is called, so setting it beforehand raises AttributeError.
    init_kwargs = {}
    if allowed_origins:
        init_kwargs["cors_allowed_origins"] = allowed_origins

    socketio.init_app(app, **init_kwargs)

    manager = RealtimeManager(
        wifi_scanner=wifi_scanner,
        device_mapper=device_mapper,
        packet_engine=packet_engine,
        db_manager=db_manager,
    )
    manager.start()
    _manager_instance = manager

    import atexit
    atexit.register(manager.stop)

    logger.info("RealtimeManager initialised and scheduler running.")
    return manager