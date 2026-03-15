"""
routes_extra.py — Analytics, Export & Health Routes
====================================================
Additional Blueprint that plugs into create_app().
Provides:
  - GET  /api/health/full          — expanded subsystem health
  - GET  /api/analytics/threats    — threat trend data
  - GET  /api/analytics/changes    — network change timeline
  - GET  /api/analytics/summary    — dashboard summary widget data
  - GET  /api/export               — export scan history as JSON or CSV
"""

from __future__ import annotations

import csv
import io
import logging
import time
from http import HTTPStatus

from flask import Blueprint, Response, jsonify, request, stream_with_context

logger = logging.getLogger("wifi_bastion.routes_extra")

extra_bp = Blueprint("extra", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# These are injected by init_extra_routes() — avoids circular imports
# ---------------------------------------------------------------------------
_db_manager    = None
_device_mapper = None
_packet_engine = None
_monitor       = None


def init_extra_routes(db_manager, device_mapper, packet_engine, monitor) -> None:
    """
    Inject dependencies into this blueprint.
    Call from create_app() after all components are initialised.
    """
    global _db_manager, _device_mapper, _packet_engine, _monitor
    _db_manager    = db_manager
    _device_mapper = device_mapper
    _packet_engine = packet_engine
    _monitor       = monitor


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _ok(data, status: HTTPStatus = HTTPStatus.OK):
    return jsonify(data), status.value

def _err(msg: str, status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR):
    return jsonify({"status": "error", "message": msg}), status.value


# ---------------------------------------------------------------------------
# /api/health/full
# ---------------------------------------------------------------------------

@extra_bp.route("/health/full", methods=["GET"])
def health_full():
    """
    Expanded health check — reports the status of every subsystem.

    Response::

        {
            "status":         "ok" | "degraded" | "critical",
            "mongodb":        "ok" | "unreachable",
            "packet_engine":  "running" | "stopped",
            "last_scan_ago":  "2m 14s" | "never",
            "network_count":  12,
            "timestamp":      1712345678
        }
    """
    issues: list[str] = []

    # MongoDB
    mongo_status = "ok"
    try:
        _db_manager.client.admin.command("ping")
    except Exception:
        mongo_status = "unreachable"
        issues.append("mongodb")

    # Packet engine
    engine_status = "running" if _packet_engine.is_monitoring else "stopped"

    # Last scan freshness
    try:
        success, scans = _db_manager.get_all_scans()
        if success and scans:
            last_ts  = scans[0].get("timestamp", 0)
            ago_secs = int(time.time() - last_ts)
            m, s     = divmod(ago_secs, 60)
            last_scan_ago   = f"{m}m {s}s ago"
            network_count   = len(scans)
        else:
            last_scan_ago   = "never"
            network_count   = 0
    except Exception:
        last_scan_ago = "unknown"
        network_count = 0

    overall = (
        "critical" if "mongodb" in issues
        else "degraded" if issues
        else "ok"
    )

    return _ok({
        "status":        overall,
        "mongodb":       mongo_status,
        "packet_engine": engine_status,
        "last_scan_ago": last_scan_ago,
        "network_count": network_count,
        "timestamp":     int(time.time()),
    })


# ---------------------------------------------------------------------------
# /api/analytics/threats
# ---------------------------------------------------------------------------

@extra_bp.route("/analytics/threats", methods=["GET"])
def analytics_threats():
    """
    Return time-series threat events for chart rendering.

    Query params:
        hours  (int, default 24)  — lookback window
        limit  (int, default 500) — max records
    """
    hours = _safe_int(request.args.get("hours"), default=24, min_val=1, max_val=168)
    limit = _safe_int(request.args.get("limit"), default=500, min_val=1, max_val=2000)

    if _monitor is None:
        return _err("Monitor not initialised.", HTTPStatus.SERVICE_UNAVAILABLE)

    events = _monitor.get_threat_history(hours=hours, limit=limit)
    return _ok({"events": events, "count": len(events), "period_hours": hours})


# ---------------------------------------------------------------------------
# /api/analytics/changes
# ---------------------------------------------------------------------------

@extra_bp.route("/analytics/changes", methods=["GET"])
def analytics_changes():
    """
    Return network change events (new/lost/downgraded) for the timeline view.

    Query params:
        hours  (int, default 24)
        limit  (int, default 200)
    """
    hours = _safe_int(request.args.get("hours"), default=24, min_val=1, max_val=168)
    limit = _safe_int(request.args.get("limit"), default=200, min_val=1, max_val=1000)

    if _monitor is None:
        return _err("Monitor not initialised.", HTTPStatus.SERVICE_UNAVAILABLE)

    changes = _monitor.get_change_history(hours=hours, limit=limit)
    return _ok({"changes": changes, "count": len(changes), "period_hours": hours})


# ---------------------------------------------------------------------------
# /api/analytics/summary
# ---------------------------------------------------------------------------

@extra_bp.route("/analytics/summary", methods=["GET"])
def analytics_summary():
    """
    Aggregated threat summary — powers dashboard stat cards.

    Response::

        {
            "total": 42,
            "by_type":     { "DEAUTH_FLOOD": 10, ... },
            "by_severity": { "CRITICAL": 5, "HIGH": 8, ... },
            "period_hours": 24
        }
    """
    hours = _safe_int(request.args.get("hours"), default=24, min_val=1, max_val=168)

    if _monitor is None:
        return _err("Monitor not initialised.", HTTPStatus.SERVICE_UNAVAILABLE)

    summary = _monitor.get_threat_summary(hours=hours)
    return _ok(summary)


# ---------------------------------------------------------------------------
# /api/export
# ---------------------------------------------------------------------------

@extra_bp.route("/export", methods=["GET"])
def export_data():
    """
    Export full scan history as JSON or CSV.

    Query params:
        format  "json" (default) | "csv"

    CSV columns: ssid, bssid, signal, encryption, trust_score,
                 rating, vendor, distance, timestamp
    """
    fmt = request.args.get("format", "json").lower().strip()

    success, scans = _db_manager.get_all_scans()
    if not success:
        return _err(str(scans))

    if fmt == "csv":
        return _export_csv(scans)
    return _export_json(scans)


def _export_json(scans: list[dict]) -> Response:
    import json
    payload = json.dumps({"scans": scans, "count": len(scans)}, default=str, indent=2)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": 'attachment; filename="wifi_bastion_export.json"'},
    )


def _export_csv(scans: list[dict]) -> Response:
    columns = [
        "ssid", "bssid", "signal", "encryption",
        "trust_score", "rating", "vendor", "distance", "timestamp",
    ]

    def generate():
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        yield buf.getvalue()
        buf.truncate(0)
        buf.seek(0)

        for scan in scans:
            writer.writerow({col: scan.get(col, "") for col in columns})
            yield buf.getvalue()
            buf.truncate(0)
            buf.seek(0)

    return Response(
        stream_with_context(generate()),
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="wifi_bastion_export.csv"'},
    )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _safe_int(value: str | None, default: int, min_val: int, max_val: int) -> int:
    """Parse an integer query param with bounds, returning default on failure."""
    if value is None:
        return default
    try:
        return max(min_val, min(max_val, int(value)))
    except (ValueError, TypeError):
        return default