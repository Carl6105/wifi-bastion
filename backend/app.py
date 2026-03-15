"""
app.py — Wi-Fi Bastion Production API Server
=============================================
Hardened Flask backend with:
  - Rate limiting       (flask-limiter via auth.py)
  - API key auth        (@require_api_key via auth.py)
  - Audit logging       (AuditLogger via auth.py)
  - WebSocket push      (flask-socketio via realtime.py)
  - Auto-scanning       (APScheduler via realtime.py)
  - Change detection    (NetworkMonitor via monitor.py)
  - Analytics + export  (routes_extra.py)
  - Request tracing     (X-Request-ID on every response)
  - Security headers    (HSTS, nosniff, etc.)
"""

from __future__ import annotations

import logging
import os
import re
import time
import uuid
from functools import wraps
from http import HTTPStatus
from typing import Any

from bson import ObjectId
from flask import Blueprint, Flask, Response, g, jsonify, request, send_file
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Local Imports
# ---------------------------------------------------------------------------
try:
    from backend.wifi_scanner   import WiFiScanner
    from backend.database       import DatabaseManager
    from backend.config         import DEBUG_MODE, ALLOWED_ORIGINS, MONITOR_INTERFACE
    from backend.network_mapper import DeviceMapper
    from backend.packet_engine  import PacketEngine
    from backend.report_gen     import SecurityReport
    from backend.auth           import require_api_key, init_limiter, audit_logger, limiter
    from backend.realtime       import init_realtime, socketio
    from backend.monitor        import NetworkMonitor
    from backend.routes_extra   import extra_bp, init_extra_routes
except ImportError:
    from wifi_scanner   import WiFiScanner          # type: ignore
    from database       import DatabaseManager      # type: ignore
    from config         import DEBUG_MODE, ALLOWED_ORIGINS, MONITOR_INTERFACE  # type: ignore
    from network_mapper import DeviceMapper         # type: ignore
    from packet_engine  import PacketEngine         # type: ignore
    from report_gen     import SecurityReport       # type: ignore
    from auth           import require_api_key, init_limiter, audit_logger, limiter  # type: ignore
    from realtime       import init_realtime, socketio   # type: ignore
    from monitor        import NetworkMonitor       # type: ignore
    from routes_extra       import extra_bp, init_extra_routes  # type: ignore

try:
    from backend.oui_lookup        import resolve_vendor, db_status
    from backend.alerts_dispatcher import dispatch_many, channels_configured
except ImportError:
    try:
        from oui_lookup        import resolve_vendor, db_status         # type: ignore
        from alerts_dispatcher import dispatch_many, channels_configured # type: ignore
    except ImportError:
        def resolve_vendor(mac): return "Unknown Vendor"
        def db_status(): return {"loaded": False, "entries": 0}
        def dispatch_many(alerts): pass
        def channels_configured(): return {}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# ── Custom JSON encoder — handles MongoDB ObjectId and datetime ───────────────
import json as _json
import datetime as _datetime

class _BastionJSONProvider(Flask.json_provider_class):
    def dumps(self, obj, **kw):
        return _json.dumps(obj, default=self._default, **kw)

    def loads(self, s, **kw):
        return _json.loads(s, **kw)

    @staticmethod
    def _default(o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, (_datetime.datetime, _datetime.date)):
            return o.isoformat()
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


# ── Clean terminal output ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("wifi_bastion.api")

# Suppress noisy third-party loggers
logging.getLogger("werkzeug").setLevel(logging.WARNING)       # hide per-request GET/POST lines
logging.getLogger("engineio.server").setLevel(logging.ERROR)  # hide engineio debug noise
logging.getLogger("socketio.server").setLevel(logging.ERROR)  # hide socketio debug noise
logging.getLogger("apscheduler").setLevel(logging.WARNING)    # hide scheduler heartbeats
logging.getLogger("urllib3").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Core component singletons
# ---------------------------------------------------------------------------
db_manager    = DatabaseManager()
wifi_scanner  = WiFiScanner(db_manager)
device_mapper = DeviceMapper()
packet_engine = PacketEngine()
net_monitor   = NetworkMonitor(db_manager)

# Start packet monitor — non-fatal if unavailable
try:
    packet_engine.start_monitor(interface=MONITOR_INTERFACE)
    logger.info("Packet monitor started on '%s'.", MONITOR_INTERFACE)
except Exception as exc:
    logger.warning(
        "Packet monitor could not start on '%s': %s — "
        "Monitor mode or elevated privileges may be required.",
        MONITOR_INTERFACE, exc,
    )

# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

_ENC_SCORE: dict[str, int] = {"WPA3": 100, "WPA2": 80, "WPA": 55, "WEP": 20}
_CRITICAL_PORTS = frozenset({21, 22, 23, 25, 445, 3389, 5900})
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def _protocol_strength(encryption: str) -> int:
    enc = encryption.upper()
    for key, score in _ENC_SCORE.items():
        if key in enc:
            return score
    return 10


def calculate_security_vectors(net: dict) -> dict:
    """Compute real-time security metrics for a single scanned network."""
    dns_status  = device_mapper.check_dns_hijack()
    deauth_info = packet_engine.get_alerts()

    dns_val    = 100 if dns_status.get("status") == "Safe" else 30
    packet_val = 100 if not deauth_info.get("attack_active") else 15
    prot_val   = _protocol_strength(net.get("encryption", ""))
    sig        = net.get("signal")
    sig_val    = max(0, min(100, (sig + 100) * 2)) if isinstance(sig, int) else 50
    trust      = round((dns_val + packet_val + prot_val + sig_val) / 4)

    return {
        "dns_secure":        dns_val,
        "packet_integrity":  packet_val,
        "protocol_strength": prot_val,
        "signal_quality":    sig_val,
        "trust_score":       trust,
        "threat_level":      _risk_label(trust),
    }


def _risk_label(score: int) -> str:
    if score >= 80: return "LOW"
    if score >= 50: return "MEDIUM"
    if score >= 25: return "HIGH"
    return "CRITICAL"


# Ports that are NORMAL on a router — DNS, HTTP, HTTPS, SSH admin
_NORMAL_ROUTER_PORTS: frozenset[int] = frozenset({53, 80, 443, 22})


def _port_risk(open_ports: list[int]) -> dict:
    """
    Classify router port exposure, excluding ports that are expected
    on any home/office router (53, 80, 443, 22).

    Risk tiers:
      CRITICAL — telnet, FTP, SMB, RDP, legacy remote access
      HIGH     — databases, VNC, non-standard web
      LOW      — only expected ports open (normal router behaviour)
    """
    # Exclude ports that are normal on a router
    risky = [p for p in open_ports if p not in _NORMAL_ROUTER_PORTS]
    normal = [p for p in open_ports if p in _NORMAL_ROUTER_PORTS]

    critical_found = [p for p in risky if p in _CRITICAL_PORTS]
    if critical_found:
        return {
            "level":  "CRITICAL",
            "detail": f"Dangerous ports exposed: {critical_found}. These enable remote attacks.",
            "ports":  open_ports,
            "risky":  risky,
            "normal": normal,
        }
    if risky:
        return {
            "level":  "HIGH",
            "detail": f"Unexpected ports open: {risky}. Review if these services are intentional.",
            "ports":  open_ports,
            "risky":  risky,
            "normal": normal,
        }
    return {
        "level":  "LOW",
        "detail": f"Only standard router ports open ({normal}). No exposure risk detected.",
        "ports":  open_ports,
        "risky":  [],
        "normal": normal,
    }


def _valid_mac(mac: str) -> bool:
    return bool(mac and _MAC_RE.match(mac))


def _require_json(f):
    """Decorator: reject requests without application/json Content-Type."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return _error("Content-Type must be application/json.", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def _ok(data: Any, status: int = 200) -> tuple[Response, int]:
    return jsonify({
        "status":     "success",
        "data":       data,
        "request_id": getattr(g, "request_id", None),
    }), status


def _error(message: str, status: int | HTTPStatus = 500) -> tuple[Response, int]:
    code = status.value if isinstance(status, HTTPStatus) else int(status)
    logger.error("[rid=%s] %s", getattr(g, "request_id", "?"), message)
    return jsonify({
        "status":     "error",
        "message":    message,
        "request_id": getattr(g, "request_id", None),
    }), code


# ---------------------------------------------------------------------------
# API Blueprint
# ---------------------------------------------------------------------------
api_bp = Blueprint("api", __name__, url_prefix="/api")


# ── Health ──────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health():
    """Basic liveness probe for load balancers / orchestrators."""
    return _ok({
        "service":            "wifi-bastion",
        "version":            os.getenv("APP_VERSION", "1.0.0"),
        "monitor_interface":  MONITOR_INTERFACE,
        "packet_engine":      "running" if packet_engine.is_monitoring else "stopped",
        "oui_database":       db_status(),
        "notification_channels": channels_configured(),
    })


# ── Debug: raw netsh output ──────────────────────────────────────────────────

@api_bp.route("/debug/netsh", methods=["GET"])
@limiter.limit("10 per minute")
def debug_netsh():
    """
    Diagnostic: returns raw netsh output so we can fix the channel parser.
    """
    import subprocess as _sp
    import platform as _pl
    import re as _re

    plat = _pl.system()
    raw_out = ""
    parse_error = None

    if plat == "Windows":
        try:
            r = _sp.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                shell=False, capture_output=True,
                timeout=12,
            )
            # Try UTF-8 first, fall back to cp1252 (common on Indian Windows)
            for enc in ("utf-8", "cp1252", "latin-1"):
                try:
                    raw_out = r.stdout.decode(enc)
                    break
                except Exception:
                    continue
        except Exception as e:
            parse_error = str(e)

    # Run the parser inline (no import needed)
    channel_map = {}
    current_bssid = None
    mac_re = _re.compile("[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")

    for raw_line in raw_out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.upper().startswith("BSSID") and ":" in line:
            m = mac_re.search(line)
            if m:
                current_bssid = m.group(0).lower()
                channel_map.setdefault(current_bssid, {})
            continue
        if current_bssid is None:
            continue
        if "channel" in line.lower() and ":" in line:
            try:
                ch = int(line.split(":", 1)[1].strip())
                channel_map[current_bssid]["channel"] = ch
            except Exception:
                pass

    return _ok({
        "platform":    plat,
        "parse_error": parse_error,
        "raw_lines":   raw_out.splitlines()[:100],
        "parsed_map":  channel_map,
        "bssid_count": len(channel_map),
    })


# ── Scan ────────────────────────────────────────────────────────────────────

@api_bp.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan():
    """
    Trigger a Wi-Fi scan.
    Enriches results with security vectors, syncs to MongoDB,
    runs change detection, and pushes results via WebSocket.
    """
    networks = wifi_scanner.scan_networks()
    if not networks:
        return _error("No networks detected. Check adapter permissions.", HTTPStatus.NOT_FOUND)

    # Enrich with security metrics
    for net in networks:
        net.update(calculate_security_vectors(net))

    # DB sync — insert new, tag existing
    ssids    = [n["ssid"] for n in networks]
    existing = db_manager.find_existing_networks(ssids)
    new_nets = [n for n in networks if n["ssid"] not in existing]

    if new_nets:
        ok, result = db_manager.insert_networks(new_nets)
        if ok:
            for net, oid in zip(new_nets, result):
                net["_id"] = str(oid)

    for net in networks:
        if net["ssid"] in existing:
            net["_id"] = str(existing[net["ssid"]]["_id"])

    # Change detection — compares to last scan
    changes = net_monitor.process_scan(networks)
    if changes:
        logger.info("%d network change(s) detected.", len(changes))

    # Audit trail + WebSocket push
    audit_logger.log_scan(len(networks))
    _emit_scan(networks)

    return _ok({
        "networks": networks,
        "count":    len(networks),
        "changes":  changes,
    })


# ── Security Alerts ─────────────────────────────────────────────────────────

@api_bp.route("/security_alerts", methods=["GET"])
@limiter.limit("30 per minute")
def security_alerts():
    """
    Aggregate real-time threat signals.
    Persists to threat history and pushes critical alerts via WebSocket.
    """
    alerts: list[dict] = []

    arp_alerts = device_mapper.detect_arp_spoofing() or []
    for a in arp_alerts:
        a.setdefault("severity", "HIGH")
        a.setdefault("timestamp", time.time())
    alerts.extend(arp_alerts)

    deauth = packet_engine.get_alerts()
    if deauth.get("attack_active"):
        alerts.append({
            "type":      "DEAUTH_FLOOD",
            "severity":  "CRITICAL",
            "message":   f"Detected {deauth['count']} deauthentication frames.",
            "timestamp": time.time(),
        })

    dns = device_mapper.check_dns_hijack()
    dns_status = dns.get("status", "Safe")
    if dns_status == "Danger":
        alerts.append({
            "type":      "DNS_HIJACK",
            "severity":  "CRITICAL",
            "message":   dns.get("message", "DNS hijack confirmed."),
            "timestamp": time.time(),
            "details":   dns.get("details", []),
        })
    elif dns_status == "Warning":
        # Timeout only — medium severity, not a confirmed attack
        alerts.append({
            "type":      "DNS_TIMEOUT",
            "severity":  "MEDIUM",
            "message":   dns.get("message", "DNS canaries timed out — check connectivity."),
            "timestamp": time.time(),
        })
    # Info and Safe statuses do NOT generate alerts

    # Beacon anomalies
    beacon_anomalies = packet_engine.get_beacon_anomalies()
    for bssid, atype in beacon_anomalies.items():
        alerts.append({
            "type":     "BEACON_ANOMALY",
            "severity": "MEDIUM",
            "message":  f"Abnormal beacon interval from {bssid} ({atype}).",
            "timestamp": time.time(),
        })

    # PMKID captures
    pmkid_captures = packet_engine.get_pmkid_captures(since_seconds=300)
    for cap in pmkid_captures:
        alerts.append({
            "type":     "PMKID_CAPTURE",
            "severity": "CRITICAL",
            "message":  f"PMKID captured from {cap['bssid']} — offline WPA2 cracking possible.",
            "timestamp": cap["timestamp"],
        })

    # Sort: CRITICAL first
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: _order.get(a.get("severity", "LOW"), 99))

    # Persist to time-series threat history
    net_monitor.record_threats(alerts)

    # Dispatch critical alerts to configured notification channels (Slack/Discord/ntfy/email)
    critical = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    if critical:
        dispatch_many(critical)

    return _ok({"alerts": alerts, "count": len(alerts)})


# ── Gateway Audit ────────────────────────────────────────────────────────────

@api_bp.route("/gateway_audit", methods=["GET"])
@limiter.limit("20 per minute")
def gateway_audit():
    """DNS canary check + multi-threaded router port scan."""
    dns_status = device_mapper.check_dns_hijack()
    open_ports = device_mapper.scan_router_ports() or []
    port_risk  = _port_risk(open_ports)

    return _ok({
        "dns":                  dns_status,
        "port_risk":            port_risk,
        "critical_ports_found": [p for p in open_ports if p in _CRITICAL_PORTS],
        "summary": {
            "dns_safe":   dns_status.get("status") == "Safe",
            "risk_level": port_risk["level"],
        },
    })


# ── Device Map ───────────────────────────────────────────────────────────────

@api_bp.route("/map_devices", methods=["GET"])
@limiter.limit("10 per minute")
def map_devices():
    """Return all active devices on the local network with OS fingerprinting."""
    devices = device_mapper.scan_devices()
    count   = len(devices) if isinstance(devices, list) else 0
    return _ok({"devices": devices, "count": count})


# ── Disconnect Device ────────────────────────────────────────────────────────

@api_bp.route("/disconnect_device", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
@_require_json
def disconnect_device():
    """
    Transmit a targeted deauth frame to a MAC address.
    ⚠️  Authorised use only — illegal without permission.
    """
    data       = request.get_json(silent=True) or {}
    target_mac = data.get("mac", "").strip()

    if not _valid_mac(target_mac):
        return _error("Valid MAC required (AA:BB:CC:DD:EE:FF).", HTTPStatus.BAD_REQUEST)

    success = packet_engine.send_deauth(target_mac)
    if not success:
        return _error("Failed to transmit deauth frame. Check monitor mode.", HTTPStatus.INTERNAL_SERVER_ERROR)

    audit_logger.log_deauth_sent(target_mac)
    return _ok({"message": f"Deauth signal transmitted to {target_mac}."})


# ── Generate Report ──────────────────────────────────────────────────────────

@api_bp.route("/generate_report", methods=["POST"])
@limiter.limit("3 per minute")
@require_api_key
@_require_json
def generate_report():
    """Generate and stream a full PDF security audit report."""
    data     = request.get_json(silent=True) or {}
    networks = data.get("networks", [])

    if not isinstance(networks, list) or not networks:
        return _error("'networks' must be a non-empty list.", HTTPStatus.BAD_REQUEST)

    dns_status = device_mapper.check_dns_hijack()
    open_ports = device_mapper.scan_router_ports() or []
    gateway_data = {
        "dns":       dns_status,
        "ports":     open_ports,
        "port_risk": _port_risk(open_ports),
    }

    report_dir  = os.getenv("REPORT_OUTPUT_DIR", "/tmp")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(
        report_dir, f"bastion_audit_{int(time.time())}_{uuid.uuid4().hex[:6]}.pdf"
    )

    SecurityReport().create_report(networks, gateway_data, report_path)
    audit_logger.log_report_generated(report_path)

    return send_file(
        report_path,
        as_attachment=True,
        download_name="wifi_bastion_audit.pdf",
        mimetype="application/pdf",
    )


# ── History ──────────────────────────────────────────────────────────────────

@api_bp.route("/history", methods=["GET"])
@limiter.limit("30 per minute")
def history():
    """Return paginated scan history. Query params: ?page=1&limit=50"""
    try:
        page  = max(int(request.args.get("page",  1)),   1)
        limit = min(int(request.args.get("limit", 50)), 200)
    except ValueError:
        return _error("'page' and 'limit' must be integers.", HTTPStatus.BAD_REQUEST)

    ok, result = db_manager.get_all_scans()
    if not ok:
        return _error(result)

    start = (page - 1) * limit
    paged = result[start: start + limit]
    return _ok({"scans": paged, "page": page, "limit": limit, "total": len(result)})


@api_bp.route("/history", methods=["DELETE"])
@limiter.limit("5 per minute")
@require_api_key
def clear_history():
    """Permanently delete all scan records."""
    ok, message = db_manager.clear_all_scans()
    return _ok({"message": message}) if ok else _error(message)


# ── Block / Unblock ──────────────────────────────────────────────────────────

@api_bp.route("/block_network", methods=["POST"])
@limiter.limit("20 per minute")
@require_api_key
@_require_json
def block_network():
    data       = request.get_json(silent=True) or {}
    network_id = data.get("network_id")
    bssid      = data.get("bssid", "").strip()
    ssid       = data.get("ssid",  "").strip()

    if not any([network_id, bssid, ssid]):
        return _error("Provide at least one of: network_id, bssid, ssid.", HTTPStatus.BAD_REQUEST)

    ok, message = db_manager.block_network(network_id, bssid, ssid)
    if ok:
        audit_logger.log_network_blocked(ssid, bssid)
    return _ok({"message": message}) if ok else _error(message)


@api_bp.route("/unblock_network", methods=["POST"])
@limiter.limit("20 per minute")
@require_api_key
@_require_json
def unblock_network():
    data = request.get_json(silent=True) or {}
    ok, message = db_manager.unblock_network(data.get("network_id"), data.get("ssid"))
    if ok:
        audit_logger.log_network_unblocked(data.get("ssid", ""))
    return _ok({"message": message}) if ok else _error(message)


@api_bp.route("/blocked", methods=["GET"])
@limiter.limit("30 per minute")
def blocked_networks():
    ok, result = db_manager.get_blocked_networks()
    if not ok:
        return _error(result)
    return _ok({"blocked": result, "count": len(result)})


# ── Network Notes ────────────────────────────────────────────────────────────

@api_bp.route("/notes", methods=["GET"])
@limiter.limit("30 per minute")
def get_notes():
    """Return all network notes/tags."""
    notes = db_manager.get_network_notes()
    return _ok({"notes": notes, "count": len(notes)})


@api_bp.route("/notes", methods=["POST"])
@limiter.limit("30 per minute")
@_require_json
def set_note():
    """Create or update a note/tag for a BSSID."""
    data = request.get_json(silent=True) or {}
    bssid = data.get("bssid", "").strip()
    note  = data.get("note",  "").strip()
    tag   = data.get("tag",   "").strip()

    if not bssid:
        return _error("bssid is required.", HTTPStatus.BAD_REQUEST)

    valid_tags = {"Home", "Office", "Trusted", "Suspicious", ""}
    if tag not in valid_tags:
        return _error(f"tag must be one of: {valid_tags}", HTTPStatus.BAD_REQUEST)

    ok, message = db_manager.set_network_note(bssid, note, tag)
    return _ok({"message": message}) if ok else _error(message)


@api_bp.route("/notes/<bssid>", methods=["DELETE"])
@limiter.limit("20 per minute")
def delete_note(bssid: str):
    ok, message = db_manager.delete_network_note(bssid)
    return _ok({"message": message}) if ok else _error(message)


# ── Whitelist ────────────────────────────────────────────────────────────────

@api_bp.route("/whitelist", methods=["GET"])
@limiter.limit("30 per minute")
def get_whitelist():
    ok, result = db_manager.get_whitelisted_networks()
    if not ok:
        return _error(result)
    return _ok({"whitelist": result, "count": len(result)})


@api_bp.route("/whitelist", methods=["POST"])
@limiter.limit("20 per minute")
@_require_json
def add_whitelist():
    data = request.get_json(silent=True) or {}
    bssid = data.get("bssid", "").strip()
    ssid  = data.get("ssid",  "").strip()
    if not bssid:
        return _error("bssid is required.", HTTPStatus.BAD_REQUEST)
    ok, message = db_manager.whitelist_network(bssid, ssid, data.get("network_id"))
    return _ok({"message": message}) if ok else _error(message)


@api_bp.route("/whitelist/<bssid>", methods=["DELETE"])
@limiter.limit("20 per minute")
def remove_whitelist(bssid: str):
    ok, message = db_manager.unwhitelist_network(bssid)
    return _ok({"message": message}) if ok else _error(message)


# ── Settings ─────────────────────────────────────────────────────────────────

@api_bp.route("/settings", methods=["GET"])
@limiter.limit("30 per minute")
def get_settings():
    """Return current app settings."""
    settings = db_manager.get_settings()
    return _ok(settings)


@api_bp.route("/settings", methods=["PATCH"])
@limiter.limit("10 per minute")
@_require_json
def save_settings():
    """Update one or more app settings."""
    data = request.get_json(silent=True) or {}
    ok, message = db_manager.save_settings(data)
    if ok:
        # Apply scan interval change to the running scheduler
        if "scan_interval_seconds" in data:
            try:
                from realtime import _manager_instance
                if _manager_instance and _manager_instance._scheduler.running:
                    _manager_instance._scheduler.reschedule_job(
                        "auto_scan",
                        trigger="interval",
                        seconds=int(data["scan_interval_seconds"]),
                    )
                    logger.info("Scan interval updated to %ds.", data["scan_interval_seconds"])
            except Exception as exc:
                logger.warning("Could not reschedule scan job: %s", exc)
    return _ok({"message": message}) if ok else _error(message)


# ── Extended alerts (beacon + PMKID) ─────────────────────────────────────────

@api_bp.route("/extended_alerts", methods=["GET"])
@limiter.limit("30 per minute")
def extended_alerts():
    """Returns beacon anomalies and PMKID captures in addition to standard alerts."""
    beacon_anomalies = packet_engine.get_beacon_anomalies()
    pmkid_captures   = packet_engine.get_pmkid_captures()

    alerts = []
    for bssid, atype in beacon_anomalies.items():
        alerts.append({
            "type":     f"BEACON_{atype}",
            "severity": "MEDIUM",
            "bssid":    bssid,
            "message":  (
                f"Abnormal beacon interval from {bssid}. "
                "Possible rogue AP or misconfigured device."
                if atype == "BEACON_FLOOD"
                else f"Unusually slow beacon rate from {bssid}."
            ),
            "timestamp": time.time(),
        })
    for cap in pmkid_captures:
        alerts.append({
            "type":       "PMKID_CAPTURE",
            "severity":   "CRITICAL",
            "bssid":      cap["bssid"],
            "client_mac": cap["client_mac"],
            "message":    (
                f"PMKID captured from {cap['bssid']} — "
                "offline WPA2 dictionary attack is now possible without client interaction."
            ),
            "timestamp": cap["timestamp"],
        })

    return _ok({"alerts": alerts, "count": len(alerts)})


# ---------------------------------------------------------------------------
# WebSocket emit helper (safe to call even if realtime isn't initialised)
# ---------------------------------------------------------------------------

def _emit_scan(networks: list[dict]) -> None:
    try:
        socketio.emit("scan_complete", {"networks": networks})
    except Exception as exc:
        logger.debug("WebSocket emit skipped: %s", exc)


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)
    app.json_provider_class = _BastionJSONProvider
    app.json = _BastionJSONProvider(app)
    app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024   # 1 MB cap

    # CORS
    CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

    # Rate limiter
    init_limiter(app)

    # Analytics / export blueprint
    init_extra_routes(db_manager, device_mapper, packet_engine, net_monitor)
    app.register_blueprint(extra_bp)

    # Main API blueprint
    app.register_blueprint(api_bp)

    # WebSocket + APScheduler
    rt = init_realtime(
        app,
        wifi_scanner=wifi_scanner,
        device_mapper=device_mapper,
        packet_engine=packet_engine,
        db_manager=db_manager,
        allowed_origins=ALLOWED_ORIGINS,
    )
    app.config["REALTIME"] = rt

    # Security headers
    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]         = "DENY"
        response.headers["X-XSS-Protection"]        = "1; mode=block"
        response.headers["Referrer-Policy"]         = "no-referrer"
        if not DEBUG_MODE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Request tracing
    @app.before_request
    def attach_request_id() -> None:
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        g.start_time = time.monotonic()

    @app.after_request
    def log_request(response: Response) -> Response:
        elapsed_ms = round((time.monotonic() - g.start_time) * 1000, 2)
        response.headers["X-Request-ID"]       = g.request_id
        response.headers["X-Response-Time-Ms"] = str(elapsed_ms)
        logger.info(
            "%s %s → %d  [%.1f ms] [rid=%s]",
            request.method, request.path,
            response.status_code, elapsed_ms, g.request_id,
        )
        return response

    # Global error handlers
    @app.errorhandler(400)
    def bad_request(e):        return _error(f"Bad request: {e}", HTTPStatus.BAD_REQUEST)

    @app.errorhandler(404)
    def not_found(e):          return _error("Endpoint not found.", HTTPStatus.NOT_FOUND)

    @app.errorhandler(405)
    def method_not_allowed(e): return _error("Method not allowed.", HTTPStatus.METHOD_NOT_ALLOWED)

    @app.errorhandler(413)
    def too_large(e):          return _error("Payload too large (max 1 MB).", 413)

    @app.errorhandler(429)
    def too_many(e):           return _error("Too many requests — slow down.", 429)

    @app.errorhandler(Exception)
    def unhandled(e):
        logger.exception("Unhandled exception [rid=%s]: %s", getattr(g, "request_id", "?"), e)
        return _error(str(e) if DEBUG_MODE else "An unexpected error occurred.", 500)

    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Wi-Fi Bastion on port %d (debug=%s).", port, DEBUG_MODE)

    application = create_app()

    # socketio.run() handles WebSocket upgrades correctly.
    # use_reloader=False is required on Windows — the werkzeug reloader
    # uses select() on non-socket file descriptors which raises WinError 10038.
    # Production: gunicorn "app:create_app()" --worker-class eventlet --workers 1
    import platform as _platform
    _windows = _platform.system() == "Windows"
    socketio.run(
        application,
        debug=DEBUG_MODE,
        host="0.0.0.0",
        port=port,
        use_reloader=False,            # Never use reloader with socketio on Windows
        allow_unsafe_werkzeug=True,    # Required when not using a production WSGI server
        log_output=False,              # Suppress engineio/socketio per-request noise
    )