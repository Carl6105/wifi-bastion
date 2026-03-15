"""
monitor.py — Network Change Detection & Threat History
=======================================================
Detects meaningful changes between successive Wi-Fi scans (new networks,
disappeared networks, encryption downgrades, BSSID changes) and maintains
a time-series threat history collection in MongoDB for trend analytics.

Used by:
  - realtime.py  (called after every auto-scan)
  - app.py       (called after every manual /api/scan)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from pymongo import DESCENDING

if TYPE_CHECKING:
    from database import DatabaseManager

logger = logging.getLogger("wifi_bastion.monitor")

# ---------------------------------------------------------------------------
# Collection name for threat events
# ---------------------------------------------------------------------------
THREAT_HISTORY_COLLECTION = "threat_history"
CHANGE_HISTORY_COLLECTION = "network_changes"

# ---------------------------------------------------------------------------
# Change types
# ---------------------------------------------------------------------------

class ChangeType:
    NEW_NETWORK         = "NEW_NETWORK"
    LOST_NETWORK        = "LOST_NETWORK"
    ENCRYPTION_DOWNGRADE = "ENCRYPTION_DOWNGRADE"
    ENCRYPTION_UPGRADE  = "ENCRYPTION_UPGRADE"
    BSSID_CHANGED       = "BSSID_CHANGED"
    SIGNAL_SPIKE        = "SIGNAL_SPIKE"


# ---------------------------------------------------------------------------
# Encryption strength ranking (higher = stronger)
# ---------------------------------------------------------------------------
_ENC_RANK: dict[str, int] = {
    "Open (No Encryption)": 0,
    "WEP":                  1,
    "WPA":                  2,
    "WPA2":                 3,
    "WPA2-PSK":             3,
    "WPA2-Enterprise":      4,
    "WPA3":                 5,
    "WPA3-PSK":             5,
    "WPA3-Enterprise":      6,
    "WPA2/WPA3-Transition": 4,
}


def _enc_rank(enc: str) -> int:
    # Partial match — "WPA2-PSK" contains "WPA2"
    for key, rank in sorted(_ENC_RANK.items(), key=lambda x: -len(x[0])):
        if key.upper() in enc.upper():
            return rank
    return -1


# ---------------------------------------------------------------------------
# NetworkMonitor
# ---------------------------------------------------------------------------

class NetworkMonitor:
    """
    Compares successive scan results and persists both change events and
    threat events to MongoDB for historical analytics.
    """

    def __init__(self, db_manager: "DatabaseManager") -> None:
        self._db             = db_manager
        self._changes_col    = db_manager.db[CHANGE_HISTORY_COLLECTION]
        self._threat_col     = db_manager.db[THREAT_HISTORY_COLLECTION]
        self._previous_scan: dict[str, dict] = {}   # ssid → network doc
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        try:
            self._changes_col.create_index([("timestamp", DESCENDING)])
            self._changes_col.create_index("change_type")
            self._threat_col.create_index([("timestamp", DESCENDING)])
            self._threat_col.create_index("type")
        except Exception as exc:
            logger.warning("monitor index creation failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_scan(self, networks: list[dict]) -> list[dict]:
        """
        Compare *networks* against the previous scan, persist changes, and
        return a list of change-event dicts for the API/frontend.
        """
        current: dict[str, dict] = {n["ssid"]: n for n in networks}
        changes: list[dict] = []

        # ---- New networks ------------------------------------------------
        for ssid, net in current.items():
            if ssid not in self._previous_scan:
                change = self._make_change(
                    ChangeType.NEW_NETWORK,
                    ssid,
                    net.get("bssid", ""),
                    f"New network appeared: {ssid} ({net.get('encryption', 'Unknown')})",
                    severity="INFO",
                    data={"encryption": net.get("encryption"), "bssid": net.get("bssid")},
                )
                changes.append(change)

        # ---- Lost networks -----------------------------------------------
        for ssid in self._previous_scan:
            if ssid not in current:
                prev = self._previous_scan[ssid]
                change = self._make_change(
                    ChangeType.LOST_NETWORK,
                    ssid,
                    prev.get("bssid", ""),
                    f"Network disappeared: {ssid}",
                    severity="INFO",
                )
                changes.append(change)

        # ---- Changes in known networks -----------------------------------
        for ssid, net in current.items():
            if ssid not in self._previous_scan:
                continue
            prev = self._previous_scan[ssid]

            # Encryption downgrade
            prev_enc  = prev.get("encryption", "")
            curr_enc  = net.get("encryption", "")
            prev_rank = _enc_rank(prev_enc)
            curr_rank = _enc_rank(curr_enc)

            if curr_rank < prev_rank:
                change = self._make_change(
                    ChangeType.ENCRYPTION_DOWNGRADE,
                    ssid,
                    net.get("bssid", ""),
                    f"Encryption DOWNGRADED: {prev_enc} → {curr_enc}",
                    severity="HIGH",
                    data={"from": prev_enc, "to": curr_enc},
                )
                changes.append(change)

            elif curr_rank > prev_rank:
                change = self._make_change(
                    ChangeType.ENCRYPTION_UPGRADE,
                    ssid,
                    net.get("bssid", ""),
                    f"Encryption upgraded: {prev_enc} → {curr_enc}",
                    severity="INFO",
                    data={"from": prev_enc, "to": curr_enc},
                )
                changes.append(change)

            # BSSID change (same SSID, different MAC — strong evil-twin signal)
            prev_bssid = prev.get("bssid", "").lower()
            curr_bssid = net.get("bssid", "").lower()
            if prev_bssid and curr_bssid and prev_bssid != curr_bssid:
                change = self._make_change(
                    ChangeType.BSSID_CHANGED,
                    ssid,
                    curr_bssid,
                    f"BSSID changed for {ssid}: {prev_bssid} → {curr_bssid}",
                    severity="HIGH",
                    data={"from": prev_bssid, "to": curr_bssid},
                )
                changes.append(change)

            # Signal spike (same SSID, much stronger signal than before)
            prev_sig = prev.get("signal")
            curr_sig = net.get("signal")
            if (
                isinstance(prev_sig, int)
                and isinstance(curr_sig, int)
                and (curr_sig - prev_sig) > 20   # +20 dBm jump is suspicious
            ):
                change = self._make_change(
                    ChangeType.SIGNAL_SPIKE,
                    ssid,
                    net.get("bssid", ""),
                    f"Unusual signal spike for {ssid}: {prev_sig} → {curr_sig} dBm",
                    severity="MEDIUM",
                    data={"from_dbm": prev_sig, "to_dbm": curr_sig},
                )
                changes.append(change)

        # Persist and update state
        if changes:
            self._persist_changes(changes)
            logger.info("%d network change(s) detected and persisted.", len(changes))

        self._previous_scan = current
        return changes

    def record_threats(self, alerts: list[dict]) -> None:
        """
        Persist active threat alerts to the time-series collection.
        Called after every threat-check cycle.
        """
        if not alerts:
            return
        try:
            stamped = [{**a, "recorded_at": time.time()} for a in alerts]
            self._threat_col.insert_many(stamped, ordered=False)
        except Exception as exc:
            logger.warning("Failed to persist threat history: %s", exc)

    # ------------------------------------------------------------------
    # Analytics queries (used by /api/analytics endpoints)
    # ------------------------------------------------------------------

    def get_threat_history(
        self,
        hours: int = 24,
        limit: int = 500,
    ) -> list[dict]:
        """Return threat events from the last *hours* hours."""
        since = time.time() - (hours * 3600)
        try:
            docs = list(
                self._threat_col
                .find({"recorded_at": {"$gte": since}})
                .sort("recorded_at", DESCENDING)
                .limit(limit)
            )
            for d in docs:
                d["_id"] = str(d["_id"])
            return docs
        except Exception as exc:
            logger.error("get_threat_history failed: %s", exc)
            return []

    def get_change_history(
        self,
        hours: int = 24,
        limit: int = 200,
    ) -> list[dict]:
        """Return network change events from the last *hours* hours."""
        since = time.time() - (hours * 3600)
        try:
            docs = list(
                self._changes_col
                .find({"timestamp": {"$gte": since}})
                .sort("timestamp", DESCENDING)
                .limit(limit)
            )
            for d in docs:
                d["_id"] = str(d["_id"])
            return docs
        except Exception as exc:
            logger.error("get_change_history failed: %s", exc)
            return []

    def get_threat_summary(self, hours: int = 24) -> dict:
        """
        Return aggregated threat counts for dashboard widgets.

        Returns::

            {
                "total": 42,
                "by_type": {"DEAUTH_FLOOD": 10, "DNS_HIJACK": 2, ...},
                "by_severity": {"CRITICAL": 5, "HIGH": 8, ...},
                "period_hours": 24
            }
        """
        since = time.time() - (hours * 3600)
        try:
            pipeline = [
                {"$match": {"recorded_at": {"$gte": since}}},
                {"$group": {
                    "_id":      "$type",
                    "count":    {"$sum": 1},
                    "severity": {"$first": "$severity"},
                }},
            ]
            results = list(self._threat_col.aggregate(pipeline))
            by_type:     dict[str, int] = {}
            by_severity: dict[str, int] = {}
            total = 0
            for r in results:
                t = r["_id"] or "UNKNOWN"
                c = r["count"]
                s = r.get("severity", "UNKNOWN")
                by_type[t]      = c
                by_severity[s]  = by_severity.get(s, 0) + c
                total           += c
            return {
                "total":        total,
                "by_type":      by_type,
                "by_severity":  by_severity,
                "period_hours": hours,
            }
        except Exception as exc:
            logger.error("get_threat_summary failed: %s", exc)
            return {"total": 0, "by_type": {}, "by_severity": {}, "period_hours": hours}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_change(
        self,
        change_type: str,
        ssid: str,
        bssid: str,
        message: str,
        severity: str = "INFO",
        data: dict | None = None,
    ) -> dict:
        return {
            "change_type": change_type,
            "ssid":        ssid,
            "bssid":       bssid,
            "message":     message,
            "severity":    severity,
            "data":        data or {},
            "timestamp":   time.time(),
        }

    def _persist_changes(self, changes: list[dict]) -> None:
        try:
            self._changes_col.insert_many(changes, ordered=False)
        except Exception as exc:
            logger.warning("Failed to persist network changes: %s", exc)