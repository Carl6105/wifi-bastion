"""
database.py — MongoDB persistence layer for Wi-Fi Bastion
==========================================================
Handles all database operations: scan storage, blocklist management,
and OS-level WiFi filtering with shell-injection-safe subprocess calls.
"""

from __future__ import annotations

import datetime
import logging
import platform
import re
import subprocess
from typing import Any

from bson.errors import InvalidId
from bson.objectid import ObjectId
from pymongo import DESCENDING, MongoClient
from pymongo.errors import (
    BulkWriteError,
    DuplicateKeyError,
    OperationFailure,
    ServerSelectionTimeoutError,
)

try:
    from backend.config import (
        MONGO_URI,
        MONGO_DB,
        MONGO_COLLECTION,
        MONGO_POOL_SIZE,
        MONGO_TIMEOUT_MS,
    )
except ImportError:
    from config import (                           # type: ignore
        MONGO_URI,
        MONGO_DB,
        MONGO_COLLECTION,
        MONGO_POOL_SIZE,
        MONGO_TIMEOUT_MS,
    )

logger = logging.getLogger("wifi_bastion.database")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BLOCKLIST_COLLECTION = "blocklist"
WHITELIST_COLLECTION = "whitelist"
NOTES_COLLECTION     = "network_notes"

# Strict SSID allowlist: printable ASCII, 1–32 chars, no shell metacharacters.
# 802.11 technically allows UTF-8 but Windows netsh doesn't — ASCII is safe.
_SSID_RE = re.compile(r'^[\x20-\x7E]{1,32}$')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_object_id(value: str | None) -> ObjectId | None:
    """Convert a string to ObjectId, returning None on invalid input."""
    if not value:
        return None
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        logger.warning("Invalid ObjectId value received: %r", value)
        return None


def _sanitise_ssid(ssid: str | None) -> str | None:
    """
    Validate an SSID before passing it to OS-level commands.
    Returns the SSID if safe, None otherwise.

    This is the single choke-point that prevents shell injection via SSID
    strings — e.g. an AP named  foo"; rm -rf /  would be rejected here.
    """
    if not ssid:
        return None
    if _SSID_RE.match(ssid):
        return ssid
    logger.warning("Rejecting SSID with unsafe characters: %r", ssid)
    return None


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


# ---------------------------------------------------------------------------
# DatabaseManager
# ---------------------------------------------------------------------------

class DatabaseManager:
    """
    Thin wrapper around PyMongo that exposes domain-level operations.

    All public methods return ``(success: bool, result)`` tuples so callers
    never need to catch exceptions — errors are logged and surfaced cleanly.
    """

    def __init__(self) -> None:
        try:
            self.client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=MONGO_TIMEOUT_MS,
                maxPoolSize=MONGO_POOL_SIZE,
                # Retry once on transient network hiccups
                retryWrites=True,
                retryReads=True,
            )
            self.db         = self.client[MONGO_DB]
            self.collection = self.db[MONGO_COLLECTION]
            self.blocklist  = self.db[BLOCKLIST_COLLECTION]

            # Eagerly verify connectivity so startup fails fast on misconfiguration
            self.client.server_info()
            logger.info("Connected to MongoDB — db=%s", MONGO_DB)

            # Ensure indexes exist (idempotent)
            self._ensure_indexes()

        except ServerSelectionTimeoutError:
            logger.error(
                "Cannot reach MongoDB at %s — is the service running?", MONGO_URI
            )
            raise
        except Exception:
            logger.exception("Unexpected error during DatabaseManager initialisation")
            raise

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def _ensure_indexes(self) -> None:
        """Create indexes once; subsequent calls are no-ops."""
        try:
            # Scans: sort by timestamp, de-duplicate by ssid
            self.collection.create_index([("timestamp", DESCENDING)])
            self.collection.create_index("ssid")

            # Blocklist: unique bssid prevents duplicate block entries
            self.blocklist.create_index("bssid", unique=True, sparse=True)
            self.blocklist.create_index("ssid")
            self.db[NOTES_COLLECTION].create_index("bssid", unique=True, sparse=True)
            self.db[WHITELIST_COLLECTION].create_index("bssid", unique=True, sparse=True)

            logger.debug("MongoDB indexes verified.")
        except OperationFailure as exc:
            logger.warning("Index creation failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Scan operations
    # ------------------------------------------------------------------

    def insert_networks(
        self, networks: list[dict]
    ) -> tuple[bool, list[str] | str]:
        """
        Bulk-insert a list of network documents.

        Returns ``(True, [str_ids])`` on success or ``(False, error_message)``.
        """
        if not networks:
            return True, []

        # Stamp every document with an insertion time
        stamped = [{**n, "created_at": _now()} for n in networks]

        try:
            result = self.collection.insert_many(stamped, ordered=False)
            return True, [str(oid) for oid in result.inserted_ids]
        except BulkWriteError as exc:
            # Partial success: some docs may have been inserted
            inserted = [
                str(oid) for oid in exc.details.get("insertedIds", {}).values()
            ]
            logger.warning(
                "Bulk write partial failure — %d inserted, errors: %s",
                len(inserted),
                exc.details.get("writeErrors"),
            )
            return bool(inserted), inserted if inserted else str(exc)
        except Exception as exc:
            logger.exception("insert_networks failed")
            return False, str(exc)

    def find_existing_networks(self, ssids: list[str]) -> dict[str, dict]:
        """
        Return a ``{ssid: document}`` map for any SSIDs already in the DB.
        """
        if not ssids:
            return {}
        try:
            cursor = self.collection.find({"ssid": {"$in": ssids}})
            return {
                doc["ssid"]: {**doc, "_id": str(doc["_id"])}
                for doc in cursor
            }
        except Exception as exc:
            logger.exception("find_existing_networks failed")
            return {}

    def get_all_scans(self) -> tuple[bool, list[dict] | str]:
        """Return all scan records, newest first."""
        try:
            scans = list(self.collection.find().sort("timestamp", DESCENDING))
            for scan in scans:
                scan["_id"] = str(scan["_id"])
            return True, scans
        except Exception as exc:
            logger.exception("get_all_scans failed")
            return False, str(exc)

    def clear_all_scans(self) -> tuple[bool, str]:
        """Hard-delete every document in the scans collection."""
        try:
            result = self.collection.delete_many({})
            msg = f"Cleared {result.deleted_count} scan record(s)."
            logger.info(msg)
            return True, msg
        except Exception as exc:
            logger.exception("clear_all_scans failed")
            return False, str(exc)

    # ------------------------------------------------------------------
    # Blocklist operations
    # ------------------------------------------------------------------

    def block_network(
        self,
        network_id: str | None,
        bssid: str | None,
        ssid: str | None,
    ) -> tuple[bool, str]:
        """
        Mark a network as blocked in the DB and apply an OS-level filter.

        Steps:
          1. Update ``is_blocked`` flag in the scans collection.
          2. Upsert into the dedicated blocklist collection.
          3. On Windows, add a ``netsh`` WLAN filter (safe, no shell=True).
        """
        errors: list[str] = []

        # ---- 1. Update scan document ----------------------------------------
        if oid := _safe_object_id(network_id):
            try:
                self.collection.update_one(
                    {"_id": oid},
                    {"$set": {"is_blocked": True, "blocked_at": _now()}},
                )
            except Exception as exc:
                errors.append(f"DB flag update failed: {exc}")
                logger.error("block_network — scan update error: %s", exc)

        # ---- 2. Upsert into blocklist ----------------------------------------
        try:
            self.blocklist.update_one(
                {"bssid": bssid},
                {
                    "$set": {
                        "bssid":       bssid,
                        "ssid":        ssid,
                        "network_id":  network_id,
                        "blocked_at":  _now(),
                    }
                },
                upsert=True,
            )
        except DuplicateKeyError:
            logger.info("Network %s is already in the blocklist.", bssid)
        except Exception as exc:
            errors.append(f"Blocklist upsert failed: {exc}")
            logger.error("block_network — blocklist upsert error: %s", exc)

        # ---- 3. OS-level filter (Windows only) ------------------------------
        safe_ssid = _sanitise_ssid(ssid)
        if platform.system() == "Windows" and safe_ssid:
            ok, msg = self._netsh_filter(
                action="add",
                permission="block",
                ssid=safe_ssid,
            )
            if not ok:
                errors.append(msg)

        if errors:
            # Partial success — DB write likely worked, OS filter may not have
            logger.warning("block_network completed with errors: %s", errors)
            return False, "; ".join(errors)

        logger.info("Blocked network — BSSID=%s SSID=%s", bssid, ssid)
        return True, "Network blocked successfully."

    def unblock_network(
        self,
        block_id: str | None,
        ssid: str | None = None,
    ) -> tuple[bool, str]:
        """
        Remove a network from the blocklist and lift the OS-level filter.
        """
        errors: list[str] = []

        # ---- 1. Fetch the record first (we need bssid for the scan update) --
        doc: dict[str, Any] | None = None
        if oid := _safe_object_id(block_id):
            try:
                doc = self.blocklist.find_one({"_id": oid})
            except Exception as exc:
                logger.error("unblock_network — lookup error: %s", exc)

        if doc is None:
            return False, "Network not found in blocklist."

        # ---- 2. Remove from blocklist ----------------------------------------
        try:
            self.blocklist.delete_one({"_id": doc["_id"]})
        except Exception as exc:
            errors.append(f"Blocklist delete failed: {exc}")
            logger.error("unblock_network — delete error: %s", exc)

        # ---- 3. Clear flag in scans collection --------------------------------
        if nid := _safe_object_id(doc.get("network_id")):
            try:
                self.collection.update_one(
                    {"_id": nid},
                    {"$set": {"is_blocked": False}, "$unset": {"blocked_at": ""}},
                )
            except Exception as exc:
                errors.append(f"Scan flag clear failed: {exc}")

        # ---- 4. OS-level filter removal (Windows only) -----------------------
        resolved_ssid = ssid or doc.get("ssid")
        safe_ssid = _sanitise_ssid(resolved_ssid)
        if platform.system() == "Windows" and safe_ssid:
            ok, msg = self._netsh_filter(
                action="delete",
                permission="block",
                ssid=safe_ssid,
            )
            if not ok:
                errors.append(msg)

        if errors:
            return False, "; ".join(errors)

        logger.info("Unblocked network — block_id=%s SSID=%s", block_id, resolved_ssid)
        return True, "Network unblocked successfully."

    def get_blocked_networks(self) -> tuple[bool, list[dict] | str]:
        """Return all currently blocked networks from the blocklist."""
        try:
            blocked = list(self.blocklist.find())
            for doc in blocked:
                doc["_id"] = str(doc["_id"])
                # Normalise datetime for JSON serialisation
                if "blocked_at" in doc and isinstance(doc["blocked_at"], datetime.datetime):
                    doc["blocked_at"] = doc["blocked_at"].isoformat()
            return True, blocked
        except Exception as exc:
            logger.exception("get_blocked_networks failed")
            return False, str(exc)

    # ------------------------------------------------------------------
    # Network notes & tags
    # ------------------------------------------------------------------

    def set_network_note(
        self,
        bssid: str,
        note: str,
        tag: str = "",
    ) -> tuple[bool, str]:
        """
        Upsert a note/tag for a BSSID.
        tag options: Home | Office | Trusted | Suspicious | (empty)
        """
        try:
            self.db[NOTES_COLLECTION].update_one(
                {"bssid": bssid},
                {"$set": {"bssid": bssid, "note": note[:500], "tag": tag, "updated_at": _now()}},
                upsert=True,
            )
            return True, "Note saved."
        except Exception as exc:
            logger.exception("set_network_note failed")
            return False, str(exc)

    def get_network_notes(self) -> dict[str, dict]:
        """Return {bssid: {note, tag}} for all annotated networks."""
        try:
            docs = list(self.db[NOTES_COLLECTION].find())
            return {
                d["bssid"]: {"note": d.get("note", ""), "tag": d.get("tag", "")}
                for d in docs if d.get("bssid")
            }
        except Exception as exc:
            logger.exception("get_network_notes failed")
            return {}

    def delete_network_note(self, bssid: str) -> tuple[bool, str]:
        try:
            self.db[NOTES_COLLECTION].delete_one({"bssid": bssid})
            return True, "Note deleted."
        except Exception as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    # Whitelist (trusted networks)
    # ------------------------------------------------------------------

    def whitelist_network(
        self,
        bssid: str,
        ssid: str,
        network_id: str | None = None,
    ) -> tuple[bool, str]:
        """Add a network to the trusted whitelist."""
        try:
            self.db[WHITELIST_COLLECTION].update_one(
                {"bssid": bssid},
                {"$set": {
                    "bssid":      bssid,
                    "ssid":       ssid,
                    "network_id": network_id,
                    "added_at":   _now(),
                }},
                upsert=True,
            )
            return True, "Network whitelisted."
        except Exception as exc:
            logger.exception("whitelist_network failed")
            return False, str(exc)

    def unwhitelist_network(self, bssid: str) -> tuple[bool, str]:
        try:
            self.db[WHITELIST_COLLECTION].delete_one({"bssid": bssid})
            return True, "Network removed from whitelist."
        except Exception as exc:
            return False, str(exc)

    def get_whitelisted_networks(self) -> tuple[bool, list[dict] | str]:
        try:
            docs = list(self.db[WHITELIST_COLLECTION].find())
            for d in docs:
                d["_id"] = str(d["_id"])
                if "added_at" in d and isinstance(d["added_at"], datetime.datetime):
                    d["added_at"] = d["added_at"].isoformat()
            return True, docs
        except Exception as exc:
            logger.exception("get_whitelisted_networks failed")
            return False, str(exc)

    def get_whitelisted_bssids(self) -> set[str]:
        """Fast set of trusted BSSIDs for threat-detection filtering."""
        try:
            docs = list(self.db[WHITELIST_COLLECTION].find({}, {"bssid": 1}))
            return {d["bssid"].lower() for d in docs if d.get("bssid")}
        except Exception:
            return set()

    # ------------------------------------------------------------------
    # App settings (scan interval, auto-block, etc.)
    # ------------------------------------------------------------------

    def get_settings(self) -> dict:
        """Return persisted app settings, falling back to defaults."""
        try:
            doc = self.db["app_settings"].find_one({"_id": "global"})
            if doc:
                doc.pop("_id", None)
                return doc
        except Exception:
            pass
        return {
            "scan_interval_seconds": 120,
            "auto_block_evil_twin":  False,
            "auto_block_threshold":  20,
            "threat_check_interval": 15,
        }

    def save_settings(self, settings: dict) -> tuple[bool, str]:
        """Persist app settings."""
        # Only allow known keys to prevent arbitrary DB writes
        _allowed = {
            "scan_interval_seconds", "auto_block_evil_twin",
            "auto_block_threshold",  "threat_check_interval",
        }
        clean = {k: v for k, v in settings.items() if k in _allowed}
        if not clean:
            return False, "No valid settings keys provided."
        try:
            self.db["app_settings"].update_one(
                {"_id": "global"},
                {"$set": clean},
                upsert=True,
            )
            return True, "Settings saved."
        except Exception as exc:
            logger.exception("save_settings failed")
            return False, str(exc)

    # ------------------------------------------------------------------
    # OS-level helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _netsh_filter(
        action: str,          # "add" | "delete"
        permission: str,      # "block" | "allow"
        ssid: str,
    ) -> tuple[bool, str]:
        """
        Invoke ``netsh wlan`` to add or remove a WLAN filter.

        ⚠️  Uses a list-form command (NO shell=True) to prevent injection.
            The SSID has already been validated by ``_sanitise_ssid`` before
            this method is called.
        """
        cmd = [
            "netsh", "wlan",
            action, "filter",
            f"permission={permission}",
            f"ssid={ssid}",
            "networktype=infrastructure",
        ]
        try:
            result = subprocess.run(
                cmd,
                shell=False,        # NEVER shell=True with user-supplied data
                check=True,
                capture_output=True,
                text=True,
                timeout=10,         # Don't hang indefinitely
            )
            logger.info(
                "netsh %s filter %s — SSID=%s stdout=%r",
                action, permission, ssid, result.stdout.strip(),
            )
            return True, result.stdout.strip()
        except subprocess.CalledProcessError as exc:
            msg = f"netsh returned non-zero ({exc.returncode}): {exc.stderr.strip()}"
            logger.error(msg)
            return False, msg
        except subprocess.TimeoutExpired:
            msg = "netsh command timed out."
            logger.error(msg)
            return False, msg
        except FileNotFoundError:
            msg = "netsh not found — OS filtering is only supported on Windows."
            logger.warning(msg)
            return False, msg