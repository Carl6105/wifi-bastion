"""
oui_lookup.py — Offline IEEE OUI vendor resolution
====================================================
Downloads the IEEE MA-L (MAC Address Large) OUI database once,
caches it to disk, and provides fast O(1) lookups.

- Free, no API key required
- ~4MB download, cached indefinitely (refreshed weekly)
- Falls back to built-in table if download fails
- Thread-safe singleton

Usage:
    from oui_lookup import resolve_vendor
    vendor = resolve_vendor("aa:bb:cc:dd:ee:ff")  # → "TP-Link Technologies"
"""

from __future__ import annotations

import csv
import io
import logging
import os
import threading
import time
from pathlib import Path

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger("wifi_bastion.oui_lookup")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_IEEE_OUI_URL   = "https://maclookup.app/downloads/csv-database/get-db?apiKey=free"
_FALLBACK_URL   = "https://standards-oui.ieee.org/oui/oui.csv"
_CACHE_DIR      = Path(os.getenv("OUI_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".wifi_bastion")))
_CACHE_FILE     = _CACHE_DIR / "oui_cache.csv"
_CACHE_MAX_AGE  = 7 * 24 * 3600   # 7 days

# ---------------------------------------------------------------------------
# Built-in fallback table (common vendors — used when offline)
# ---------------------------------------------------------------------------

_BUILTIN: dict[str, str] = {
    # TP-Link
    "f0:ed:b8": "TP-Link",       "b4:a7:c6": "TP-Link",
    "f2:ed:b8": "TP-Link",       "50:c7:bf": "TP-Link",
    "98:da:c4": "TP-Link",       "c8:3a:35": "TP-Link",
    "e8:de:27": "TP-Link",       "54:a7:03": "TP-Link",
    # Netgear
    "a0:04:60": "Netgear",       "c0:ff:d4": "Netgear",
    "28:c6:8e": "Netgear",       "20:4e:7f": "Netgear",
    # Asus
    "00:0c:6e": "Asus",          "04:d4:c4": "Asus",
    "2c:56:dc": "Asus",          "50:46:5d": "Asus",
    # Cisco / Linksys
    "04:25:e0": "Cisco",         "00:1a:2b": "Cisco",
    "68:86:a7": "Cisco",         "00:50:56": "Cisco (VMware)",
    # D-Link
    "14:d6:4d": "D-Link",        "1c:7e:e5": "D-Link",
    "f0:7d:68": "D-Link",
    # Apple
    "a8:da:0c": "Apple",         "f4:f1:5a": "Apple",
    "3c:22:fb": "Apple",         "00:50:e4": "Apple",
    "f8:ff:c2": "Apple",
    # Samsung
    "9c:53:22": "Samsung",       "f4:42:8f": "Samsung",
    "50:01:bb": "Samsung",
    # JioFiber / Reliance
    "8c:a3:99": "JioFiber",      "44:e9:dd": "JioFiber",
    # Huawei
    "00:46:4b": "Huawei",        "54:89:98": "Huawei",
    "70:72:cf": "Huawei",
    # Xiaomi / Mi
    "00:9e:c8": "Xiaomi",        "34:ce:00": "Xiaomi",
    "78:11:dc": "Xiaomi",
    # Google (Nest WiFi, Chromecast)
    "f4:f5:d8": "Google",        "54:60:09": "Google",
    "3c:5a:b4": "Google",
    # Eero (Amazon)
    "f4:f9:51": "Amazon/Eero",   "fc:65:de": "Amazon/Eero",
    # Ubiquiti
    "04:18:d6": "Ubiquiti",      "dc:9f:db": "Ubiquiti",
    "f4:92:bf": "Ubiquiti",
    # Aruba (HP)
    "00:0b:86": "Aruba/HP",      "94:b4:0f": "Aruba/HP",
    # Mikrotik
    "4c:5e:0c": "MikroTik",      "d4:ca:6d": "MikroTik",
    "2c:c8:1b": "MikroTik",
    # Microsoft
    "00:50:f2": "Microsoft",     "28:18:78": "Microsoft",
    # Intel (common in laptops)
    "00:21:6a": "Intel",         "8c:8d:28": "Intel",
    "ac:ed:5c": "Intel",
    # Realtek (common in budget devices)
    "00:e0:4c": "Realtek",
}


# ---------------------------------------------------------------------------
# OUI Database
# ---------------------------------------------------------------------------

class OUIDatabase:
    """Thread-safe OUI lookup backed by a disk-cached IEEE CSV."""

    def __init__(self) -> None:
        self._db:    dict[str, str] = {}
        self._lock   = threading.RLock()
        self._loaded = False
        # Load in background so startup isn't delayed
        t = threading.Thread(target=self._load, daemon=True, name="oui-loader")
        t.start()

    def _load(self) -> None:
        """Load OUI data: cache → download → builtin fallback."""
        try:
            if self._cache_valid():
                self._parse_cache()
                logger.info("OUI database loaded from cache (%d entries).", len(self._db))
                return
        except Exception as e:
            logger.debug("Cache load failed: %s", e)

        if _REQUESTS_AVAILABLE:
            try:
                self._download_and_cache()
                logger.info("OUI database downloaded (%d entries).", len(self._db))
                return
            except Exception as e:
                logger.warning("OUI download failed: %s — using built-in table.", e)

        with self._lock:
            self._db = {k.replace(":", "").upper()[:6]: v for k, v in _BUILTIN.items()}
            self._loaded = True
            logger.info("Using built-in OUI table (%d entries).", len(self._db))

    def _cache_valid(self) -> bool:
        if not _CACHE_FILE.exists():
            return False
        age = time.time() - _CACHE_FILE.stat().st_mtime
        return age < _CACHE_MAX_AGE

    def _parse_cache(self) -> None:
        db: dict[str, str] = {}
        with open(_CACHE_FILE, encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    oui  = row[0].strip().replace(":", "").replace("-", "").upper()[:6]
                    name = row[1].strip()
                    if oui and name:
                        db[oui] = name
        with self._lock:
            self._db     = db
            self._loaded = True

    def _download_and_cache(self) -> None:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        resp = _requests.get(_IEEE_OUI_URL, timeout=15, stream=True)
        resp.raise_for_status()
        raw = resp.content.decode("utf-8", errors="ignore")

        db: dict[str, str] = {}
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if len(row) >= 2:
                oui  = row[0].strip().replace(":", "").replace("-", "").upper()[:6]
                name = row[1].strip()
                if oui and name:
                    db[oui] = name

        if len(db) < 100:
            raise ValueError(f"Suspiciously small OUI database: {len(db)} entries")

        # Write cache
        with open(_CACHE_FILE, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            for oui, name in db.items():
                writer.writerow([oui, name])

        with self._lock:
            self._db     = db
            self._loaded = True

    def lookup(self, mac: str) -> str:
        """
        Look up a MAC address and return the vendor name.
        Returns 'Unknown Vendor' if not found.
        """
        try:
            oui = mac.strip().upper().replace(":", "").replace("-", "")[:6]
            with self._lock:
                return self._db.get(oui, "Unknown Vendor")
        except Exception:
            return "Unknown Vendor"

    @property
    def loaded(self) -> bool:
        with self._lock:
            return self._loaded

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._db)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_db_instance: OUIDatabase | None = None
_init_lock = threading.Lock()


def _get_db() -> OUIDatabase:
    global _db_instance
    if _db_instance is None:
        with _init_lock:
            if _db_instance is None:
                _db_instance = OUIDatabase()
    return _db_instance


def resolve_vendor(mac: str) -> str:
    """Public API — resolve a MAC address to vendor name."""
    return _get_db().lookup(mac)


def db_status() -> dict:
    """Return database status for the /api/health endpoint."""
    db = _get_db()
    return {
        "loaded":    db.loaded,
        "entries":   db.size,
        "cache_file": str(_CACHE_FILE),
    }