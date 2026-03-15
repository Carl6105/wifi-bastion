"""
wifi_scanner.py — Wi-Fi network scanning and threat detection
=============================================================
Wraps pywifi to scan nearby 802.11 networks, enriches each result with
vendor info, distance estimates, and a multi-factor trust score, then
runs a suite of threat-detection checks (evil twin, MAC spoofing, weak
encryption, signal anomaly, blocklist).
"""

from __future__ import annotations

import math
import logging
import time
from collections import defaultdict
from typing import Any

try:
    import pywifi
    from pywifi import const as pywifi_const
    _PYWIFI_AVAILABLE = True
except ImportError:
    _PYWIFI_AVAILABLE = False
    logger_pre = logging.getLogger("wifi_bastion.wifi_scanner")
    logger_pre.warning("pywifi is not installed — Wi-Fi scanning will be unavailable.")

try:
    from backend.config import (
        AKM_MAPPING,
        SCAN_WAIT_TIME,
        WEAK_ENCRYPTION_TYPES,
        SIGNAL_ANOMALY_THRESHOLD,
    )
except ImportError:
    from config import (                            # type: ignore
        AKM_MAPPING,
        SCAN_WAIT_TIME,
        WEAK_ENCRYPTION_TYPES,
        SIGNAL_ANOMALY_THRESHOLD,
    )

logger = logging.getLogger("wifi_bastion.wifi_scanner")

# Try to use the full IEEE OUI database; fall back to built-in table
try:
    from backend.oui_lookup import resolve_vendor as _resolve_vendor
except ImportError:
    try:
        from oui_lookup import resolve_vendor as _resolve_vendor  # type: ignore
    except ImportError:
        _resolve_vendor = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Path-loss model constants for indoor distance estimation
# Reference power at 1 m (dBm) and path-loss exponent
_FRIIS_REF_POWER: float = -30.0
_FRIIS_PATH_LOSS: float = 2.7

# ── Threat scoring weights ──────────────────────────────────────────────────
# Score starts at 100. Each factor deducts points.
# Design: encryption is the baseline, threats are additive penalties.
# Max realistic score: WPA3 with no threats = 100
# Min: Open network with active attack = 0

# Encryption deductions (mutually exclusive — strongest wins)
_ENC_DEDUCTIONS: dict[str, int] = {
    "WPA3-ENTERPRISE": 0,
    "WPA3":            0,
    "WPA3-PSK":        0,
    "WPA2/WPA3":       5,   # Transition mode — slightly weaker
    "WPA2-ENTERPRISE": 5,
    "WPA2":            12,
    "WPA2-PSK":        12,
    "WPA":             40,
    "WEP":             60,  # WEP is trivially broken — near-zero trust
    "OPEN":            70,  # Open network — no confidentiality at all
}

# Threat deductions (cumulative, capped at max 80 total from threats)
_THREAT_DEDUCTIONS: dict[str, int] = {
    "EVIL_TWIN":   45,  # Active attack — highest weight
    "DEAUTH":      40,  # Active attack
    "MAC_SPOOF":   35,  # Active attack
    "ARP_SPOOF":   35,  # Active attack
    "BLOCKED":     80,  # User-marked dangerous — nearly zeroed
    "SIGNAL":      20,  # Suspicious signal variance
    "HIDDEN":      10,  # Hidden SSID — minor suspicion only
    "WEAK":        15,  # Weak encryption (already penalised above but add threat flag)
}

# Signal quality bonus/penalty — good signal = slightly higher trust
# (strong signal from expected direction is harder to spoof convincingly)
def _signal_adjustment(signal_dbm: int | None) -> int:
    """Return a small adjustment (-5 to +5) based on signal strength."""
    if signal_dbm is None:
        return 0
    if signal_dbm >= -50:    return 3   # Excellent — likely legitimate nearby AP
    if signal_dbm >= -65:    return 1   # Good
    if signal_dbm >= -80:    return 0   # Fair
    if signal_dbm >= -90:    return -2  # Weak — harder to trust
    return -5                           # Very weak — suspicious

# Number of MAC prefix octets to compare for evil-twin detection
# 4 octets (first half of the MAC) is a reasonable heuristic —
# legitimate AP chains share OUI (3 octets); spoofed twins often differ earlier
_EVIL_TWIN_PREFIX_LEN = 13   # "aa:bb:cc:dd" — 4 octets in colon notation


# ---------------------------------------------------------------------------
# Vendor lookup (OUI → manufacturer)
# ---------------------------------------------------------------------------

# Inline OUI table for offline use.  For a production system, replace or
# supplement this with a lookup against https://maclookup.app/api or
# the ieee-data package (pip install netaddr).
_OUI_TABLE: dict[str, str] = {
    # TP-Link
    "f0:ed:b8": "TP-Link",
    "b4:a7:c6": "TP-Link",
    "f2:ed:b8": "TP-Link (Virtual)",
    "50:c7:bf": "TP-Link",
    "98:da:c4": "TP-Link",
    # Netgear
    "a0:04:60": "Netgear",
    "c0:ff:d4": "Netgear",
    "28:c6:8e": "Netgear",
    # Asus
    "00:0c:6e": "Asus",
    "04:d4:c4": "Asus",
    "2c:56:dc": "Asus",
    # Cisco / Linksys
    "04:25:e0": "Cisco",
    "00:1a:2b": "Cisco",
    "68:86:a7": "Cisco",
    # D-Link
    "14:d6:4d": "D-Link",
    "1c:7e:e5": "D-Link",
    # Apple
    "a8:da:0c": "Apple",
    "f4:f1:5a": "Apple",
    "3c:22:fb": "Apple",
    # Samsung
    "9c:53:22": "Samsung",
    "f4:42:8f": "Samsung",
    # JioFiber
    "8c:a3:99": "JioFiber",
    "44:e9:dd": "JioFiber",
    # Huawei
    "00:46:4b": "Huawei",
    "54:89:98": "Huawei",
    # Xiaomi / Mi
    "00:9e:c8": "Xiaomi",
    "34:ce:00": "Xiaomi",
    # Google (Nest WiFi)
    "f4:f5:d8": "Google",
    "54:60:09": "Google",
    # Eero
    "f4:f9:51": "Eero",
}


def _lookup_vendor(bssid: str) -> str:
    """
    Resolve a BSSID to a manufacturer name.
    Uses the full IEEE OUI database if oui_lookup is available,
    otherwise falls back to the built-in _OUI_TABLE.
    """
    if _resolve_vendor is not None:
        try:
            result = _resolve_vendor(bssid)
            if result and result != "Unknown Vendor":
                return result
        except Exception:
            pass
    # Built-in fallback
    try:
        normalised = bssid.strip().lower().replace("-", ":")
        oui = normalised[:8]
        return _OUI_TABLE.get(oui, "Unknown Vendor")
    except (AttributeError, IndexError):
        return "Unknown Vendor"


# ---------------------------------------------------------------------------
# Signal / distance helpers
# ---------------------------------------------------------------------------

def _parse_signal_dbm(signal: Any) -> int | None:
    """
    Safely extract an integer dBm value from pywifi's signal attribute.

    pywifi returns signal as a plain int on most platforms, but some builds
    return strings like '-72 dBm'.  Both are handled here.
    """
    if isinstance(signal, int):
        return signal
    if isinstance(signal, float):
        return int(signal)
    if isinstance(signal, str):
        try:
            return int(signal.split()[0])
        except (ValueError, IndexError):
            pass
    logger.debug("Could not parse signal value: %r", signal)
    return None


# ---------------------------------------------------------------------------
# Channel / band helpers
# ---------------------------------------------------------------------------

def _channel_to_band(channel: int | None) -> str:
    """Return human-readable band for a channel number."""
    if channel is None:
        return "Unknown"
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel >= 1 and channel <= 233:
        return "6 GHz"
    return "Unknown"


def _netsh_channel_map() -> dict[str, dict]:
    """
    Parse ``netsh wlan show networks mode=bssid`` on Windows.

    Returns {bssid_lower: {channel, band, radio, signal_pct}}.

    Diagnostic findings:
      - BSSID lines ARE indented: "    BSSID 1 : aa:bb:cc:dd:ee:ff"
        After .strip() -> "BSSID 1 : ..." so startswith works fine
      - Windows netsh has a "Band" field: "Band : 2.4 GHz" - read directly
      - "Channel Utilization" also contains "channel" - must exact-match label
    """
    import platform
    import subprocess
    import re as _re

    if platform.system() != "Windows":
        return {}

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            shell=False,
            capture_output=True,
            timeout=15,
        )
        raw_out = result.stdout
        text = None
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                text = raw_out.decode(enc)
                break
            except Exception:
                continue
        if text is None:
            return {}
    except Exception as exc:
        logger.debug("netsh channel scan failed: %s", exc)
        return {}

    channel_map = {}
    current_bssid = None
    _mac_re = _re.compile("[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # "    BSSID 1                 : aa:bb:cc:dd:ee:ff"
        # After strip() -> "BSSID 1 : aa:bb:cc:dd:ee:ff"
        if line.upper().startswith("BSSID") and ":" in line:
            m = _mac_re.search(line)
            if m:
                current_bssid = m.group(0).lower()
                channel_map.setdefault(current_bssid, {})
            continue

        if current_bssid is None:
            continue

        # All remaining fields use "Label : Value" format
        if ":" not in line:
            continue

        label, _, value = line.partition(":")
        label_clean = label.strip().lower()
        value_clean = value.strip()

        # Exact label "channel" — skips "channel utilization"
        if label_clean == "channel":
            try:
                channel_map[current_bssid]["channel"] = int(value_clean)
            except (ValueError, TypeError):
                pass
            continue

        # "band : 2.4 GHz"  — read directly, no computation needed
        if label_clean == "band":
            channel_map[current_bssid]["band"] = value_clean
            continue

        if label_clean == "radio type":
            channel_map[current_bssid]["radio"] = value_clean
            continue

        if label_clean == "signal":
            try:
                channel_map[current_bssid]["signal_pct"] = int(
                    value_clean.replace("%", "").strip()
                )
            except (ValueError, TypeError):
                pass
            continue

    logger.debug("netsh channel map: %d BSSID(s) parsed.", len(channel_map))
    return channel_map


def _estimate_distance(signal_dbm: int) -> float | str:
    """
    Estimate physical distance (metres) from RSSI using the log-distance
    path-loss model:

        d = 10 ^ ((P_ref - RSSI) / (10 * n))

    where P_ref is the reference power at 1 m and n is the path-loss exponent.
    Both are set for typical indoor environments.

    Returns a rounded float or 'N/A' if the input is nonsensical.
    """
    if signal_dbm >= 0:
        # Positive dBm values are physically impossible for received power
        return "N/A"
    try:
        distance = 10 ** ((_FRIIS_REF_POWER - signal_dbm) / (10 * _FRIIS_PATH_LOSS))
        return round(distance, 1)
    except (ValueError, ZeroDivisionError):
        return "N/A"


# ---------------------------------------------------------------------------
# Trust scoring
# ---------------------------------------------------------------------------

def _calculate_trust_score(net: dict) -> int:
    """
    Multi-factor 0–100 trust score.

    Factors (in order of weight):
    1. Encryption strength  — baseline, mutually exclusive
    2. Active threats       — cumulative deductions, capped at 80
    3. Signal quality       — small adjustment (-5 to +5)

    Returns an integer in [0, 100].
    """
    score = 100
    enc   = net.get("encryption", "").upper()

    # ── 1. Encryption deduction ────────────────────────────────────────────
    # Match longest key first (WPA2-ENTERPRISE before WPA2, etc.)
    enc_deduction = _ENC_DEDUCTIONS["OPEN"]  # default: open
    for enc_key, deduction in sorted(_ENC_DEDUCTIONS.items(), key=lambda x: -len(x[0])):
        if enc_key in enc:
            enc_deduction = deduction
            break
    score -= enc_deduction

    # ── 2. Threat deductions (cumulative, total capped at 80) ──────────────
    threat_total = 0
    for threat in net.get("threats", []):
        t = threat.upper()
        deduction = 0
        if "EVIL TWIN" in t or "EVIL_TWIN" in t:
            deduction = _THREAT_DEDUCTIONS["EVIL_TWIN"]
        elif "DEAUTH" in t:
            deduction = _THREAT_DEDUCTIONS["DEAUTH"]
        elif "MAC SPOOF" in t or "MAC_SPOOF" in t:
            deduction = _THREAT_DEDUCTIONS["MAC_SPOOF"]
        elif "ARP SPOOF" in t or "ARP_SPOOF" in t:
            deduction = _THREAT_DEDUCTIONS["ARP_SPOOF"]
        elif "BLOCK" in t:
            deduction = _THREAT_DEDUCTIONS["BLOCKED"]
        elif "SIGNAL ANOMALY" in t or "SIGNAL_ANOMALY" in t:
            deduction = _THREAT_DEDUCTIONS["SIGNAL"]
        elif "HIDDEN" in t:
            deduction = _THREAT_DEDUCTIONS["HIDDEN"]
        elif "WEAK" in t:
            deduction = _THREAT_DEDUCTIONS["WEAK"]
        threat_total = min(threat_total + deduction, 80)  # cap at 80

    score -= threat_total

    # ── 3. Signal quality adjustment ──────────────────────────────────────
    score += _signal_adjustment(net.get("signal"))

    return max(0, min(100, score))


def _trust_rating(score: int) -> str:
    if score >= 80:
        return "Safe"
    if score >= 50:
        return "Warning"
    return "Danger"


# ---------------------------------------------------------------------------
# WiFiScanner
# ---------------------------------------------------------------------------

class WiFiScanner:
    """
    Wraps pywifi to scan nearby 802.11 networks and run threat detection.

    Args:
        db_manager: Optional DatabaseManager instance for blocklist lookups.
    """

    def __init__(self, db_manager: Any = None) -> None:
        self.db_manager = db_manager
        self.interface  = None

        if not _PYWIFI_AVAILABLE:
            logger.error(
                "pywifi is not installed.  "
                "Run: pip install pywifi  (Windows/Linux only)"
            )
            return

        try:
            wifi       = pywifi.PyWiFi()
            interfaces = wifi.interfaces()
            if not interfaces:
                raise RuntimeError("No Wi-Fi interfaces found on this machine.")
            self.interface = interfaces[0]
            logger.info("Wi-Fi scanner ready — interface: %s", self.interface.name())
        except Exception as exc:
            logger.error("Failed to initialise Wi-Fi scanner: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_networks(self) -> list[dict]:
        """
        Trigger a scan, wait for results, enrich each network, and run
        threat detection.

        Returns a list of network dicts (empty on failure).
        """
        if self.interface is None:
            logger.error("scan_networks called but no interface is available.")
            return []

        try:
            self.interface.scan()
            logger.info("Scan triggered — waiting %d s for results.", SCAN_WAIT_TIME)
            time.sleep(SCAN_WAIT_TIME)
            raw_results = self.interface.scan_results()
        except Exception as exc:
            logger.error("Scan failed: %s", exc)
            return []

        # De-duplicate by BSSID — keep the entry with the strongest signal
        # pywifi on Windows appends a trailing colon to every BSSID e.g.
        # "f2:ed:b8:1e:62:4a:" — strip it so lookups against netsh work.
        unique: dict[str, Any] = {}
        for network in raw_results:
            bssid = getattr(network, "bssid", None)
            if not bssid:
                continue
            bssid = bssid.strip().rstrip(":")   # strip trailing colon
            existing = unique.get(bssid)
            sig_new = _parse_signal_dbm(getattr(network, "signal", None))
            sig_old = _parse_signal_dbm(getattr(existing, "signal", None)) if existing else None

            if existing is None or (sig_new is not None and (sig_old is None or sig_new > sig_old)):
                unique[bssid] = network

        networks: list[dict] = []
        for bssid, network in unique.items():
            ssid_raw = getattr(network, "ssid", "").strip()
            signal_raw = getattr(network, "signal", None)
            signal_dbm = _parse_signal_dbm(signal_raw)

            net_info: dict = {
                "ssid":       ssid_raw if ssid_raw else "Hidden Network",
                "bssid":      bssid,
                "signal":     signal_dbm,
                "channel":    None,   # enriched below via netsh
                "band":       "Unknown",
                "encryption": self._get_encryption_type(network),
                "timestamp":  time.time(),
                "vendor":     _lookup_vendor(bssid),
                "distance":   _estimate_distance(signal_dbm) if signal_dbm is not None else "N/A",
            }
            networks.append(net_info)

        logger.info("Raw scan complete — %d unique network(s) found.", len(networks))

        # Enrich channel/band data from netsh (Windows only).
        # pywifi does not expose channel/frequency on Windows — netsh is authoritative.
        try:
            ch_map = _netsh_channel_map()
            if ch_map:
                for net in networks:
                    # Normalise: strip trailing colon pywifi sometimes adds
                    key = net["bssid"].lower().rstrip(":")
                    info = ch_map.get(key, {})
                    if info.get("channel"):
                        net["channel"] = info["channel"]
                        net["band"]    = info.get("band", _channel_to_band(info["channel"]))
                    if info.get("radio"):
                        net["radio_type"] = info["radio"]
                logger.debug("Channel enrichment applied to %d networks.", len(networks))
        except Exception as exc:
            logger.warning("Channel enrichment failed: %s", exc)

        return self._detect_threats(networks)

    # ------------------------------------------------------------------
    # Encryption detection
    # ------------------------------------------------------------------

    def _get_encryption_type(self, network: Any) -> str:
        """Map pywifi's AKM integer to a human-readable encryption label."""
        try:
            akm_list = getattr(network, "akm", [])
            if akm_list:
                akm_value = akm_list[0]
                return AKM_MAPPING.get(akm_value, f"Unknown (AKM {akm_value})")
        except Exception as exc:
            logger.warning("Could not determine encryption type: %s", exc)
        return "Unknown"

    # ------------------------------------------------------------------
    # Threat detection
    # ------------------------------------------------------------------

    def _detect_threats(self, networks: list[dict]) -> list[dict]:
        """
        Run all threat-detection checks across the full list of scanned networks.

        Checks performed:
          1. Blocklist membership
          2. Evil Twin (same SSID, different OUI)
          3. MAC Spoofing (same BSSID claimed by multiple records)
          4. Weak / open encryption
          5. Hidden SSID
          6. Signal anomaly (same SSID, wildly different signal levels)
        """
        # Build SSID and BSSID lookup maps upfront
        ssid_map:  dict[str, list[dict]] = defaultdict(list)
        bssid_map: dict[str, list[dict]] = defaultdict(list)
        for net in networks:
            ssid_map[net["ssid"]].append(net)
            bssid_map[net["bssid"]].append(net)

        # Fetch blocklist, whitelist, notes and settings once per scan
        blocked_bssids:   set[str]  = set()
        whitelisted_bssids: set[str] = set()
        notes_map:          dict     = {}
        auto_block          = False
        auto_block_threshold = 20

        if self.db_manager:
            try:
                success, blocked_data = self.db_manager.get_blocked_networks()
                if success and isinstance(blocked_data, list):
                    blocked_bssids = {
                        item["bssid"].lower()
                        for item in blocked_data
                        if item.get("bssid")
                    }
            except Exception as exc:
                logger.warning("Could not load blocklist: %s", exc)

            try:
                whitelisted_bssids = self.db_manager.get_whitelisted_bssids()
            except Exception as exc:
                logger.warning("Could not load whitelist: %s", exc)

            try:
                notes_map = self.db_manager.get_network_notes()
            except Exception as exc:
                logger.warning("Could not load notes: %s", exc)

            try:
                settings = self.db_manager.get_settings()
                auto_block           = settings.get("auto_block_evil_twin", False)
                auto_block_threshold = settings.get("auto_block_threshold", 20)
            except Exception as exc:
                logger.warning("Could not load settings: %s", exc)

        for net in networks:
            threats: list[str] = []
            ssid  = net["ssid"]
            bssid = net["bssid"].lower()

            # ---- 1. Blocklist -----------------------------------------------
            if bssid in blocked_bssids:
                threats.append("Network Blocked")

            # ---- 2. Evil Twin -----------------------------------------------
            # Heuristic: same SSID, different OUI = likely rogue clone.
            # We use a 3-stage check to reduce false positives:
            #   a) Must have 2+ networks with same SSID
            #   b) BSSIDs must differ in their OUI (first 3 octets)
            #   c) Encryption type mismatch on same SSID = strong indicator
            siblings = ssid_map[ssid]
            if len(siblings) > 1:
                for other in siblings:
                    if other["bssid"] == net["bssid"]:
                        continue
                    my_oui    = net["bssid"].lower()[:8]    # aa:bb:cc
                    other_oui = other["bssid"].lower()[:8]
                    oui_mismatch = my_oui != other_oui
                    enc_mismatch = net.get("encryption", "") != other.get("encryption", "")

                    # Both OUI mismatch AND encryption mismatch = high confidence
                    if oui_mismatch and enc_mismatch:
                        threats.append("Evil Twin Attack Detected")
                        break
                    # OUI mismatch alone — lower confidence, still flag
                    if oui_mismatch:
                        threats.append("Suspected Evil Twin")
                        break

            # ---- 3. MAC Spoofing --------------------------------------------
            if len(bssid_map[net["bssid"]]) > 1:
                threats.append("MAC Spoofing Detected")

            # ---- 4. Weak / open encryption ----------------------------------
            enc = net.get("encryption", "")
            if enc in WEAK_ENCRYPTION_TYPES:
                threats.append("Weak Encryption")

            # ---- 5. WEP specifically — extra flag (critically broken) ------
            if "WEP" in enc.upper():
                threats.append("WEP Encryption (Critically Weak)")

            # ---- 6. Hidden SSID ---------------------------------------------
            if net["ssid"] == "Hidden Network":
                threats.append("Hidden SSID Detected")

            # ---- 7. Signal anomaly ------------------------------------------
            # Same SSID seen at wildly different signal levels = suspicious.
            # A real AP at a fixed location has consistent signal strength.
            if len(siblings) > 1:
                signals = [
                    s["signal"] for s in siblings
                    if isinstance(s.get("signal"), int)
                ]
                if len(signals) >= 2:
                    spread = max(signals) - min(signals)
                    if spread > SIGNAL_ANOMALY_THRESHOLD:
                        threats.append("Signal Anomaly Detected")

            # ---- 8. Vendor anomaly ------------------------------------------
            # If a network claims to be from a known infrastructure vendor
            # but has weak/open encryption, that's unusual.
            vendor = (net.get("vendor") or "").upper()
            infra_vendors = {"CISCO", "NETGEAR", "ASUS", "TP-LINK", "UBIQUITI"}
            is_infra = any(v in vendor for v in infra_vendors)
            if is_infra and enc in WEAK_ENCRYPTION_TYPES:
                threats.append("Enterprise Vendor with Weak Encryption")

            # ---- 9. Whitelist check — trusted networks skip threat alerts ------
            if bssid in whitelisted_bssids:
                threats = []   # clear all threats for trusted network
                net["whitelisted"] = True
            else:
                net["whitelisted"] = False

            # ---- Attach notes/tag -----------------------------------------
            note_data = notes_map.get(bssid) or notes_map.get(net["bssid"]) or {}
            net["note"] = note_data.get("note", "")
            net["tag"]  = note_data.get("tag", "")

            # ---- Finalise ---------------------------------------------------
            net["threats"]     = threats
            net["is_safe"]     = len(threats) == 0
            net["trust_score"] = _calculate_trust_score(net)
            net["rating"]      = _trust_rating(net["trust_score"])

            # ---- Auto-block Evil Twin ---------------------------------------
            if (auto_block
                    and not net["whitelisted"]
                    and net["trust_score"] <= auto_block_threshold
                    and any("Evil Twin" in t for t in threats)):
                logger.warning(
                    "AUTO-BLOCK triggered for %s (score=%d, threats=%s)",
                    net["ssid"], net["trust_score"], threats,
                )
                if self.db_manager:
                    try:
                        self.db_manager.block_network(
                            network_id=net.get("_id"),
                            bssid=net["bssid"],
                            ssid=net["ssid"],
                        )
                        net["auto_blocked"] = True
                    except Exception as exc:
                        logger.error("Auto-block failed: %s", exc)

        logger.info(
            "Threat detection complete — %d network(s), %d with threats.",
            len(networks),
            sum(1 for n in networks if not n["is_safe"]),
        )
        return networks