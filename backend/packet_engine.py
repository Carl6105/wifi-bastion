"""
packet_engine.py — Real-time 802.11 packet monitoring and deauth detection
===========================================================================
Sniffs Wi-Fi management frames in a background thread, detects
deauthentication flood attacks, and provides targeted deauth transmission
for authorised penetration testing.

⚠️  Legal notice: Monitor-mode sniffing and deauth transmission must only
    be used on networks you own or have explicit written authorisation to
    test. Unauthorised use is illegal in most jurisdictions.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("wifi_bastion.packet_engine")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Number of deauth frames within the observation window to trigger an alert
DEAUTH_ALERT_THRESHOLD: int   = 5

# Seconds of silence after which the deauth counter resets
ATTACK_WINDOW_SECONDS:  float = 30.0

# How long send_deauth() waits for scapy to be importable before giving up
_SCAPY_IMPORT_TIMEOUT:  float = 5.0

# ---------------------------------------------------------------------------
# Lazy Scapy import
# ---------------------------------------------------------------------------
# Scapy is an optional heavy dependency. We import it lazily so the rest of
# the application starts normally even if Scapy isn't installed.

def _try_import_scapy() -> tuple[Any, Any, Any] | None:
    """
    Attempt to import the Scapy symbols we need.
    Returns (sniff, Dot11Deauth, RadioTap, Dot11, sendp) or None.
    """
    try:
        from scapy.all import (          # noqa: PLC0415
            Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
            EAPOL, RadioTap, sendp, sniff,
        )
        return sniff, Dot11Deauth, RadioTap, Dot11, sendp, Dot11Beacon, Dot11Elt, EAPOL
    except ImportError:
        logger.warning(
            "Scapy is not installed — packet monitoring and deauth "
            "transmission will be unavailable.  Run: pip install scapy"
        )
        return None


# ---------------------------------------------------------------------------
# Attack state  (isolated, lock-protected)
# ---------------------------------------------------------------------------

@dataclass
class _DeauthState:
    """
    All mutable state touched by both the sniffer thread and Flask request
    threads lives here, protected by a single RLock.
    """
    count:          int   = 0
    last_seen:      float = 0.0
    attack_active:  bool  = False
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record_frame(self) -> None:
        with self._lock:
            self.count     += 1
            self.last_seen  = time.monotonic()
            self.attack_active = self.count >= DEAUTH_ALERT_THRESHOLD

    def snapshot(self) -> dict:
        """Return a consistent read of the current state."""
        with self._lock:
            now = time.monotonic()
            # Auto-expire: if the window has passed with no new frames, reset
            if self.last_seen and (now - self.last_seen) > ATTACK_WINDOW_SECONDS:
                self.count         = 0
                self.attack_active = False
            return {
                "attack_active": self.attack_active,
                "count":         self.count,
                "last_seen":     self.last_seen,      # monotonic — relative to process start
                "timestamp":     time.time(),          # wall clock for the API response
            }

    def reset(self) -> None:
        with self._lock:
            self.count         = 0
            self.last_seen     = 0.0
            self.attack_active = False


@dataclass
class _BeaconState:
    """
    Track beacon intervals per BSSID for anomaly detection.
    Legitimate APs beacon every ~100ms (100 TU). Values outside
    50–300ms are flagged as anomalous — could indicate a rogue AP
    trying to win probe responses aggressively, or a misconfigured device.
    """
    # BSSID → list of last N inter-beacon intervals (ms)
    intervals: dict = field(default_factory=dict)
    anomalies: dict = field(default_factory=dict)   # BSSID → anomaly_type
    last_seen:  dict = field(default_factory=dict)   # BSSID → last monotonic ts
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    NORMAL_MIN_MS = 50
    NORMAL_MAX_MS = 300
    HISTORY_LEN   = 10   # keep last 10 intervals per BSSID

    def record_beacon(self, bssid: str) -> str | None:
        """
        Record a beacon arrival. Returns anomaly type string or None if normal.
        """
        with self._lock:
            now = time.monotonic()
            last = self.last_seen.get(bssid)
            self.last_seen[bssid] = now

            if last is None:
                return None  # first beacon — no interval to measure

            interval_ms = (now - last) * 1000
            history = self.intervals.setdefault(bssid, [])
            history.append(interval_ms)
            if len(history) > self.HISTORY_LEN:
                history.pop(0)

            if len(history) < 3:
                return None  # need at least 3 samples

            avg = sum(history) / len(history)
            if avg < self.NORMAL_MIN_MS:
                self.anomalies[bssid] = "BEACON_FLOOD"
                return "BEACON_FLOOD"
            if avg > self.NORMAL_MAX_MS:
                self.anomalies[bssid] = "BEACON_SLOW"
                return "BEACON_SLOW"

            # Clear anomaly if back to normal
            self.anomalies.pop(bssid, None)
            return None

    def get_anomalies(self) -> dict:
        with self._lock:
            return dict(self.anomalies)


@dataclass
class _PMKIDState:
    """
    Detect PMKID captures in EAPOL frames.
    PMKID is embedded in the first EAPOL frame of a WPA2 4-way handshake.
    Its presence means an attacker can attempt offline dictionary attacks
    WITHOUT deauthenticating any client.
    """
    captures: list = field(default_factory=list)   # list of capture dicts
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record(self, bssid: str, client_mac: str) -> None:
        with self._lock:
            self.captures.append({
                "bssid":      bssid,
                "client_mac": client_mac,
                "timestamp":  time.time(),
            })
            # Keep last 50 captures
            if len(self.captures) > 50:
                self.captures.pop(0)

    def get_recent(self, since_seconds: float = 300) -> list:
        cutoff = time.time() - since_seconds
        with self._lock:
            return [c for c in self.captures if c["timestamp"] >= cutoff]


# ---------------------------------------------------------------------------
# PacketEngine
# ---------------------------------------------------------------------------

class PacketEngine:
    """
    Manages a background 802.11 packet sniffer and exposes deauth-detection
    state to the rest of the application.
    """

    def __init__(self) -> None:
        self._state        = _DeauthState()
        self._beacon_state = _BeaconState()
        self._pmkid_state  = _PMKIDState()
        self._thread:    threading.Thread | None = None
        self._stop_event = threading.Event()
        self._interface: str | None = None
        self._scapy      = _try_import_scapy()   # None if not installed

    # ------------------------------------------------------------------
    # Monitor lifecycle
    # ------------------------------------------------------------------

    @property
    def is_monitoring(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start_monitor(self, interface: str) -> None:
        """
        Start the background sniffer on *interface*.

        Idempotent — calling this when already monitoring is a no-op.
        Raises ``RuntimeError`` if Scapy is not installed.
        """
        if self._scapy is None:
            raise RuntimeError(
                "Scapy is not installed. Cannot start packet monitor."
            )
        if self.is_monitoring:
            logger.debug("Monitor already running on '%s' — ignoring.", self._interface)
            return

        self._interface  = interface
        self._stop_event.clear()
        self._state.reset()

        self._thread = threading.Thread(
            target=self._sniffer_loop,
            args=(interface,),
            name=f"pkt-sniffer-{interface}",
            daemon=True,    # Won't block process shutdown
        )
        self._thread.start()
        logger.info("Packet monitor started on interface '%s'.", interface)

    def stop_monitor(self) -> None:
        """
        Signal the sniffer thread to stop and wait for it to exit.

        Note: Scapy's ``sniff()`` doesn't expose a clean stop mechanism —
        ``stop_filter`` is the approved approach but requires a packet to
        arrive before it's evaluated.  The stop_event therefore acts as a
        soft signal; the thread exits on the next packet or on timeout.
        """
        if not self.is_monitoring:
            return
        logger.info("Stopping packet monitor.")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                logger.warning(
                    "Sniffer thread did not exit cleanly within 5 s — "
                    "it will be abandoned (daemon=True ensures process exit)."
                )
        self._thread = None

    def _sniffer_loop(self, interface: str) -> None:
        """Entry point for the sniffer daemon thread."""
        sniff_fn, *_ = self._scapy  # type: ignore[misc]
        try:
            sniff_fn(
                iface=interface,
                prn=self._process_packet,
                store=False,                    # Never buffer packets in RAM
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.error(
                "Permission denied on interface '%s'. "
                "Monitor mode requires root / administrator privileges.",
                interface,
            )
        except OSError as exc:
            logger.error(
                "OS error on interface '%s': %s — "
                "verify the interface name and that monitor mode is enabled.",
                interface, exc,
            )
        except Exception as exc:
            logger.exception("Sniffer crashed unexpectedly: %s", exc)
        finally:
            logger.info("Sniffer thread exiting for interface '%s'.", interface)

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------

    def _process_packet(self, pkt: Any) -> None:
        """
        Called by Scapy for every captured packet.
        Must be fast — this runs in the sniffer thread.
        Handles: Deauth frames, Beacon frames (interval anomaly), EAPOL (PMKID).
        """
        if self._scapy is None:
            return

        _, Dot11Deauth, _, Dot11, _, Dot11Beacon, Dot11Elt, EAPOL = self._scapy  # type: ignore

        # ── Deauth flood detection ────────────────────────────────────────
        if pkt.haslayer(Dot11Deauth):
            sender   = getattr(pkt, "addr2", "??:??:??:??:??:??")
            receiver = getattr(pkt, "addr1", "??:??:??:??:??:??")
            reason   = getattr(pkt.getlayer(Dot11Deauth), "reason", 0)
            self._state.record_frame()
            log_fn = logger.warning if self._state.attack_active else logger.debug
            log_fn("Deauth frame #%d — src=%s dst=%s reason=%d",
                   self._state.count, sender, receiver, reason)
            return

        # ── Beacon interval anomaly detection ────────────────────────────
        if pkt.haslayer(Dot11Beacon):
            bssid  = getattr(pkt, "addr3", None) or getattr(pkt, "addr2", None)
            if bssid:
                anomaly = self._beacon_state.record_beacon(bssid)
                if anomaly:
                    logger.warning("Beacon anomaly %s detected from BSSID %s", anomaly, bssid)
            return

        # ── PMKID capture detection (EAPOL frame 1 of 4-way handshake) ──
        if pkt.haslayer(EAPOL):
            try:
                eapol_layer = pkt[EAPOL]
                raw = bytes(eapol_layer)
                # PMKID is 16 bytes appended to the end of the first EAPOL frame.
                # Key Info field at offset 5 (big-endian 2 bytes).
                # We look for WPA2 key type (bit 3 = 1) and PMKID present (bit 6 = 0).
                if len(raw) >= 99:
                    key_info = int.from_bytes(raw[5:7], "big")
                    key_type   = (key_info >> 3) & 1  # 1 = pairwise
                    install    = (key_info >> 6) & 1  # 0 = first frame
                    ack        = (key_info >> 7) & 1  # 1 = AP → STA
                    if key_type == 1 and install == 0 and ack == 1:
                        bssid      = getattr(pkt, "addr2", "unknown")
                        client_mac = getattr(pkt, "addr1", "unknown")
                        # PMKID lives in the last 16 bytes of the key data
                        pmkid = raw[-16:].hex()
                        self._pmkid_state.record(bssid, client_mac)
                        logger.warning(
                            "PMKID captured — BSSID=%s Client=%s PMKID=%s",
                            bssid, client_mac, pmkid,
                        )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_alerts(self) -> dict:
        """
        Return current deauth-attack state.
        Thread-safe — may be called from any Flask request thread.
        """
        return self._state.snapshot()

    def get_beacon_anomalies(self) -> dict:
        """Return current beacon interval anomalies keyed by BSSID."""
        return self._beacon_state.get_anomalies()

    def get_pmkid_captures(self, since_seconds: float = 300) -> list:
        """Return PMKID captures from the last N seconds."""
        return self._pmkid_state.get_recent(since_seconds)

    def send_deauth(self, target_mac: str, count: int = 5) -> bool:
        """
        Transmit *count* deauthentication frames to *target_mac*.

        ⚠️  Authorised use only.  Requires monitor-mode interface and root.

        Args:
            target_mac: Target station MAC address (XX:XX:XX:XX:XX:XX).
            count:      Number of frames to send (default 5, cap 64).

        Returns:
            True on success, False on any failure.
        """
        if self._scapy is None:
            logger.error("send_deauth: Scapy not available.")
            return False

        if not self._interface:
            logger.error("send_deauth: No monitoring interface configured.")
            return False

        # Clamp count to a reasonable ceiling
        count = max(1, min(count, 64))

        _, Dot11Deauth, RadioTap, Dot11, sendp = self._scapy  # type: ignore[misc]

        try:
            frame = (
                RadioTap()
                / Dot11(addr1=target_mac, addr2="ff:ff:ff:ff:ff:ff", addr3="ff:ff:ff:ff:ff:ff")
                / Dot11Deauth(reason=7)   # reason=7: Class 3 frame received from non-associated STA
            )
            sendp(
                frame,
                iface=self._interface,
                count=count,
                inter=0.1,      # 100 ms between frames
                verbose=False,
            )
            logger.warning(
                "Deauth frames sent — target=%s count=%d interface=%s",
                target_mac, count, self._interface,
            )
            return True

        except PermissionError:
            logger.error(
                "send_deauth: Permission denied — root privileges required."
            )
            return False
        except OSError as exc:
            logger.error("send_deauth: OS error — %s", exc)
            return False
        except Exception as exc:
            logger.exception("send_deauth: Unexpected error — %s", exc)
            return False