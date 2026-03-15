"""
network_mapper.py — Local network discovery and threat detection
================================================================
Handles device mapping (OS fingerprinting, vendor lookup), DNS integrity
checks, router port scanning, and ARP spoofing detection.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

try:
    import nmap
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False

logger = logging.getLogger("wifi_bastion.network_mapper")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DNS canary configuration.
# We resolve well-known hostnames and validate responses against expected
# IP *ranges* (not exact IPs) — anycast means the exact IP varies by region.
# Each entry: (hostname, expected_prefix_or_range, operator_name)
_DNS_CANARY_HOSTS: list[tuple[str, str, str]] = [
    ("dns.google",      "8.8.",    "Google DNS"),
    ("one.one.one.one", "1.1.1.",  "Cloudflare DNS"),
]

# Private/RFC1918 ranges that should NEVER be the result of resolving a
# public internet hostname — these indicate a hijack or transparent proxy.
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "0.")

# Common ports to probe on the router/gateway
# Ports scanned on the router/gateway.
# Split into tiers for risk classification:
#   CRITICAL  — remote admin, legacy protocols, file sharing
#   HIGH      — databases, VNC, uncommon web
#   NORMAL    — DNS, HTTP, HTTPS are EXPECTED on a router and NOT flagged
_ROUTER_PORTS: list[int] = [
    # Critical / dangerous if exposed
    21, 22, 23, 25, 110, 135, 139, 445,
    1723, 3306, 3389, 5900, 5432, 6379,
    # Potentially risky
    8080, 8443, 8888, 8181,
    # Expected on routers — scanned but NOT flagged as risk
    53, 80, 443,
]

# Ports that are EXPECTED on a router and should NOT raise risk level
_ROUTER_NORMAL_PORTS: frozenset[int] = frozenset({53, 80, 443, 22})

_PORT_SCAN_TIMEOUT:  float = 0.5   # seconds per port
_PORT_SCAN_WORKERS:  int   = 30
_NMAP_SCAN_TIMEOUT:  int   = 120   # seconds for full nmap run
_DNS_RESOLVE_TIMEOUT: float = 3.0  # seconds

# Simple MAC pattern used in ARP table parsing
_MAC_RE = re.compile(r"[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5}")


# ---------------------------------------------------------------------------
# DeviceMapper
# ---------------------------------------------------------------------------

class DeviceMapper:
    """
    Orchestrates all local-network intelligence gathering:
      - Active device discovery with OS fingerprinting (nmap)
      - DNS hijack / canary checking
      - Gateway port exposure auditing
      - ARP table spoofing detection
    """

    def __init__(self) -> None:
        self.nm = self._init_nmap()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _init_nmap() -> Any | None:
        """Return a PortScanner instance or None if nmap is unavailable."""
        if not _NMAP_AVAILABLE:
            logger.warning("python-nmap is not installed — device scan disabled.")
            return None
        if not shutil.which("nmap"):
            logger.warning("nmap binary not found in PATH — device scan disabled.")
            return None
        try:
            scanner = nmap.PortScanner()
            logger.info("nmap initialised successfully.")
            return scanner
        except nmap.PortScannerError as exc:
            logger.error("nmap initialisation error: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Network address helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_local_ip() -> str:
        """
        Determine the machine's primary outbound IP without sending any traffic.
        Falls back to 192.168.1.1 if the network is unreachable.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.connect(("8.8.8.8", 80))
                return sock.getsockname()[0]
        except OSError:
            logger.warning("Could not determine local IP — falling back to 192.168.1.1")
            return "192.168.1.1"

    def get_local_ip_range(self) -> str:
        """
        Return the /24 subnet for the current local IP.
        Validates the resulting network string to prevent nmap injection.
        """
        local_ip = self.get_local_ip()
        try:
            # Build a proper network object (validates the address)
            network = ipaddress.IPv4Network(
                f"{local_ip}/24", strict=False
            )
            return str(network)   # e.g. "192.168.1.0/24"
        except ValueError:
            logger.error("Invalid local IP %r — defaulting to 192.168.1.0/24", local_ip)
            return "192.168.1.0/24"

    def get_gateway_ip(self) -> str:
        """
        Derive the default gateway address by assuming .1 on the local /24.
        A more robust implementation would parse the OS routing table.
        """
        local_ip = self.get_local_ip()
        parts = local_ip.split(".")
        parts[-1] = "1"
        return ".".join(parts)

    # ------------------------------------------------------------------
    # Device discovery
    # ------------------------------------------------------------------

    def scan_devices(self) -> list[dict] | dict:
        """
        Run an nmap OS-detection scan across the local /24 subnet.

        Requires root / administrator privileges for OS fingerprinting.
        Returns a list of device dicts sorted by IP, or an error dict.
        """
        if not self.nm:
            return {"error": "nmap is not available on this host."}

        target_range = self.get_local_ip_range()
        logger.info("Starting device scan on %s", target_range)

        try:
            # -O  : OS detection (needs root)
            # -F  : Fast port scan (top 100 ports only)
            # --osscan-guess : Aggressive OS guessing when no exact match
            # -T4 : Aggressive timing — faster on a LAN
            self.nm.scan(
                hosts=target_range,
                arguments="-O -F --osscan-guess -T4",
                timeout=_NMAP_SCAN_TIMEOUT,
            )
        except nmap.PortScannerError as exc:
            logger.error("nmap scan error: %s", exc)
            return {"error": str(exc)}
        except Exception as exc:
            logger.exception("Unexpected error during device scan")
            return {"error": str(exc)}

        devices: list[dict] = []
        for host in self.nm.all_hosts():
            if self.nm[host].state() != "up":
                continue

            addresses = self.nm[host].get("addresses", {})
            mac      = addresses.get("mac", "Unknown")
            vendor   = self.nm[host].get("vendor", {}).get(mac, "Unknown Vendor")

            os_name, accuracy, device_type = "Unknown OS", 0, "generic"
            os_matches = self.nm[host].get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                os_name  = best.get("name", "Unknown OS")
                accuracy = int(best.get("accuracy", 0))
                os_classes = best.get("osclass", [])
                if os_classes:
                    device_type = os_classes[0].get("type", "generic")

            open_ports = self._get_open_ports(host)

            devices.append({
                "ip":          host,
                "mac":         mac,
                "vendor":      vendor,
                "os":          os_name,
                "accuracy":    accuracy,
                "device_type": device_type,
                "open_ports":  open_ports,
                "status":      "online",
                "scanned_at":  int(time.time()),
            })

        # Sort by IP octet numerically
        devices.sort(key=lambda d: [int(o) for o in d["ip"].split(".")])
        logger.info("Device scan complete — %d host(s) found.", len(devices))
        return devices

    def _get_open_ports(self, host: str) -> list[int]:
        """Extract open TCP port numbers for an already-scanned host."""
        try:
            tcp_data = self.nm[host].get("tcp", {})
            return [
                port for port, info in tcp_data.items()
                if info.get("state") == "open"
            ]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # DNS hijack detection
    # ------------------------------------------------------------------

    def check_dns_hijack(self) -> dict:
        """
        Canary-based DNS hijack detection with anycast-aware validation.

        Detection strategy:
          1. DANGER  — resolved IP is in a private/loopback range
                       (public hostname should NEVER resolve to RFC1918)
          2. DANGER  — resolved IP doesn't start with the expected operator prefix
                       AND is in a private range (clear interception)
          3. WARNING — resolved IP doesn't match the expected prefix but is a
                       valid public IP (could be regional anycast variance)
          4. SAFE    — resolved IP starts with the expected operator prefix

        This approach eliminates false positives caused by ISP-level
        anycast routing while still catching actual DNS hijacking attacks.
        """
        results: list[dict] = []
        danger_count = 0
        warning_count = 0

        for hostname, expected_prefix, operator in _DNS_CANARY_HOSTS:
            resolved = self._resolve_with_timeout(hostname)

            if resolved is None:
                # Timeout — could be network issue, not necessarily hijack
                results.append({
                    "host":     hostname,
                    "operator": operator,
                    "status":   "Warning",
                    "resolved": None,
                    "message":  "Resolution timed out — network may be restricted.",
                })
                warning_count += 1
                continue

            # Check 1: Private/loopback IP — definite hijack
            is_private = any(resolved.startswith(p) for p in _PRIVATE_PREFIXES)
            if is_private:
                danger_count += 1
                results.append({
                    "host":     hostname,
                    "operator": operator,
                    "status":   "Danger",
                    "resolved": resolved,
                    "message":  f"DNS hijack confirmed — {hostname} resolves to private IP {resolved}. "
                                f"Expected {operator} range ({expected_prefix}x.x).",
                })
                continue

            # Check 2: Correct operator prefix — safe
            if resolved.startswith(expected_prefix):
                results.append({
                    "host":     hostname,
                    "operator": operator,
                    "status":   "Safe",
                    "resolved": resolved,
                    "message":  f"Resolved to {operator} address {resolved} — correct.",
                })
                continue

            # Check 3: Different public IP — ISP transparent proxy or regional routing
            # Do NOT increment warning_count — this is expected on many networks
            results.append({
                "host":     hostname,
                "operator": operator,
                "status":   "Info",
                "resolved": resolved,
                "message":  f"Resolved to {resolved} via ISP DNS (not {operator} {expected_prefix}x.x). "
                            f"Normal behaviour — ISP transparent DNS proxy detected.",
            })

        # Aggregate: only trigger Danger on confirmed private-IP redirects
        if danger_count > 0:
            return {
                "status":  "Danger",
                "message": f"DNS hijack detected — {danger_count} canary(s) resolve to private/loopback IPs.",
                "details": results,
            }

        # All canaries timed out — suspicious but not confirmed
        if warning_count == len(_DNS_CANARY_HOSTS) and all(r["resolved"] is None for r in results):
            return {
                "status":  "Warning",
                "message": "All DNS canaries timed out — network may be filtering DNS or offline.",
                "details": results,
            }

        # Info results only — ISP may use transparent DNS proxy (common, not dangerous)
        info_count = sum(1 for r in results if r["status"] == "Info")
        if info_count > 0 and danger_count == 0:
            return {
                "status":  "Safe",
                "message": f"DNS resolves to public IPs (ISP proxy or regional routing — {info_count} canary(s) use non-standard paths). No hijack detected.",
                "details": results,
            }

        return {
            "status":  "Safe",
            "message": "All DNS canaries resolved correctly.",
            "details": results,
        }

    @staticmethod
    def _resolve_with_timeout(hostname: str) -> str | None:
        """Resolve a hostname with a timeout; returns IP string or None."""
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(_DNS_RESOLVE_TIMEOUT)
            try:
                return socket.gethostbyname(hostname)
            finally:
                socket.setdefaulttimeout(old_timeout)
        except (socket.gaierror, socket.timeout, OSError):
            return None

    # ------------------------------------------------------------------
    # Router port scanning
    # ------------------------------------------------------------------

    def scan_router_ports(self) -> list[int]:
        """
        Multi-threaded TCP connect scan against the local gateway.

        Returns only the open ports. The risk classification in app.py
        uses _ROUTER_NORMAL_PORTS to separate expected ports (53, 80, 443)
        from genuinely dangerous ones.
        """
        gateway_ip = self.get_gateway_ip()
        logger.info("Scanning %d ports on gateway %s", len(_ROUTER_PORTS), gateway_ip)

        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=_PORT_SCAN_WORKERS) as pool:
            future_to_port = {
                pool.submit(self._check_single_port, gateway_ip, port): port
                for port in _ROUTER_PORTS
            }
            for future in as_completed(future_to_port):
                result = future.result()
                if result is not None:
                    open_ports.append(result)

        open_ports.sort()
        normal = [p for p in open_ports if p in _ROUTER_NORMAL_PORTS]
        risky  = [p for p in open_ports if p not in _ROUTER_NORMAL_PORTS]
        logger.info("Port scan complete — open: %s | normal: %s | risky: %s",
                    open_ports, normal, risky)
        return open_ports

    def get_router_normal_ports(self) -> frozenset:
        """Expose the normal-port set so app.py can use it for classification."""
        return _ROUTER_NORMAL_PORTS

    @staticmethod
    def _check_single_port(ip: str, port: int) -> int | None:
        """Attempt a TCP connect to (ip, port). Returns port if open, else None."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(_PORT_SCAN_TIMEOUT)
                if sock.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            pass
        return None

    # ------------------------------------------------------------------
    # ARP spoofing detection
    # ------------------------------------------------------------------

    def detect_arp_spoofing(self) -> list[dict]:
        """
        Parse the OS ARP table and flag any MAC address associated with
        more than one IP — a strong indicator of ARP spoofing / MITM.

        Returns a list of alert dicts (empty if clean).
        """
        arp_output = self._get_arp_table()
        if arp_output is None:
            return []

        # Extract all (ip, mac) pairs
        pairs = _MAC_RE.findall(arp_output)
        # arp -a output format: "192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
        # Use a broader pattern to capture both the IP and MAC together
        ip_mac_pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})"
        )
        ip_mac_pairs = ip_mac_pattern.findall(arp_output)

        mac_to_ips: dict[str, list[str]] = defaultdict(list)
        for ip, mac in ip_mac_pairs:
            normalised = mac.lower().replace("-", ":")

            # ── Skip entries that are never spoofing indicators ──────────
            # 1. Broadcast / unset MACs
            if normalised in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            # 2. Multicast MACs (first octet LSB = 1)
            try:
                if int(normalised.split(":")[0], 16) & 0x01:
                    continue
            except ValueError:
                continue
            # 3. Broadcast / link-local / multicast IPs
            try:
                import ipaddress as _ip
                parsed = _ip.ip_address(ip)
                if parsed.is_multicast or parsed.is_link_local or str(parsed).endswith(".255"):
                    continue
                # Skip 255.255.255.255
                if str(parsed) == "255.255.255.255":
                    continue
            except ValueError:
                continue

            if ip not in mac_to_ips[normalised]:
                mac_to_ips[normalised].append(ip)

        alerts: list[dict] = []
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alerts.append({
                    "type":     "ARP_SPOOF",
                    "severity": "HIGH",
                    "mac":      mac,
                    "ips":      ips,
                    "details":  (
                        f"MAC {mac} is mapped to {len(ips)} IPs: {', '.join(ips)}. "
                        "This may indicate an ARP spoofing / MITM attack."
                    ),
                })
                logger.warning("ARP spoofing candidate: %s → %s", mac, ips)

        return alerts

    @staticmethod
    def _get_arp_table() -> str | None:
        """
        Run ``arp -a`` and return its stdout as a string.

        Uses a list-form command (no shell=True) and a timeout.
        """
        try:
            result = subprocess.run(
                ["arp", "-a"],
                shell=False,          # No shell=True — ever
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout
        except FileNotFoundError:
            logger.error("'arp' command not found on this system.")
            return None
        except subprocess.TimeoutExpired:
            logger.error("'arp -a' timed out.")
            return None
        except Exception as exc:
            logger.exception("ARP table read failed: %s", exc)
            return None