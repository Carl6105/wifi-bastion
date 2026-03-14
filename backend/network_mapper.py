import nmap
import socket
import logging
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor # For faster multi-port scanning

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DeviceMapper:
    """Handles advanced local network discovery and OS fingerprinting."""

    def __init__(self):
        try:
            # Initialize Nmap PortScanner for hardware discovery
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap not found in system path. Please install Nmap.")
            self.nm = None
        except Exception as e:
            logger.error(f"Unexpected error initializing Nmap: {e}")
            self.nm = None

    def get_local_ip_range(self):
        """Detects the current local IP and returns the /24 range."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return ".".join(local_ip.split('.')[:-1]) + ".0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan_devices(self):
        """
        Performs an Advanced Nmap Scan (Feature 2 & 3).
        Probes for OS details, device types, and hardware vendors.
        """
        target_range = self.get_local_ip_range()
        if not self.nm:
            return {"error": "Nmap not installed on host system."}

        try:
            # -O: OS detection, -F: Fast scan, --osscan-guess: Aggressive guessing
            self.nm.scan(hosts=target_range, arguments='-O -F --osscan-guess')
            discovered_devices = []

            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    mac = self.nm[host]['addresses'].get('mac', 'Unknown')
                    vendor = self.nm[host]['vendor'].get(mac, 'Generic Device')
                    os_name, accuracy, device_type = "Unknown OS", 0, "generic"

                    if 'osmatch' in self.nm[host] and len(self.nm[host]['osmatch']) > 0:
                        best_match = self.nm[host]['osmatch'][0]
                        os_name = best_match.get('name', 'Unknown')
                        accuracy = int(best_match.get('accuracy', 0))
                        if 'osclass' in best_match and len(best_match['osclass']) > 0:
                            device_type = best_match['osclass'][0].get('type', 'generic')

                    discovered_devices.append({
                        "ip": host, "mac": mac, "vendor": vendor,
                        "os": os_name, "accuracy": accuracy,
                        "device_type": device_type, "status": "online"
                    })
            return sorted(discovered_devices, key=lambda x: [int(d) for d in x['ip'].split('.')])
        except Exception as e:
            logger.error(f"Advanced Scan failed: {e}")
            return []

    def check_dns_hijack(self):
        """Feature 6: Checks if DNS is hijacked by comparing local resolution."""
        target_host = "google.com"
        try:
            local_res = socket.gethostbyname(target_host)
            # Detect loopback or null-route redirection
            if local_res.startswith("127.") or local_res.startswith("0."):
                return {"status": "Danger", "message": f"Suspicious Redirection: {local_res}"}
            return {"status": "Safe", "message": f"Resolved to {local_res}"}
        except Exception:
            return {"status": "Warning", "message": "DNS resolution blocked"}

    def _check_single_port(self, ip, port):
        """Internal helper to check if a specific port is open via TCP handshake."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) 
                if s.connect_ex((ip, port)) == 0:
                    return port
        except:
            pass
        return None

    def scan_router_ports(self):
        """
        DYNAMIC SIMULATION (Feature 10): Detects local IP automatically 
        and performs a multi-threaded scan of all common service ports.
        """
        # Comprehensive list of dangerous/common ports for simulation
        test_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443
        ]
        open_ports = []
        
        try:
            # Step 1: Automatically find the local machine's IP (e.g., 192.168.1.6)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            target_ip = s.getsockname()[0]
            s.close()
            
            logger.info(f"Initiating full-port simulation on Target IP: {target_ip}")

            # Step 2: Parallel scanning across all ports for real-time PPT results
            with ThreadPoolExecutor(max_workers=30) as executor:
                results = executor.map(lambda p: self._check_single_port(target_ip, p), test_ports)
                open_ports = [p for p in results if p is not None]
            
            return open_ports
        except Exception as e:
            logger.error(f"Dynamic gateway audit failed: {e}")
            return []

    def detect_arp_spoofing(self):
        """Feature 8: System ARP table monitor for Man-in-the-Middle detection."""
        try:
            output = subprocess.check_output(("arp", "-a")).decode("ascii")
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})"
            pairs = re.findall(pattern, output)
            
            mac_to_ips = defaultdict(list)
            for ip, mac in pairs:
                mac_to_ips[mac.lower().replace('-', ':')].append(ip)

            alerts = []
            for mac, ips in mac_to_ips.items():
                # If one MAC address is associated with multiple IPs, it's a spoofing sign
                if len(ips) > 1:
                    alerts.append({
                        "type": "ARP Spoofing", "mac": mac,
                        "details": f"Collision: {mac} represents {len(ips)} IPs"
                    })
            return alerts
        except Exception:
            return []