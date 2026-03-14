import pywifi
from pywifi import PyWiFi, const, Profile
import time
import math
from collections import defaultdict
import logging

# Updated imports to handle the new directory structure
try:
    from backend.config import AKM_MAPPING, SCAN_WAIT_TIME, WEAK_ENCRYPTION_TYPES, SIGNAL_ANOMALY_THRESHOLD
except ImportError:
    from config import AKM_MAPPING, SCAN_WAIT_TIME, WEAK_ENCRYPTION_TYPES, SIGNAL_ANOMALY_THRESHOLD

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WiFiScanner:
    """Handles Wi-Fi scanning and threat detection operations."""
    
    def __init__(self, db_manager=None):
        """Initialize the Wi-Fi scanner."""
        try:
            self.wifi = PyWiFi()
            self.interface = self.wifi.interfaces()[0]
            self.db_manager = db_manager
            logger.info(f"Initialized Wi-Fi scanner: {self.interface.name()}")
        except Exception as e:
            logger.error(f"Failed to initialize Wi-Fi scanner: {str(e)}")
            raise

    def get_vendor(self, bssid):
        """Resolves MAC addresses to manufacturer names (Feature 3)."""
        vendors = {
            "f0:ed:b8": "TP-Link",
            "8c:a3:99": "JioFiber",
            "a8:da:0c": "Apple",
            "b4:a7:c6": "TP-Link",
            "04:25:e0": "Intel/Cisco",
            "9c:53:22": "Samsung",
            "f2:ed:b8": "TP-Link (Virtual)"
        }
        # Extract the OUI (first 3 octets)
        prefix = bssid.lower()[:8].replace("-", ":")
        return vendors.get(prefix, "Unknown Vendor")

    def estimate_distance(self, signal_dbm):
        """Estimates physical distance based on RSSI (Feature 13)."""
        try:
            # RSSI (dBm) = -10n log10(d) + A
            # Standard indoors: A (1m power) = -30, n (path-loss) = 2.7
            rssi = abs(int(signal_dbm.split(" ")[0]))
            # Mathematical path-loss model
            distance = 10**((27.55 - (20 * math.log10(2412)) + rssi) / 20)
            return round(distance, 1)
        except:
            return "N/A"

    def calculate_trust_score(self, net):
        """Assigns a 0–100 Trust Score based on security factors (Feature 15)."""
        score = 100
        
        # 1. Encryption Audit (Feature 11)
        enc = net['encryption']
        if "WPA3" in enc:
            score -= 0
        elif "WPA2" in enc:
            score -= 10
        elif "WPA" in enc or "WEP" in enc:
            score -= 40
        else: # Open Network
            score -= 60

        # 2. Threat deductions
        threats = net.get("threats", [])
        for threat in threats:
            if "Attack" in threat: score -= 50
            if "Anomaly" in threat: score -= 20
            if "Hidden" in threat: score -= 15
            if "Blocked" in threat: score -= 100 # Immediate Zero

        return max(0, score)

    def get_encryption_type(self, network):
        """Determine Wi-Fi encryption type."""
        encryption = "Unknown"
        try:
            if hasattr(network, 'akm') and network.akm:
                akm_value = network.akm[0]
                encryption = AKM_MAPPING.get(akm_value, "Unknown encryption")
        except Exception as e:
            logger.warning(f"Error determining encryption type: {str(e)}")
        return encryption
    
    def scan_networks(self):
        """Scan for Wi-Fi networks and detect threats."""
        try:
            self.interface.scan()
            logger.info(f"Scanning... waiting {SCAN_WAIT_TIME}s")
            time.sleep(SCAN_WAIT_TIME)
            results = self.interface.scan_results()
            
            # Filter unique BSSIDs
            unique_results = {}
            for network in results:
                bssid = network.bssid
                if bssid not in unique_results or network.signal > unique_results[bssid].signal:
                    unique_results[bssid] = network

            networks = []
            for bssid, network in unique_results.items():
                ssid = network.ssid.strip()
                network_info = {
                    'ssid': ssid if ssid else "Hidden Network",
                    'bssid': bssid,
                    'signal': f"{network.signal} dBm",
                    'encryption': self.get_encryption_type(network),
                    'timestamp': time.time(),
                    'vendor': self.get_vendor(bssid),
                    'distance': self.estimate_distance(f"{network.signal}")
                }
                networks.append(network_info)
            
            return self.detect_threats(networks)
        except Exception as e:
            logger.error(f"Error scanning: {str(e)}")
            return []
    
    def detect_threats(self, networks):
        """Analyze networks for security risks and calculate risk metrics."""
        try:
            ssid_counts = defaultdict(list)
            bssid_counts = defaultdict(list)

            for net in networks:
                ssid_counts[net["ssid"]].append(net)
                bssid_counts[net["bssid"]].append(net)

            blocked_bssids = []
            if self.db_manager:
                success, blocked_data = self.db_manager.get_blocked_networks()
                if success:
                    blocked_bssids = [item['bssid'] for item in blocked_data]
                
            for net in networks:
                threats = []
                
                # 1. Blocklist Check
                if net["bssid"] in blocked_bssids:
                    threats.append("🚫 Network Blocked")

                # 2. Refined Evil Twin Detection
                if len(ssid_counts[net["ssid"]]) > 1:
                    is_suspicious = False
                    for other in ssid_counts[net["ssid"]]:
                        if other['bssid'] == net['bssid']: continue
                        prefix1 = net['bssid'].lower()[:13]
                        prefix2 = other['bssid'].lower()[:13]
                        if prefix1 != prefix2:
                            is_suspicious = True
                            break
                    if is_suspicious:
                        threats.append("🚨 Evil Twin Attack Detected")

                # 3. MAC Spoofing
                if len(bssid_counts[net["bssid"]]) > 1:
                    threats.append("🚨 MAC Spoofing Detected")

                # 4. Weak Encryption (Feature 11 partial)
                if net["encryption"] in WEAK_ENCRYPTION_TYPES:
                    threats.append("⚠️ Weak Encryption")

                # 5. Hidden SSID (Feature 4 partial)
                if net["ssid"] == "Hidden Network":
                    threats.append("⚠️ Hidden SSID Detected")

                # 6. Signal Anomaly
                if len(ssid_counts[net["ssid"]]) > 1:
                    try:
                        signals = [int(n["signal"].split(" ")[0]) for n in ssid_counts[net["ssid"]]]
                        if (max(signals) - min(signals)) > SIGNAL_ANOMALY_THRESHOLD:
                            threats.append("🚨 Signal Anomaly")
                    except (ValueError, IndexError):
                        pass

                # Finalize threats
                net["threats"] = threats 
                net["is_safe"] = len(threats) == 0
                
                # Integrated Risk Scoring (Feature 15)
                net["trust_score"] = self.calculate_trust_score(net)
                
                # Encryption Audit Rating (Feature 11)
                if net["trust_score"] >= 80: net["rating"] = "Safe"
                elif net["trust_score"] >= 50: net["rating"] = "Warning"
                else: net["rating"] = "Danger"

            return networks
        except Exception as e:
            logger.error(f"Threat detection error: {str(e)}")
            return networks