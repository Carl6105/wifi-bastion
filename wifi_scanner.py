import pywifi
from pywifi import PyWiFi, const, Profile
import time
from collections import defaultdict
import logging
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
            self.interface = self.wifi.interfaces()[0]  # Use the first available Wi-Fi interface
            self.db_manager = db_manager  # Store database manager for blocklist access
            logger.info(f"Initialized Wi-Fi scanner using interface: {self.interface.name()}")
        except Exception as e:
            logger.error(f"Failed to initialize Wi-Fi scanner: {str(e)}")
            raise
    
    def get_encryption_type(self, network):
        """Determine Wi-Fi encryption type.
        
        Args:
            network: PyWiFi network object
            
        Returns:
            str: Human-readable encryption type
        """
        encryption = "Unknown"
        
        try:
            if hasattr(network, 'akm') and network.akm:
                akm_value = network.akm[0]
                encryption = AKM_MAPPING.get(akm_value, "Unknown encryption")
        except Exception as e:
            logger.warning(f"Error determining encryption type: {str(e)}")
            
        return encryption
    
    def scan_networks(self):
        """Scan for Wi-Fi networks.
        
        Returns:
            list: List of detected networks with their properties
        """
        try:
            self.interface.scan()
            logger.info(f"Initiated Wi-Fi scan, waiting {SCAN_WAIT_TIME} seconds for completion")
            time.sleep(SCAN_WAIT_TIME)  # Wait for scan completion
            results = self.interface.scan_results()
            logger.info(f"Scan completed, found {len(results)} networks")
            
            networks = []
            for network in results:
                ssid = network.ssid.strip()
                if not ssid:  # Skip networks with empty SSIDs (will be handled later as hidden)
                    ssid = ""  # Ensure empty string for hidden networks
                    
                network_info = {
                    'ssid': ssid,
                    'bssid': network.bssid,
                    'signal': f"{network.signal} dBm",
                    'encryption': self.get_encryption_type(network),
                }
                networks.append(network_info)
                
            return self.detect_threats(networks)
            
        except Exception as e:
            logger.error(f"Error scanning Wi-Fi networks: {str(e)}")
            return []
    
    def detect_threats(self, networks):
        """Analyze networks and detect security threats.
        
        Args:
            networks (list): List of network dictionaries
            
        Returns:
            list: Networks with added threat information
        """
        try:
            ssid_counts = defaultdict(list)  # Store BSSIDs per SSID
            bssid_counts = defaultdict(list)  # Store SSIDs per BSSID

            # First pass: build the lookup dictionaries
            for net in networks:
                ssid_counts[net["ssid"]].append(net)
                bssid_counts[net["bssid"]].append(net)

            # Get blocked networks if database manager is available
            blocked_networks = []
            if self.db_manager:
                blocked_networks = self.db_manager.get_blocked_networks()
                
            # Second pass: detect threats for each network
            for net in networks:
                threats = []
                
                # Check if network is blocked
                if net["bssid"] in blocked_networks:
                    threats.append("🚫 Network Blocked")

                # Evil Twin Attack Detection (Multiple BSSIDs for the same SSID)
                if len(ssid_counts[net["ssid"]]) > 1:
                    threats.append("🚨 Evil Twin Attack Detected")

                # MAC Spoofing Detection (Multiple SSIDs with same BSSID)
                if len(bssid_counts[net["bssid"]]) > 1:
                    threats.append("🚨 MAC Spoofing Detected")

                # Weak Encryption Detection
                if net["encryption"] in WEAK_ENCRYPTION_TYPES:
                    threats.append("⚠️ Weak Encryption")

                # Hidden SSID Detection
                if net["ssid"] == "":
                    threats.append("⚠️ Hidden SSID Detected")

                # Signal Strength Anomalies (Possible Fake AP)
                if len(ssid_counts[net["ssid"]]) > 1:
                    try:
                        signal_strengths = [int(n["signal"].split(" ")[0]) for n in ssid_counts[net["ssid"]]]
                        max_signal, min_signal = max(signal_strengths), min(signal_strengths)
                        if abs(max_signal - min_signal) > SIGNAL_ANOMALY_THRESHOLD:  # If signal variance is large
                            threats.append("🚨 Signal Anomaly (Possible Fake AP)")
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error analyzing signal strengths: {str(e)}")

                net["threats"] = ", ".join(threats) if threats else "✅ No Threats Detected"
                
            logger.info(f"Threat detection completed for {len(networks)} networks")
            return networks
            
        except Exception as e:
            logger.error(f"Error during threat detection: {str(e)}")
            # Return networks without threat analysis rather than failing completely
            for net in networks:
                net["threats"] = "⚠️ Threat detection failed"
            return networks