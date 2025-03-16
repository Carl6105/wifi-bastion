# Configuration settings for Wi-Fi Bastion

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB = "wifi_bastion"
MONGO_COLLECTION = "wifi_scans"

# Application Settings
DEBUG_MODE = True
SCAN_WAIT_TIME = 3  # seconds to wait for scan completion

# Threat Detection Settings
WEAK_ENCRYPTION_TYPES = ["Open (No Encryption)", "WPA"]
SIGNAL_ANOMALY_THRESHOLD = 30  # dBm difference to consider suspicious

# AKM Mapping for Encryption Types
AKM_MAPPING = {
    0: "Open (No Encryption)",
    1: "WPA",
    2: "WPA2",
    3: "WPA3",
    4: "WPA2-PSK",
    5: "WPA3-PSK"
}
