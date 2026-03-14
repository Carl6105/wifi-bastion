# Configuration settings for Wi-Fi Bastion

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB = "wifi_bastion"
MONGO_COLLECTION = "wifi_scans"

# Application Settings
DEBUG_MODE = True
PORT = 5000 # The port your Flask API will run on
SCAN_WAIT_TIME = 3  # seconds to wait for scan completion

# CORS Configuration
# This allows your React frontend to communicate with this Python backend
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]

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