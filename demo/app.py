from flask import Flask, render_template, jsonify
from pymongo import MongoClient
import time

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["wifi_bastion_demo"]
collection = db["wifi_scans"]

# Predefined demo threats
THREAT_LEVELS = {
    "Low": "Informational - No immediate risk detected.",
    "Medium": "Suspicious - Possible security weakness, proceed with caution.",
    "High": "Critical Threat - Do not connect! Potential attack detected."
}

DEMO_NETWORKS = [
    {"ssid": "PublicWiFi", "bssid": "AA:BB:CC:DD:EE:01", "encryption": "Open (No Encryption)", "signal": "-45 dBm", "threat": "Weak Encryption", "threat_level": "Medium"},
    {"ssid": "CoffeeShop_Free", "bssid": "AA:BB:CC:DD:EE:02", "encryption": "WPA2-Personal", "signal": "-60 dBm", "threat": "Possible Evil Twin", "threat_level": "High"},
    {"ssid": "Home_Network", "bssid": "AA:BB:CC:DD:EE:03", "encryption": "WPA3-Personal", "signal": "-30 dBm", "threat": "No Threat Detected", "threat_level": "Low"},
    {"ssid": "Airport_FreeWiFi", "bssid": "AA:BB:CC:DD:EE:04", "encryption": "WPA", "signal": "-75 dBm", "threat": "Outdated Encryption", "threat_level": "Medium"},
    {"ssid": "Corporate_Guest", "bssid": "AA:BB:CC:DD:EE:05", "encryption": "WPA2-Enterprise", "signal": "-50 dBm", "threat": "Rogue Access Point", "threat_level": "High"},
]

# Function to simulate a scan
def simulate_scan():
    print("Simulating Wi-Fi scan...")
    time.sleep(2)  # Simulate network scanning delay
    return DEMO_NETWORKS

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/scan", methods=["GET"])
def scan_page():
    return render_template("scan.html")

@app.route("/scan/start", methods=["POST"])
def start_scan():
    try:
        networks = simulate_scan()

        # Clear previous scans (optional, prevents duplicate entries)
        collection.delete_many({})  

        # Insert simulated scan into MongoDB
        collection.insert_many(networks)

        # Convert MongoDB ObjectIds to strings before returning JSON
        for network in networks:
            network["_id"] = str(network.get("_id", ""))

        return jsonify(networks)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history")
def history():
    try:
        scans = list(collection.find())

        for scan in scans:
            scan["_id"] = str(scan["_id"])  # Convert ObjectId to string
            scan["threat_description"] = THREAT_LEVELS.get(scan["threat_level"], "Unknown")

        return render_template("history.html", scans=scans)

    except Exception as e:
        return render_template("history.html", error=str(e))

if __name__ == "__main__":
    app.run(debug=True)