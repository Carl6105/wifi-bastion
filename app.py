from flask import Flask, render_template, jsonify, request
import pywifi
from pywifi import PyWiFi, const, Profile
from pymongo import MongoClient
import time
from collections import defaultdict

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["wifi_bastion"]
collection = db["wifi_scans"]

def get_encryption_type(network):
    """Determine Wi-Fi encryption type."""
    encryption = "Unknown"
    akm_mapping = {
        0: "Open (No Encryption)",
        1: "WPA",
        2: "WPA2",
        3: "WPA3",
        4: "WPA2-PSK",
        5: "WPA3-PSK"
    }

    if hasattr(network, 'akm') and network.akm:
        akm_value = network.akm[0]
        encryption = akm_mapping.get(akm_value, "Unknown encryption")

    return encryption

def detect_threats(networks):
    """Analyze networks and detect security threats."""
    ssid_counts = defaultdict(list)  # Store BSSIDs per SSID
    bssid_counts = defaultdict(list)  # Store SSIDs per BSSID

    for net in networks:
        ssid_counts[net["ssid"]].append(net)
        bssid_counts[net["bssid"]].append(net)

    for net in networks:
        threats = []

        # **Evil Twin Attack Detection** (Multiple BSSIDs for the same SSID)
        if len(ssid_counts[net["ssid"]]) > 1:
            threats.append("🚨 Evil Twin Attack Detected")

        # **MAC Spoofing Detection** (Multiple SSIDs with same BSSID)
        if len(bssid_counts[net["bssid"]]) > 1:
            threats.append("🚨 MAC Spoofing Detected")

        # **Weak Encryption Detection**
        if net["encryption"] in ["Open (No Encryption)", "WPA"]:
            threats.append("⚠️ Weak Encryption")

        # **Hidden SSID Detection**
        if net["ssid"] == "":
            threats.append("⚠️ Hidden SSID Detected")

        # **Signal Strength Anomalies (Possible Fake AP)**
        if len(ssid_counts[net["ssid"]]) > 1:
            signal_strengths = [int(n["signal"].split(" ")[0]) for n in ssid_counts[net["ssid"]]]
            max_signal, min_signal = max(signal_strengths), min(signal_strengths)
            if abs(max_signal - min_signal) > 30:  # If signal variance is large, it’s suspicious
                threats.append("🚨 Signal Anomaly (Possible Fake AP)")

        net["threats"] = ", ".join(threats) if threats else "✅ No Threats Detected"

    return networks

def get_wifi_networks():
    """Scan for Wi-Fi networks and detect security risks."""
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(3)  # Wait for scan completion
    results = iface.scan_results()

    networks = []
    for network in results:
        ssid = network.ssid.strip()
        if not ssid:
            continue

        network_info = {
            'ssid': ssid,
            'bssid': network.bssid,
            'signal': f"{network.signal} dBm",
            'encryption': get_encryption_type(network),
        }
        networks.append(network_info)

    return detect_threats(networks)  # Detect threats before returning

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/scan", methods=["GET"])
def scan_page():
    return render_template("scan.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Perform Wi-Fi scan and detect threats, then store results in MongoDB."""
    networks = get_wifi_networks()

    if networks:
        try:
            existing_ssids = [net['ssid'] for net in networks]
            existing_networks = collection.find({"ssid": {"$in": existing_ssids}})
            existing_ssids_in_db = {doc['ssid']: doc for doc in existing_networks}

            new_networks = [net for net in networks if net['ssid'] not in existing_ssids_in_db]

            if new_networks:
                insert_result = collection.insert_many(new_networks)
                for net, obj_id in zip(new_networks, insert_result.inserted_ids):
                    net["_id"] = str(obj_id)  # Convert ObjectId to string
            
            # Convert existing networks' ObjectId before returning JSON
            for net in networks:
                if net['ssid'] in existing_ssids_in_db:
                    net["_id"] = str(existing_ssids_in_db[net['ssid']]['_id'])

        except Exception as e:
            print(f"Error inserting into MongoDB: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

        return jsonify(networks)  # Now all `_id` fields are strings

    return jsonify({"status": "error", "message": "No networks found."}), 404

@app.route('/history')
def history():
    """Retrieve Wi-Fi scan history."""
    try:
        scans = collection.find()
        formatted_scans = [{"_id": str(scan["_id"]), **scan} for scan in scans]
        return render_template('history.html', scans=formatted_scans)
    except Exception as e:
        print(f"Error fetching scan history: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)