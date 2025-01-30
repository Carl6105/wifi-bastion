from flask import Flask, render_template, jsonify, request
import pywifi
from pywifi import PyWiFi, const, Profile
from pymongo import MongoClient
import time
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["wifi_bastion"]
collection = db["wifi_scans"]

def get_encryption_type(network):
    """
    Get the encryption type of a Wi-Fi network based on 'auth', 'akm', and 'cipher' fields.
    For Open networks, assign WPA2-Personal by default.
    """
    encryption = "Unknown"
    
    # Dictionary to map AKM values to their descriptions
    akm_mapping = {
        0: "Open (No Encryption)",  # Open networks
        1: "WPA (Wi-Fi Protected Access)",  # WPA encryption
        2: "WPA2 (Wi-Fi Protected Access 2)",  # WPA2 encryption
        3: "WPA3 (Wi-Fi Protected Access 3)",  # WPA3 encryption
        4: "WPA2-PSK (Wi-Fi Protected Access 2 - Pre-Shared Key)",  # WPA2-PSK encryption
        5: "WPA3-PSK (Wi-Fi Protected Access 3 - Pre-Shared Key)"  # WPA3-PSK encryption
    }

    if hasattr(network, 'akm') and network.akm:
        akm_value = network.akm[0]  # Get the first AKM value

        # If the network is open and has no encryption, assign WPA2-Personal as default
        if akm_value == 0:
            encryption = "WPA2-Personal"
        else:
            encryption = akm_mapping.get(akm_value, "Unknown encryption")  
    else:
        encryption = "No encryption info available"
    
    return encryption

def get_wifi_networks():
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]  # Assuming the first interface is the Wi-Fi interface

    iface.scan()  # Start scanning for networks
    time.sleep(3)  # Wait for scan to complete
    results = iface.scan_results()  # Retrieve scan results

    networks = []
    for network in results:
        ssid = network.ssid.strip()  
        if not ssid:  
            continue  

        encryption = get_encryption_type(network)  
        network_info = {
            'ssid': ssid,  
            'bssid': network.bssid,
            'signal': f"{network.signal} dBm",
            'encryption': encryption,
        }
        networks.append(network_info)

    return networks

def serialize_mongo_document(doc):
    """Serialize MongoDB documents for JSON response."""
    doc["_id"] = str(doc["_id"])
    return doc

@app.route("/")
def home():
    """Render the home page."""
    return render_template("home.html")

@app.route("/scan", methods=["GET"])
def scan_page():
    """Render the scan page."""
    return render_template("scan.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Scan for Wi-Fi networks and store them in MongoDB."""
    networks = get_wifi_networks()

    if networks:
        try:
            existing_ssids = [network['ssid'] for network in networks]
            existing_networks = collection.find({"ssid": {"$in": existing_ssids}})
            existing_ssids_in_db = {doc['ssid']: doc for doc in existing_networks}

            new_networks = [
                network for network in networks
                if network['ssid'] not in existing_ssids_in_db
            ]

            if new_networks:
                collection.insert_many(new_networks)
                print("New networks added to MongoDB.")
            else:
                print("No new networks to insert.")

        except Exception as e:
            print(f"Error inserting into MongoDB: {str(e)}")
            return jsonify({"status": "error", "message": f"Error inserting into MongoDB: {str(e)}"}), 500

        updated_networks = [serialize_mongo_document(doc) for doc in collection.find({"ssid": {"$in": existing_ssids}})]
        return jsonify(updated_networks)

    return jsonify({"status": "error", "message": "No networks found."}), 404

@app.route('/history')
def history():
    """Retrieve the scan history from MongoDB."""
    try:
        # Retrieve scan history from MongoDB
        scans = collection.find()  
        formatted_scans = []
        for scan in scans:
            scan["_id"] = str(scan["_id"])  # Convert ObjectId to string for display
            formatted_scans.append(scan)

        return render_template('history.html', scans=formatted_scans)
    except Exception as e:
        print(f"Error fetching scan history: {str(e)}")
        return jsonify({"status": "error", "message": f"Error fetching scan history: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)