from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import logging
import os
import threading

# Local Imports
try:
    from backend.wifi_scanner import WiFiScanner
    from backend.database import DatabaseManager
    from backend.config import DEBUG_MODE
    from backend.network_mapper import DeviceMapper
    from backend.packet_engine import PacketEngine
    from backend.report_gen import SecurityReport
except ImportError:
    from wifi_scanner import WiFiScanner
    from database import DatabaseManager
    from config import DEBUG_MODE
    from network_mapper import DeviceMapper
    from packet_engine import PacketEngine
    from report_gen import SecurityReport

# 1. Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 2. Initialize Flask App
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 3. Initialize Core Components
db_manager = DatabaseManager()
wifi_scanner = WiFiScanner(db_manager)
device_mapper = DeviceMapper()
packet_engine = PacketEngine()

# 4. Start Background Monitoring
try:
    # Feature 7: Initializing monitoring on the Wi-Fi interface
    packet_engine.start_monitor(interface="Wi-Fi") 
except Exception as e:
    logger.error(f"Packet Engine failed: {e}. Monitor mode may be required.")

# --- HELPER LOGIC ---

def calculate_security_vectors(net):
    """Calculates real-time security metrics for frontend Radar Charts."""
    # Feature 6: DNS Hijacking Check
    dns_status = device_mapper.check_dns_hijack()
    dns_val = 100 if dns_status['status'] == "Safe" else 30
    
    # Feature 7: Deauth Attack Status
    deauth_status = packet_engine.get_alerts()
    packet_val = 100 if not deauth_status["attack_active"] else 15
    
    # Feature 1: Protocol Strength Check
    enc = net.get('encryption', '').upper()
    if 'WPA3' in enc:
        prot_val = 100
    elif 'WPA2' in enc:
        prot_val = 80
    else:
        prot_val = 40

    return {
        "dns_secure": dns_val,
        "packet_integrity": packet_val,
        "protocol_strength": prot_val,
        "trust_score": (dns_val + packet_val + prot_val) // 3
    }

# --- API ROUTES ---

@app.route('/api/security_alerts', methods=['GET'])
def security_alerts():
    """Real-time threat aggregator (Features 6, 7, 8)."""
    try:
        alerts = []
        # Feature 8: ARP Spoofing
        arp_alerts = device_mapper.detect_arp_spoofing()
        if arp_alerts:
            alerts.extend(arp_alerts)
        
        # Feature 7: Deauth Attacks
        deauth_status = packet_engine.get_alerts()
        if deauth_status["attack_active"]:
            alerts.append({
                "type": "🚨 DEAUTH FLOOD DETECTED",
                "message": f"Detected {deauth_status['count']} deauth frames."
            })
        
        # Feature 6: DNS Hijacking
        dns_status = device_mapper.check_dns_hijack()
        if dns_status['status'] == "Danger":
            alerts.append({
                "type": "🚨 DNS HIJACKING", 
                "message": dns_status['message']
            })
        return jsonify(alerts)
    except Exception as e:
        logger.error(f"Alerts Error: {e}")
        return jsonify([])

@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    """Feature 19: Generates a PDF security audit report."""
    try:
        data = request.json
        networks = data.get('networks', [])
        dns_status = device_mapper.check_dns_hijack()
        open_ports = device_mapper.scan_router_ports()
        
        gateway_data = {
            "dns": dns_status,
            "ports": open_ports,
            "port_risk": "High" if any(p in [21, 23, 445] for p in open_ports) else "Low"
        }
        report = SecurityReport()
        report_filename = "security_audit_report.pdf"
        report.create_report(networks, gateway_data, report_filename)
        return send_file(report_filename, as_attachment=True)
    except Exception as e:
        logger.error(f"PDF Gen Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/gateway_audit', methods=['GET'])
def gateway_audit():
    """Feature 6 & 10: DNS Canary and Router Port Scan."""
    try:
        dns_status = device_mapper.check_dns_hijack()
        open_ports = device_mapper.scan_router_ports() 
        
        if not open_ports:
            port_risk = "Safe"
        else:
            critical_ports = {21, 23, 445, 3389}
            found_critical = [p for p in open_ports if p in critical_ports]
            port_risk = f"Critical" if found_critical else f"Vulnerable"

        return jsonify({
            "dns": dns_status,
            "ports": open_ports,
            "port_risk": port_risk
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/map_devices', methods=['GET'])
def map_devices():
    """Feature 2 & 3: Active Device Mapping."""
    try:
        devices = device_mapper.scan_devices()
        return jsonify(devices)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/scan", methods=["POST"])
def scan():
    """Enhanced Scan with Metadata for Visual Analytics."""
    try:
        networks = wifi_scanner.scan_networks()
        if not networks:
            return jsonify({"status": "error", "message": "No networks found."}), 404

        # Injecting unique security vectors for each network
        for net in networks:
            vectors = calculate_security_vectors(net)
            net.update(vectors)

        # Database sync logic
        existing_ssids = [net['ssid'] for net in networks]
        existing_ssids_in_db = db_manager.find_existing_networks(existing_ssids)
        new_networks = [net for net in networks if net['ssid'] not in existing_ssids_in_db]

        if new_networks:
            success, result = db_manager.insert_networks(new_networks)
            if success:
                for net, obj_id in zip(new_networks, result):
                    net["_id"] = str(obj_id)
        
        for net in networks:
            if net['ssid'] in existing_ssids_in_db:
                net["_id"] = str(existing_ssids_in_db[net['ssid']]['_id'])

        return jsonify(networks)
    except Exception as e:
        logger.error(f"Scan Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/disconnect_device', methods=['POST'])
def disconnect_device():
    """Feature: Targeted De-authentication of a node."""
    try:
        data = request.json
        target_mac = data.get('mac')
        if not target_mac:
            return jsonify({"status": "error", "message": "Target MAC required"}), 400

        # Invoke Scapy engine de-auth
        success = packet_engine.send_deauth(target_mac) 
        if success:
            return jsonify({"status": "success", "message": f"Signal sent to {target_mac}"})
        return jsonify({"status": "error", "message": "Failed to transmit"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/history', methods=['GET'])
def history():
    success, result = db_manager.get_all_scans()
    return jsonify(result) if success else (jsonify({"error": result}), 500)

@app.route('/api/history', methods=['DELETE'])
def clear_history():
    success, message = db_manager.clear_all_scans()
    return jsonify({"status": "success" if success else "error", "message": message})

@app.route('/api/block_network', methods=['POST'])
def block_network():
    data = request.json 
    success, message = db_manager.block_network(data.get('network_id'), data.get('bssid'), data.get('ssid'))
    return jsonify({"status": "success" if success else "error", "message": message})

@app.route('/api/unblock_network', methods=['POST'])
def unblock_network():
    data = request.json
    success, message = db_manager.unblock_network(data.get('network_id'), data.get('ssid'))
    return jsonify({"status": "success" if success else "error", "message": message})

@app.route('/api/blocked', methods=['GET'])
def blocked_networks():
    success, result = db_manager.get_blocked_networks()
    return jsonify(result) if success else (jsonify({"error": result}), 500)

if __name__ == "__main__":
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=5000)