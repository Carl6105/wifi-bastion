from flask import Flask, render_template, jsonify, request
import logging
import datetime
from wifi_scanner import WiFiScanner
from database import DatabaseManager
from config import DEBUG_MODE

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize components
db_manager = DatabaseManager()
wifi_scanner = WiFiScanner(db_manager)

# Custom Jinja filter for timestamp conversion
@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert a Unix timestamp to a readable date format."""
    if timestamp:
        return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return 'N/A'

# Custom Jinja filter to replace Django's {% now %} tag
@app.template_filter('now')
def now_filter(format_string):
    """Return the current date in the specified format."""
    today = datetime.datetime.now()
    if format_string == 'F j, Y':
        return today.strftime('%B %d, %Y')
    return today.strftime(format_string)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/scan", methods=["GET"])
def scan_page():
    return render_template("scan.html")

@app.route("/scan", methods=["POST"])
def scan():
    """Perform Wi-Fi scan and detect threats, then store results in MongoDB."""
    try:
        # Use the WiFiScanner to scan networks
        networks = wifi_scanner.scan_networks()

        if not networks:
            logger.warning("No networks found during scan")
            return jsonify({"status": "error", "message": "No networks found."}), 404

        # Get existing networks from database
        existing_ssids = [net['ssid'] for net in networks]
        existing_ssids_in_db = db_manager.find_existing_networks(existing_ssids)

        # Identify new networks to insert
        new_networks = [net for net in networks if net['ssid'] not in existing_ssids_in_db]

        # Insert new networks into database
        if new_networks:
            success, result = db_manager.insert_networks(new_networks)
            if success:
                # Add IDs to the new networks
                for net, obj_id in zip(new_networks, result):
                    net["_id"] = str(obj_id)  # Convert ObjectId to string
            else:
                logger.error(f"Database insertion error: {result}")
                return jsonify({"status": "error", "message": result}), 500
        
        # Add IDs to existing networks
        for net in networks:
            if net['ssid'] in existing_ssids_in_db:
                net["_id"] = str(existing_ssids_in_db[net['ssid']]['_id'])

        return jsonify(networks)  # All networks now have string _id fields

    except Exception as e:
        logger.error(f"Error during scan operation: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/history')
def history():
    """Retrieve Wi-Fi scan history."""
    try:
        success, result = db_manager.get_all_scans()
        
        if not success:
            logger.error(f"Error fetching scan history: {result}")
            return jsonify({"status": "error", "message": result}), 500
            
        formatted_scans = [{"_id": str(scan["_id"]), **{k: v for k, v in scan.items() if k != "_id"}} for scan in result]
        return render_template('history.html', scans=formatted_scans)
    except Exception as e:
        logger.error(f"Error in history route: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/block_network', methods=['POST'])
def block_network():
    """Add a network to the blocklist."""
    try:
        network_id = request.form.get('network_id')
        bssid = request.form.get('bssid')
        
        if not network_id or not bssid:
            return jsonify({"status": "error", "message": "Missing network ID or BSSID"}), 400
            
        success, message = db_manager.block_network(network_id, bssid)
        
        if not success:
            logger.error(f"Error blocking network: {message}")
            return jsonify({"status": "error", "message": message}), 500
            
        return jsonify({"status": "success", "message": message})
    except Exception as e:
        logger.error(f"Error in block_network route: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/unblock_network', methods=['POST'])
def unblock_network():
    """Remove a network from the blocklist."""
    try:
        network_id = request.form.get('network_id')
        
        if not network_id:
            return jsonify({"status": "error", "message": "Missing network ID"}), 400
            
        success, message = db_manager.unblock_network(network_id)
        
        if not success:
            logger.error(f"Error unblocking network: {message}")
            return jsonify({"status": "error", "message": message}), 500
            
        return jsonify({"status": "success", "message": message})
    except Exception as e:
        logger.error(f"Error in unblock_network route: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/blocked')
def blocked_networks():
    """Display all blocked networks."""
    try:
        success, blocked = db_manager.get_blocked_networks()
        
        if not success:
            logger.error(f"Error fetching blocked networks: {blocked}")
            return jsonify({"status": "error", "message": blocked}), 500
            
        return render_template('blocked.html', networks=blocked)
    except Exception as e:
        logger.error(f"Error in blocked_networks route: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/privacy')
def privacy():
    """Display privacy policy."""
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    """Display terms of service."""
    return render_template('terms.html')

if __name__ == "__main__":
    app.run(debug=DEBUG_MODE)