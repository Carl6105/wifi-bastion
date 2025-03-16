# Wi-Fi Bastion

Wi-Fi Bastion is a web-based application designed to scan available Wi-Fi networks and display their details, such as SSID, BSSID, encryption type, and signal strength. It also stores scanned network information in a MongoDB database and provides a history of previous scans. The app helps users identify Wi-Fi networks and their security status.

## Features

- **Wi-Fi Network Scanning:** Scans nearby Wi-Fi networks and retrieves their details like SSID, BSSID, encryption type, and signal strength.
- **Scan History:** Stores previous scans in MongoDB, allowing users to view their Wi-Fi scan history.
- **Real-time Results:** Displays scan results in real-time with information on the encryption type and signal strength of nearby networks.
- **Security Alerts:** Identifies network security types (e.g., WPA2, WPA3) and displays them to the user.
- **Threat Detection:** Analyzes networks for potential security threats including:
  - Evil Twin Attack Detection
  - MAC Spoofing Detection
  - Weak Encryption Detection
  - Hidden SSID Detection
  - Signal Strength Anomalies
- **Network Blocking:** Allows users to block suspicious networks and manage a blocklist.
- **Responsive Design:** The app is built using Bootstrap and is fully responsive, providing an excellent user experience on both desktop and mobile devices.
- **Visual Security Flow:** Includes a diagram generator to visualize the security analysis process.

## Tech Stack

- **Backend:**
  - Python (Flask framework)
  - MongoDB (for storing scan history)
  - PyWiFi (for Wi-Fi network scanning)

- **Frontend:**
  - HTML
  - CSS
  - JavaScript
  - Bootstrap (for styling and layout)

- **Additional Libraries:**
  - PyWiFi (for interacting with the Wi-Fi hardware)

## Setup Instructions

### Prerequisites

Ensure the following are installed:

- **Python** (3.x)
- **MongoDB** (installed locally or remotely)
- **pip** (Python package installer)

### Installation Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/Carl6105/wifi-bastion
   cd wifi-bastion
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Ensure MongoDB is running on your system.

4. Configure the application settings in `config.py` if needed.

5. Run the application:

   ```bash
   python app.py
   ```

6. Open your web browser and navigate to `http://localhost:5000`

## Usage

1. **Scanning Networks:** Click the "Scan Wi-Fi Networks" button on the home page to initiate a scan.

2. **Viewing History:** Navigate to the "View Scan History" page to see previously scanned networks.

3. **Managing Blocked Networks:** Use the "View Blocked Networks" page to see and manage networks you've blocked.

4. **Understanding Threats:** The application uses the following indicators for threats:
   - ✅ No Threats Detected
   - ⚠️ Warning (Weak Encryption, Hidden SSID)
   - 🚨 Critical Threat (Evil Twin Attack, MAC Spoofing, Signal Anomaly)
   - 🚫 Network Blocked