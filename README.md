# Wi-Fi Bastion 🛡️
**A Software-Defined Wireless Intrusion Prevention System (WIPS)**

Wi-Fi Bastion is a proactive security perimeter designed to monitor airwaves for de-authentication floods, detect rogue access points (Evil Twins), and harden network gateways via OS-level hardware filtering. It translates complex RF telemetry into actionable security intelligence through a modern web dashboard.

## 🚀 Key Features
* **Intrusion Analysis Engine:** Real-time sniffing of 802.11 management frames using Scapy.
* **Rogue Point Detection:** Identifies Evil Twin clones by verifying BSSIDs against OUI databases and signal strength (RSSI) anomalies.
* **Gateway Intelligence Audit:** Probes for DNS hijacking (Canary checks) and critical port exposure.
* **Active Mitigation:** Integrated with Windows WLAN API to blacklist malicious networks at the driver level.
* **Forensic Archive:** Comprehensive scan history and threat incident logging using MongoDB.
* **Automated Reporting:** Generates PDF security audit reports for offline compliance review.

## 🛠️ Tech Stack
* **Frontend:** React.js, Tailwind CSS, Lucide Icons
* **Backend:** Python (Flask), Scapy (Packet Engine), Nmap (Service Mapping)
* **Database:** MongoDB
* **OS Interface:** Windows WLAN API

## 📋 Installation & Setup

### Prerequisites
* Python 3.8+
* Node.js & npm
* MongoDB Community Server
* **Npcap:** Required for raw packet sniffing on Windows. [Download here](https://npcap.com/). *Ensure "Support raw 802.11 traffic" is checked during install.*

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server (Run as Administrator for Packet Sniffing)
python app.py
```

###2. Frontend Setup
```Bash
# Navigate to frontend directory
cd frontend

# Install packages
npm install

# Start development server
npm start
```

## 📖 Usage
Initialize Control Center: Launch the app and click "Initialize Security Scan."

Monitor Radar: View the "Trust Index" of nearby APs.

Audit Topology: Use the Topology tab to fingerprint devices on your network.

Enforce Policy: If an "Evil Twin" is detected, use the Restrict button to block the BSSID instantly.

## ⚖️ License & Disclaimer
This project is developed for educational purposes at Malla Reddy University. Unauthorized use of this tool against networks without permission is strictly prohibited and illegal.

Developed by: Sai Lakshman Rangisetti, S Mohammed Aadil, T. Bhavesh | Batch: 2022-2026 | Department: CSE - Cyber Security
