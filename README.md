Wi-Fi Bastion 🛡️

Wi-Fi Bastion is a proactive Wireless Intrusion Prevention System (WIPS) designed to monitor airwaves for security threats, detect rogue access points, and enforce hardware-level mitigation. By combining Python (Scapy/Flask) with a React.js dashboard, it translates complex RF telemetry into actionable security intelligence.

🚀 Key Features
Rogue Point Detection: Identifies Evil Twin clones using BSSID/OUI verification and RSSI anomaly detection.
Intrusion Analysis: Detects active De-authentication floods and ARP spoofing in real-time.
Gateway Audit: Probes for DNS hijacking and critical port exposure (Canary checks).
Active Mitigation: One-click hardware kill-switch integrated with the Windows WLAN API.
Forensic Archive: Persistent logging of environment snapshots in MongoDB.
Security Reports: Generates automated PDF security audits of the network topology.

🏗️ Architecture
The system follows a tiered architecture:

Hardware/OS Tier: Scapy & Nmap for packet sniffing; Windows WLAN API for blocking.
Logic Tier: Flask API and the "Watchdog" heuristic engine.
Data Tier: MongoDB for forensic storage.
Presentation Tier: React.js Dashboard with real-time Radar Charts (Trust Index).

🛠️ Tech Stack
Frontend: React.js, Tailwind CSS, Lucide Icons
Backend: Python 3.x, Flask, Flask-CORS
Security Engines: Scapy (Packet Analysis), Nmap (Service Discovery)
Database: MongoDB
OS Integration: Windows WLAN API
📋 Installation & Setup
Prerequisites
Python 3.8+
Node.js & npm
MongoDB Compass
Npcap (Required for Scapy on Windows - Install with "Dot11" support)

1. Backend Setup
```
cd backend
python -m venv venv
source venv/bin/activate  # Or venv\Scripts\activate on Windows
pip install -r requirements.txt
python app.py
```

2. Frontend Setup

```
cd frontend
npm install
npm start
```

📖 Usage
Ensure your Wi-Fi adapter supports Monitor Mode.
Launch the Control Center via the browser at http://localhost:3000.
Click "Initialize Security Scan" to begin real-time airwave monitoring.
View the Trust Index for nearby networks.
If a threat is flagged (Red Alert), use the "Restrict" button to sever the connection at the driver level.

⚠️ Disclaimer
This tool is developed for educational and ethical security auditing purposes only. Use it only on networks you own or have explicit permission to test. Unauthorized access or disruption of wireless networks is illegal.