# Wi-Fi Bastion 🛡️

### A Software-Defined Wireless Intrusion Prevention System (WIPS)

Wi-Fi Bastion is a proactive wireless security platform that monitors your airwaves in real time, detects rogue access points and active attacks, fingerprints every device on your network, and lets you block dangerous networks at the OS driver level — all from a modern web dashboard, a REST API, or a standalone desktop app.

> Built as a final year project at Malla Reddy University, Department of CSE – Cyber Security (Batch 2022–2026)

---

## 🚀 Key Features

### Threat Detection
- **Evil Twin Detection** — identifies rogue APs cloning legitimate SSIDs using 3-stage OUI + encryption mismatch analysis
- **Deauthentication Flood Detection** — real-time 802.11 frame capture alerts within seconds of an attack starting
- **ARP Spoofing Detection** — scans the OS ARP table every 15 seconds, flags MAC-to-IP collisions
- **DNS Hijack Detection** — multi-canary validation using private-IP detection; correctly handles ISP transparent proxies
- **PMKID Capture Detection** — detects offline WPA2 cracking attempts by monitoring EAPOL handshake frames
- **Beacon Interval Anomaly** — flags APs broadcasting outside the normal 50–300ms range
- **MAC Spoofing Detection** — identifies duplicate BSSID claims across scan results
- **Signal Anomaly Detection** — same-SSID networks with suspicious RSSI variance are flagged
- **WEP / Open Network Flagging** — automatic critical severity flags for broken or absent encryption

### Network Intelligence
- **OS Fingerprinting** — nmap-powered device discovery with OS detection, vendor resolution, and open port mapping
- **IEEE OUI Vendor Lookup** — full offline IEEE MAC database (~30,000 entries), auto-downloaded and cached weekly
- **Channel Map & Congestion Analysis** — shows which Wi-Fi channels are overloaded; reads band/channel directly from Windows netsh
- **Distance Estimation** — log-distance path-loss model estimates physical range to each AP
- **Trust Scoring** — weighted 0–100 score combining encryption strength, active threats, and signal quality

### Access Control & Policy
- **OS-Level Network Blocking** — integrates with Windows `netsh wlan` to blacklist BSSIDs at the driver level
- **Trusted Whitelist** — mark networks as trusted to exclude them from all threat alerts
- **Network Notes & Tags** — annotate any BSSID with a custom note and a tag (Home, Office, Trusted, Suspicious)
- **Auto-Block Evil Twin** — configurable toggle: automatically block Evil Twin networks below a trust score threshold

### Automation & Alerts
- **WebSocket Push** — Flask-SocketIO streams scan results and threat alerts to the dashboard in real time
- **Configurable Auto-Scanning** — background scan interval adjustable from 30 seconds to 10 minutes
- **Push Notifications** — CRITICAL/HIGH alerts sent to Slack, Discord, ntfy.sh, or Gmail automatically
- **Time-Series Threat History** — all threat events stored in MongoDB for trend analysis

### Reporting & Analytics
- **PDF Security Reports** — one-click audit reports with executive summary, network tables, and recommendations
- **Security Analytics** — trust score trends, hourly activity, encryption breakdown, threat type charts
- **JSON / CSV Export** — export full scan history via the API

### Interfaces
- **React Web Dashboard** — 9-page dark-themed SPA
- **Standalone Desktop GUI** — tkinter app, zero extra dependencies, talks to the backend via HTTP
- **REST API** — documented Flask API with rate limiting, API key auth, and structured JSON responses

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend API | Python · Flask · Flask-SocketIO · Flask-Limiter · APScheduler |
| Packet Engine | Scapy (802.11 frame capture) |
| Network Scanning | pywifi · python-nmap |
| Channel Detection | Windows netsh wlan (built-in, no install needed) |
| Database | MongoDB · PyMongo |
| PDF Reports | ReportLab Platypus |
| Frontend | React · Vite · Recharts |
| Desktop GUI | Python tkinter (stdlib) |
| OS Interface | Windows WLAN API (`netsh wlan`) |

---

## 📋 Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10+ | Required for union type hints |
| Node.js 18+ | For the React frontend |
| MongoDB Community | Local `localhost:27017` or MongoDB Atlas |
| **nmap** | Must be in system PATH — [nmap.org/download.html](https://nmap.org/download.html) |
| **Npcap** | Raw packet capture on Windows — [npcap.com](https://npcap.com) — check **"Support raw 802.11 traffic"** |
| Administrator | Required for nmap OS detection and Scapy monitor mode |

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Carl6105/wifi-bastion
cd wifi-bastion
```

### 2. Backend setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend setup

```bash
cd frontend
npm install
```

### 4. Add fonts to `frontend/index.html`

```html
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=IBM+Plex+Mono:wght@300;400;500&family=Outfit:wght@300;400;500;600&display=swap" rel="stylesheet">
```

---

## Running

```bash
# 1. Start MongoDB
mongod --dbpath C:\data\db

# 2. Start backend (run as Administrator)
cd backend
python app.py

# 3. Start frontend (new terminal)
cd frontend
npm run dev

# 4. Open in browser
# http://localhost:5173

# Optional: standalone desktop app
python gui_app.py
```

---

## Project Structure

```
wifi-bastion/
├── backend/
│   ├── app.py                 # Flask API server
│   ├── config.py              # Configuration
│   ├── auth.py                # API key auth + rate limiting + audit log
│   ├── database.py            # MongoDB persistence
│   ├── wifi_scanner.py        # Wi-Fi scanning + threat detection + channels
│   ├── network_mapper.py      # nmap + DNS + ARP + port scan
│   ├── packet_engine.py       # Scapy packet capture
│   ├── report_gen.py          # PDF report generation
│   ├── monitor.py             # Change detection + threat history
│   ├── realtime.py            # WebSocket + background jobs
│   ├── routes_extra.py        # Analytics + export endpoints
│   ├── oui_lookup.py          # IEEE OUI vendor database
│   ├── alerts_dispatcher.py   # Push notification dispatch
│   ├── gui_app.py             # Standalone desktop GUI
│   └── requirements.txt
│
└── frontend/src/pages/
    ├── home.jsx               # Landing page
    ├── Dashbd.jsx             # Overview dashboard
    ├── Scan.jsx               # Wi-Fi scanner
    ├── SecurityAlerts.jsx     # Live threat feed
    ├── Analytics.jsx          # Security charts
    ├── ChannelMap.jsx         # Channel map + notes + whitelist
    ├── DeviceMap.jsx          # Network topology
    ├── History.jsx            # Scan archive
    ├── Blocked.jsx            # Restricted networks
    └── Settings.jsx           # App configuration
```

---

## Legal Disclaimer

> **Authorised use only.** Deauthentication, OS-level blocking, and packet sniffing must only be used on networks you own or have written permission to test. Unauthorised use may violate the IT Act (India), Computer Misuse Act (UK), CFAA (US), and equivalent laws. The authors accept no liability for misuse.

---

## Authors

**Sai Lakshman Rangisetti · S Mohammed Aadil · T. Bhavesh**

Malla Reddy University — CSE Cyber Security — Batch 2022–2026