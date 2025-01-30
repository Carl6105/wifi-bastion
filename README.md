# Wi-Fi Bastion

Wi-Fi Bastion is a web-based application designed to scan available Wi-Fi networks and display their details, such as SSID, BSSID, encryption type, and signal strength. It also stores scanned network information in a MongoDB database and provides a history of previous scans. The app helps users identify Wi-Fi networks and their security status.

## Features

- **Wi-Fi Network Scanning:** Scans nearby Wi-Fi networks and retrieves their details like SSID, BSSID, encryption type, and signal strength.
- **Scan History:** Stores previous scans in MongoDB, allowing users to view their Wi-Fi scan history.
- **Real-time Results:** Displays scan results in real-time with information on the encryption type and signal strength of nearby networks.
- **Security Alerts:** Identifies network security types (e.g., WPA2, WPA3) and displays them to the user.
- **Responsive Design:** The app is built using Bootstrap and is fully responsive, providing an excellent user experience on both desktop and mobile devices.

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