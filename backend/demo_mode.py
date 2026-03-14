def get_demo_threats():
    return [
        {
            "ssid": "Free_Public_WiFi",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "trust_score": 15,
            "threats": ["🚨 Evil Twin Attack Detected", "🚨 Signal Anomaly"],
            "encryption": "Open",
            "vendor": "Unknown (Hacker)",
            "distance": "1.2",
            "rating": "Danger"
        }
    ]