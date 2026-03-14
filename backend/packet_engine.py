from scapy.all import sniff, Dot11Deauth
import threading
import logging
import time

logger = logging.getLogger(__name__)

class PacketEngine:
    def __init__(self):
        self.deauth_count = 0
        self.last_attack_time = 0
        self.is_monitoring = False
        self.thread = None

    def process_packet(self, pkt):
        """Callback for every packet sniffed."""
        # Look specifically for Dot11 Deauthentication frames
        if pkt.haslayer(Dot11Deauth):
            addr1 = pkt.addr1  # Receiver
            addr2 = pkt.addr2  # Sender
            self.deauth_count += 1
            self.last_attack_time = time.time()
            logger.warning(f"DEAUTH DETECTED: {addr2} -> {addr1}")

    def start_monitor(self, interface):
        """Starts the sniffer in a background thread."""
        if self.is_monitoring:
            return
        
        def sniffer_loop():
            try:
                # monitor=True requires your Wi-Fi card to support Monitor Mode
                sniff(iface=interface, prn=self.process_packet, store=0)
            except Exception as e:
                logger.error(f"Sniffer crashed: {e}")
                self.is_monitoring = False

        self.is_monitoring = True
        self.thread = threading.Thread(target=sniffer_loop, daemon=True)
        self.thread.start()
        logger.info("Deauthentication Monitor active.")

    def get_alerts(self):
        """Returns attack status and resets count if old."""
        # If no deauths in the last 30 seconds, consider the attack over
        if time.time() - self.last_attack_time > 30:
            self.deauth_count = 0
            
        return {
            "attack_active": self.deauth_count > 5, # Threshold to avoid noise
            "count": self.deauth_count,
            "timestamp": self.last_attack_time
        }