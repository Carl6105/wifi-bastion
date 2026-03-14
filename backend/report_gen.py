from fpdf import FPDF
import datetime
import os

class SecurityReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Wi-Fi Bastion - Security Audit Report', 0, 1, 'C')
        self.set_font('Arial', 'I', 10)
        self.cell(0, 10, f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def create_report(self, networks, gateway_data, filename="audit_report.pdf"):
        self.add_page()
        
        # 1. Executive Summary
        self.chapter_title("1. Executive Summary")
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, f"This audit analyzed {len(networks)} nearby wireless networks. "
                             f"The gateway integrity check resulted in a status of: {gateway_data.get('port_risk', 'Unknown')}.")
        self.ln(5)

        # 2. Network Analysis Table
        self.chapter_title("2. Detailed Network Analysis")
        self.set_font('Arial', 'B', 8)
        # Table Headers
        self.cell(40, 7, 'SSID', 1)
        self.cell(40, 7, 'BSSID', 1)
        self.cell(25, 7, 'Score', 1)
        self.cell(35, 7, 'Encryption', 1)
        self.cell(50, 7, 'Threats', 1)
        self.ln()

        self.set_font('Arial', '', 8)
        for net in networks:
            # CLEAN EMOJIS: This line removes any character that isn't standard text
            raw_threats = ", ".join(net.get('threats', [])) if net.get('threats') else "None"
            clean_threats = "".join([c for c in raw_threats if ord(c) < 256]) 
            
            # Also clean SSID in case it has emojis
            clean_ssid = "".join([c for c in str(net['ssid']) if ord(c) < 256])

            self.cell(40, 7, clean_ssid[:20], 1)
            self.cell(40, 7, str(net['bssid']), 1)
            self.cell(25, 7, f"{net['trust_score']}/100", 1)
            self.cell(35, 7, str(net['encryption']), 1)
            self.cell(50, 7, clean_threats[:30], 1)
            self.ln()

        self.output(filename)
        return filename