"""
report_gen.py — PDF Security Audit Report Generator
=====================================================
Produces a professional, multi-section PDF report using ReportLab's
Platypus layout engine.  Handles unicode SSIDs correctly, paginates
large network tables automatically, and colour-codes risk levels.

Dependencies:
    pip install reportlab
"""

from __future__ import annotations

import datetime
import logging
import os
import unicodedata
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger("wifi_bastion.report_gen")

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------

_BRAND_DARK   = colors.HexColor("#0D1B2A")   # deep navy
_BRAND_ACCENT = colors.HexColor("#1E88E5")   # blue
_BRAND_LIGHT  = colors.HexColor("#E3F2FD")   # light blue tint

_RISK_COLOURS: dict[str, colors.Color] = {
    "CRITICAL": colors.HexColor("#B71C1C"),
    "HIGH":     colors.HexColor("#E53935"),
    "MEDIUM":   colors.HexColor("#FB8C00"),
    "LOW":      colors.HexColor("#43A047"),
    "SAFE":     colors.HexColor("#43A047"),
    "DANGER":   colors.HexColor("#B71C1C"),
    "WARNING":  colors.HexColor("#FB8C00"),
    "UNKNOWN":  colors.HexColor("#9E9E9E"),
}

_PAGE_W, _PAGE_H = A4
_MARGIN          = 18 * mm


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _safe_text(value: Any, max_len: int = 0) -> str:
    """
    Convert *value* to a plain-ASCII-safe string for use in PDF cells.

    Strategy:
      1. Convert to str.
      2. Normalise unicode (NFC) — keeps accented Latin characters intact.
      3. Replace characters that ReportLab's built-in fonts can't render
         (code-points > 255) with '?'.
      4. Strip leading/trailing whitespace.
      5. Optionally truncate to *max_len* characters.
    """
    text = unicodedata.normalize("NFC", str(value))
    text = "".join(c if ord(c) < 256 else "?" for c in text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def _risk_colour(label: str) -> colors.Color:
    return _RISK_COLOURS.get(label.upper(), _RISK_COLOURS["UNKNOWN"])


def _trust_label(score: int) -> str:
    if score >= 80:
        return "LOW"
    if score >= 50:
        return "MEDIUM"
    if score >= 25:
        return "HIGH"
    return "CRITICAL"


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=22,
            textColor=_BRAND_DARK,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#607D8B"),
            spaceAfter=12,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontSize=13,
            textColor=_BRAND_ACCENT,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=(0, 0, 2, 0),
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=10,
            textColor=_BRAND_DARK,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#212121"),
        ),
        "cell": ParagraphStyle(
            "Cell",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            wordWrap="CJK",
        ),
        "cell_bold": ParagraphStyle(
            "CellBold",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            fontName="Helvetica-Bold",
        ),
    }


# ---------------------------------------------------------------------------
# Page template (header / footer)
# ---------------------------------------------------------------------------

def _make_page_template(title: str, generated_at: str):
    """Return an onPage callback that draws consistent header/footer."""

    def _draw(canvas, doc):                          # noqa: ANN001
        canvas.saveState()
        w = _PAGE_W

        # ---- Header bar ----
        canvas.setFillColor(_BRAND_DARK)
        canvas.rect(0, _PAGE_H - 28 * mm, w, 28 * mm, fill=True, stroke=False)

        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 11)
        canvas.drawString(_MARGIN, _PAGE_H - 16 * mm, title)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - _MARGIN, _PAGE_H - 16 * mm, generated_at)

        # ---- Footer ----
        canvas.setFillColor(colors.HexColor("#ECEFF1"))
        canvas.rect(0, 0, w, 12 * mm, fill=True, stroke=False)
        canvas.setFillColor(colors.HexColor("#607D8B"))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(_MARGIN, 4 * mm, "Wi-Fi Bastion — Confidential Security Report")
        canvas.drawRightString(
            w - _MARGIN, 4 * mm, f"Page {doc.page}"
        )

        canvas.restoreState()

    return _draw


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _section_executive_summary(
    styles: dict,
    networks: list[dict],
    gateway_data: dict,
    generated_at: str,
) -> list:
    story: list = []
    story.append(Paragraph("1. Executive Summary", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT))
    story.append(Spacer(1, 6))

    total     = len(networks)
    critical  = sum(1 for n in networks if _trust_label(n.get("trust_score", 50)) == "CRITICAL")
    high      = sum(1 for n in networks if _trust_label(n.get("trust_score", 50)) == "HIGH")
    open_nets = sum(1 for n in networks if "Open" in str(n.get("encryption", "")))

    port_risk_raw = gateway_data.get("port_risk", {})
    port_level    = (
        port_risk_raw.get("level", "UNKNOWN")
        if isinstance(port_risk_raw, dict)
        else str(port_risk_raw)
    )
    dns_status = gateway_data.get("dns", {}).get("status", "Unknown")

    summary_text = (
        f"This automated audit analysed <b>{total}</b> wireless network(s) "
        f"detected in the vicinity, performed on <i>{generated_at}</i>. "
        f"<br/><br/>"
        f"Of the networks surveyed: <b>{critical}</b> were rated <font color='#B71C1C'>CRITICAL</font>, "
        f"<b>{high}</b> were rated <font color='#E53935'>HIGH</font> risk, and "
        f"<b>{open_nets}</b> were open (no encryption). "
        f"<br/><br/>"
        f"The local gateway DNS integrity check returned: "
        f"<b><font color='{_risk_colour(dns_status).hexval()}'>{dns_status}</font></b>. "
        f"Gateway port exposure risk level: "
        f"<b><font color='{_risk_colour(port_level).hexval()}'>{port_level}</font></b>."
    )
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 10))
    return story


def _section_network_table(styles: dict, networks: list[dict]) -> list:
    story: list = []
    story.append(Paragraph("2. Detailed Network Analysis", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT))
    story.append(Spacer(1, 6))

    usable_width = _PAGE_W - 2 * _MARGIN

    # Column widths (sum = usable_width ~= 174 mm for A4)
    col_w = [
        usable_width * 0.22,   # SSID
        usable_width * 0.20,   # BSSID
        usable_width * 0.10,   # Score
        usable_width * 0.15,   # Encryption
        usable_width * 0.10,   # Risk
        usable_width * 0.23,   # Threats
    ]

    header_row = [
        Paragraph("SSID",       styles["cell_bold"]),
        Paragraph("BSSID",      styles["cell_bold"]),
        Paragraph("Score",      styles["cell_bold"]),
        Paragraph("Encryption", styles["cell_bold"]),
        Paragraph("Risk",       styles["cell_bold"]),
        Paragraph("Threats",    styles["cell_bold"]),
    ]
    rows = [header_row]

    row_styles: list[tuple] = []

    for i, net in enumerate(networks, start=1):
        trust_score = int(net.get("trust_score", 50))
        risk_label  = _trust_label(trust_score)
        risk_color  = _risk_colour(risk_label)

        ssid        = _safe_text(net.get("ssid", "Hidden"), max_len=28)
        bssid       = _safe_text(net.get("bssid", "N/A"),  max_len=20)
        encryption  = _safe_text(net.get("encryption", "Unknown"), max_len=18)
        threats_raw = net.get("threats") or []
        threats     = _safe_text(", ".join(threats_raw) if threats_raw else "None", max_len=50)

        row = [
            Paragraph(ssid,                          styles["cell"]),
            Paragraph(bssid,                         styles["cell"]),
            Paragraph(f"{trust_score}/100",          styles["cell"]),
            Paragraph(encryption,                    styles["cell"]),
            Paragraph(f"<b>{risk_label}</b>",        styles["cell"]),
            Paragraph(threats,                       styles["cell"]),
        ]
        rows.append(row)

        # Alternating row background
        bg = colors.HexColor("#F5F5F5") if i % 2 == 0 else colors.white
        row_styles.append(("BACKGROUND", (0, i), (-1, i), bg))

        # Colour the Risk cell text
        row_styles.append(("TEXTCOLOR", (4, i), (4, i), risk_color))

    table = Table(rows, colWidths=col_w, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                # Header styling
                ("BACKGROUND",  (0, 0), (-1, 0), _BRAND_DARK),
                ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, 0), 8),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                ("TOPPADDING",    (0, 0), (-1, 0), 6),
                # Grid
                ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#CFD8DC")),
                ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",  (0, 1), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                *row_styles,
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 10))
    return story


def _section_gateway_audit(styles: dict, gateway_data: dict) -> list:
    story: list = []
    story.append(Paragraph("3. Gateway & DNS Audit", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT))
    story.append(Spacer(1, 6))

    # --- DNS Status ---
    dns = gateway_data.get("dns", {})
    dns_status  = _safe_text(dns.get("status", "Unknown"))
    dns_message = _safe_text(dns.get("message", "No details available."))
    dns_color   = _risk_colour(dns_status).hexval()

    story.append(Paragraph("DNS Integrity Check", styles["h2"]))
    story.append(
        Paragraph(
            f"Status: <b><font color='{dns_color}'>{dns_status}</font></b> — {dns_message}",
            styles["body"],
        )
    )

    # DNS canary details if present
    details = dns.get("details", [])
    if details:
        dns_rows = [[
            Paragraph("Host",     styles["cell_bold"]),
            Paragraph("Resolved", styles["cell_bold"]),
            Paragraph("Result",   styles["cell_bold"]),
        ]]
        for d in details:
            s = _safe_text(d.get("status", ""))
            dns_rows.append([
                Paragraph(_safe_text(d.get("host", "")),     styles["cell"]),
                Paragraph(_safe_text(d.get("resolved", "N/A")), styles["cell"]),
                Paragraph(
                    f"<font color='{_risk_colour(s).hexval()}'>{s}</font>",
                    styles["cell"]
                ),
            ])
        dns_table = Table(
            dns_rows,
            colWidths=[(_PAGE_W - 2 * _MARGIN) * r for r in (0.4, 0.35, 0.25)],
        )
        dns_table.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), _BRAND_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#CFD8DC")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ]))
        story.append(Spacer(1, 4))
        story.append(dns_table)

    story.append(Spacer(1, 8))

    # --- Port Exposure ---
    port_risk = gateway_data.get("port_risk", {})
    if isinstance(port_risk, dict):
        level  = _safe_text(port_risk.get("level", "UNKNOWN"))
        detail = _safe_text(port_risk.get("detail", ""))
        ports  = port_risk.get("ports", [])
    else:
        level, detail, ports = _safe_text(str(port_risk)), "", []

    port_color = _risk_colour(level).hexval()
    story.append(Paragraph("Router Port Exposure", styles["h2"]))
    story.append(
        Paragraph(
            f"Risk Level: <b><font color='{port_color}'>{level}</font></b>",
            styles["body"],
        )
    )
    if detail:
        story.append(Paragraph(detail, styles["body"]))
    if ports:
        story.append(
            Paragraph(f"Open ports detected: <b>{', '.join(str(p) for p in sorted(ports))}</b>", styles["body"])
        )

    story.append(Spacer(1, 10))
    return story


def _section_recommendations(styles: dict, networks: list[dict], gateway_data: dict) -> list:
    story: list = []
    story.append(Paragraph("4. Recommendations", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BRAND_ACCENT))
    story.append(Spacer(1, 6))

    recs: list[str] = []

    open_nets = [n for n in networks if "Open" in str(n.get("encryption", ""))]
    if open_nets:
        ssids = ", ".join(_safe_text(n.get("ssid", "?"), 20) for n in open_nets[:5])
        recs.append(
            f"<b>Avoid open networks:</b> {ssids} — these transmit all data "
            "unencrypted.  Use a VPN if connection is unavoidable."
        )

    wep_nets = [n for n in networks if "WEP" in str(n.get("encryption", "")).upper()]
    if wep_nets:
        recs.append(
            "<b>WEP networks detected:</b> WEP encryption is cryptographically "
            "broken and can be cracked in seconds.  Upgrade to WPA2 or WPA3 immediately."
        )

    port_risk = gateway_data.get("port_risk", {})
    level = port_risk.get("level", "") if isinstance(port_risk, dict) else ""
    if level in ("CRITICAL", "HIGH"):
        recs.append(
            "<b>Close exposed gateway ports:</b> Critical services (FTP, Telnet, SMB, RDP) "
            "should never be exposed on a home/office router.  Access the router admin "
            "panel and disable unnecessary services."
        )

    dns = gateway_data.get("dns", {})
    if dns.get("status") in ("Danger", "Warning"):
        recs.append(
            "<b>Investigate DNS settings:</b> DNS canary checks returned unexpected "
            "results.  Verify your router's DNS configuration and consider using "
            "a trusted resolver such as 1.1.1.1 or 8.8.8.8."
        )

    if not recs:
        recs.append(
            "No critical issues were identified in this scan.  Continue monitoring "
            "regularly and keep router firmware up to date."
        )

    for idx, rec in enumerate(recs, start=1):
        story.append(Paragraph(f"{idx}. {rec}", styles["body"]))
        story.append(Spacer(1, 5))

    return story


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SecurityReport:
    """
    Generates a complete Wi-Fi security audit PDF using ReportLab Platypus.

    Usage::

        report = SecurityReport()
        path = report.create_report(networks, gateway_data, "/tmp/audit.pdf")
    """

    def create_report(
        self,
        networks: list[dict],
        gateway_data: dict,
        filename: str = "security_audit_report.pdf",
    ) -> str:
        """
        Build and save the PDF report.

        Args:
            networks:     List of enriched network dicts from the scanner.
            gateway_data: Dict with ``dns`` and ``port_risk`` keys.
            filename:     Output file path (including .pdf extension).

        Returns:
            Absolute path to the saved PDF.
        """
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)

        generated_at = datetime.datetime.now(tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        report_title = "Wi-Fi Bastion — Security Audit Report"

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            leftMargin=_MARGIN,
            rightMargin=_MARGIN,
            topMargin=32 * mm,     # Space for the header bar
            bottomMargin=18 * mm,
            title=report_title,
            author="Wi-Fi Bastion",
            subject="Wireless Security Audit",
        )

        styles = _build_styles()

        # ---- Cover / title block ----
        story: list = [
            Spacer(1, 8 * mm),
            Paragraph(report_title, styles["title"]),
            Paragraph(f"Generated: {generated_at}", styles["subtitle"]),
            HRFlowable(width="100%", thickness=2, color=_BRAND_ACCENT),
            Spacer(1, 6 * mm),
        ]

        story += _section_executive_summary(styles, networks, gateway_data, generated_at)
        story += _section_network_table(styles, networks)
        story.append(PageBreak())
        story += _section_gateway_audit(styles, gateway_data)
        story += _section_recommendations(styles, networks, gateway_data)

        on_page = _make_page_template(report_title, generated_at)
        doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

        abs_path = os.path.abspath(filename)
        logger.info("Security report written to %s", abs_path)
        return abs_path