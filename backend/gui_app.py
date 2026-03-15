"""
gui_app.py — Wi-Fi Bastion Desktop GUI
========================================
A standalone tkinter desktop application that talks to the Flask backend
via HTTP. No additional dependencies — uses only Python stdlib.

Run:
    python gui_app.py

Requirements:
    - Backend (app.py) must be running on localhost:5000
    - Python 3.10+
    - tkinter (included with standard Python on Windows/macOS)
      Linux: sudo apt install python3-tk
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
import urllib.error
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk
from typing import Any

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

API_BASE    = os.getenv("BASTION_API", "http://127.0.0.1:5000/api")
API_KEY     = os.getenv("API_KEY", "")
REFRESH_MS  = 8000   # how often the live panels auto-refresh (ms)

# ---------------------------------------------------------------------------
# Colour palette (dark cybersecurity theme)
# ---------------------------------------------------------------------------

C = {
    "bg":         "#0b0e13",
    "surface":    "#111520",
    "elevated":   "#161b27",
    "border":     "#1e2635",
    "text_high":  "#c8d3e0",
    "text_mid":   "#7e8fa4",
    "text_low":   "#4a5568",
    "blue":       "#3b7dd8",
    "teal":       "#2d7d6f",
    "red":        "#c0392b",
    "amber":      "#b45309",
    "green":      "#2d7d6f",
    "white":      "#e2eaf4",
}

# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _api(path: str, method: str = "GET", body: dict | None = None,
         timeout: int = 10) -> dict | list | None:
    """Make an API call, return parsed JSON or None on error."""
    url = f"{API_BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    try:
        data = json.dumps(body).encode() if body else None
        req  = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}: {e.reason}"}
    except urllib.error.URLError as e:
        return {"_error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}


def _get_list(path: str, key: str | None = None) -> list:
    """Get a list from the API, unwrapping the new {status, data} envelope."""
    result = _api(path)
    if result is None:
        return []
    if isinstance(result, list):
        return result
    data = result.get("data", result)
    if key and isinstance(data, dict):
        data = data.get(key, [])
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Reusable widget helpers
# ---------------------------------------------------------------------------

def _label(parent, text, fg=None, bg=None, font_size=10, bold=False,
           anchor="w", padx=0, pady=0):
    f = ("Consolas", font_size, "bold" if bold else "normal")
    w = tk.Label(parent, text=text,
                 fg=fg or C["text_mid"], bg=bg or C["surface"],
                 font=f, anchor=anchor, padx=padx, pady=pady)
    return w


def _separator(parent, bg=None):
    return tk.Frame(parent, height=1, bg=bg or C["border"])


def _scrolled(parent, height=10, fg=None, bg=None, font_size=9):
    st = scrolledtext.ScrolledText(
        parent, height=height, wrap=tk.WORD,
        fg=fg or C["text_mid"], bg=bg or C["elevated"],
        insertbackground=C["text_high"],
        relief=tk.FLAT, borderwidth=0,
        font=("Consolas", font_size),
        padx=8, pady=6,
    )
    st.config(state=tk.DISABLED)
    return st


def _write(widget, text):
    widget.config(state=tk.NORMAL)
    widget.delete("1.0", tk.END)
    widget.insert(tk.END, text)
    widget.config(state=tk.DISABLED)


def _btn(parent, text, cmd, bg=None, fg=None, width=None):
    kw = dict(
        text=text, command=cmd,
        bg=bg or C["blue"], fg=fg or C["white"],
        relief=tk.FLAT, cursor="hand2",
        font=("Consolas", 9, "bold"),
        padx=10, pady=4,
        activebackground=C["elevated"],
        activeforeground=C["white"],
        borderwidth=0,
    )
    if width:
        kw["width"] = width
    return tk.Button(parent, **kw)


# ---------------------------------------------------------------------------
# Individual tab panels
# ---------------------------------------------------------------------------

class DashboardTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._build()
        self.after(500, self._refresh)

    def _build(self):
        # Stat bar
        sf = tk.Frame(self, bg=C["surface"], pady=8)
        sf.pack(fill=tk.X, padx=10, pady=(10, 0))

        self._stats = {}
        for label, key, color in [
            ("Logged Sessions", "total",   C["blue"]),
            ("With Threats",    "threats", C["red"]),
            ("Clean Scans",     "clean",   C["teal"]),
            ("Blacklisted",     "blocked", C["amber"]),
        ]:
            col = tk.Frame(sf, bg=C["surface"], padx=20)
            col.pack(side=tk.LEFT, fill=tk.X, expand=True)
            val_lbl = tk.Label(col, text="—", fg=color, bg=C["surface"],
                               font=("Consolas", 20, "bold"))
            val_lbl.pack()
            tk.Label(col, text=label.upper(), fg=C["text_low"], bg=C["surface"],
                     font=("Consolas", 7)).pack()
            _separator(col, C["border"]).pack(fill=tk.X, pady=4)
            self._stats[key] = val_lbl

        # Recent networks
        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X, padx=10, pady=6)
        _label(self, "  RECENT NETWORKS", C["text_low"], C["bg"],
               font_size=8, bold=True).pack(anchor="w", padx=10)

        cols = ("SSID", "Trust", "Encryption", "Status")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=10)
        self._style_tree()
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=160 if c == "SSID" else 90)
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))

        bf = tk.Frame(self, bg=C["bg"])
        bf.pack(fill=tk.X, padx=10, pady=(0, 10))
        _btn(bf, "↻  Refresh", self._refresh).pack(side=tk.LEFT)
        self._status = _label(bf, "", C["text_low"], C["bg"], font_size=8)
        self._status.pack(side=tk.LEFT, padx=12)

    def _style_tree(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background=C["elevated"], foreground=C["text_mid"],
                        fieldbackground=C["elevated"], rowheight=24,
                        font=("Consolas", 9), borderwidth=0)
        style.configure("Treeview.Heading",
                        background=C["surface"], foreground=C["text_low"],
                        font=("Consolas", 8, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", C["blue"])])

    def _refresh(self):
        self._status.config(text="Loading...")
        threading.Thread(target=self._fetch, daemon=True).start()
        self.after(REFRESH_MS, self._refresh)

    def _fetch(self):
        history = _get_list("/history", "scans")
        blocked = _get_list("/blocked", "blocked")
        threats = [h for h in history if h.get("threats")]

        self.after(0, lambda: self._update(history, blocked, threats))

    def _update(self, history, blocked, threats):
        self._stats["total"].config(text=str(len(history)))
        self._stats["threats"].config(text=str(len(threats)))
        self._stats["clean"].config(text=str(len(history) - len(threats)))
        self._stats["blocked"].config(text=str(len(blocked)))

        for row in self._tree.get_children():
            self._tree.delete(row)

        for h in history[:30]:
            score = h.get("trust_score", 0)
            tag   = "safe" if score >= 80 else "warn" if score >= 50 else "danger"
            thrs  = h.get("threats", [])
            status = "✓ Clean" if not thrs else f"⚠ {len(thrs)} threat(s)"
            self._tree.insert("", tk.END, values=(
                h.get("ssid", "—"),
                f"{score}/100",
                h.get("encryption", "—"),
                status,
            ), tags=(tag,))

        self._tree.tag_configure("safe",   foreground=C["teal"])
        self._tree.tag_configure("warn",   foreground=C["amber"])
        self._tree.tag_configure("danger", foreground=C["red"])
        self._status.config(text=f"Updated {time.strftime('%H:%M:%S')}")


class ScannerTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._scanning = False
        self._networks = []
        self._build()

    def _build(self):
        bf = tk.Frame(self, bg=C["bg"], pady=8)
        bf.pack(fill=tk.X, padx=10)

        self._scan_btn = _btn(bf, "▶  Run Scan", self._start_scan)
        self._scan_btn.pack(side=tk.LEFT)

        _btn(bf, "⊘  Block Selected", self._block_selected,
             bg=C["red"]).pack(side=tk.LEFT, padx=(8, 0))

        self._scan_status = _label(bf, "  Ready.", C["text_low"], C["bg"], 8)
        self._scan_status.pack(side=tk.LEFT, padx=8)

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=4)

        cols = ("#", "SSID", "BSSID", "Vendor", "Signal", "Encryption", "Trust", "Threats")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        self._style_tree()

        widths = [30, 160, 130, 120, 60, 100, 60, 160]
        for c, w in zip(cols, widths):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, minwidth=w)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=(0, 10))
        vsb.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 10), padx=(0, 10))

        self._progress = ttk.Progressbar(self, mode="indeterminate", length=200)

    def _style_tree(self):
        style = ttk.Style()
        style.configure("Scan.Treeview",
                        background=C["elevated"], foreground=C["text_mid"],
                        fieldbackground=C["elevated"], rowheight=22,
                        font=("Consolas", 8), borderwidth=0)
        self._tree.configure(style="Scan.Treeview")

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._scan_btn.config(state=tk.DISABLED, text="Scanning...")
        self._scan_status.config(text="  Probing spectrum...")
        self._progress.pack(fill=tk.X, padx=10, pady=4)
        self._progress.start(12)
        threading.Thread(target=self._fetch_scan, daemon=True).start()

    def _fetch_scan(self):
        result = _api("/scan", "POST")
        self.after(0, lambda: self._on_scan_done(result))

    def _on_scan_done(self, result):
        self._scanning = False
        self._scan_btn.config(state=tk.NORMAL, text="▶  Run Scan")
        self._progress.stop()
        self._progress.pack_forget()

        if result is None or "_error" in (result or {}):
            err = (result or {}).get("_error", "Unknown error")
            self._scan_status.config(text=f"  ✕ Error: {err}")
            return

        # Extract networks from envelope
        networks = []
        if isinstance(result, list):
            networks = result
        elif isinstance(result, dict):
            data = result.get("data", result)
            if isinstance(data, dict):
                networks = data.get("networks", [])
            elif isinstance(data, list):
                networks = data

        self._networks = networks
        self._populate(networks)
        self._scan_status.config(text=f"  ✓ {len(networks)} networks found — {time.strftime('%H:%M:%S')}")

    def _populate(self, networks):
        for row in self._tree.get_children():
            self._tree.delete(row)

        for i, net in enumerate(networks, 1):
            score  = net.get("trust_score", 0)
            thrs   = net.get("threats", [])
            threat_str = ", ".join(thrs) if thrs else "—"
            tag    = "safe" if score >= 80 else "warn" if score >= 50 else "danger"
            sig    = net.get("signal")
            sig_str = f"{sig} dBm" if isinstance(sig, int) else "—"

            self._tree.insert("", tk.END, iid=str(i - 1), values=(
                i,
                net.get("ssid", "Hidden"),
                net.get("bssid", "—"),
                net.get("vendor", "—"),
                sig_str,
                net.get("encryption", "—"),
                f"{score}/100",
                threat_str,
            ), tags=(tag,))

        self._tree.tag_configure("safe",   foreground=C["teal"])
        self._tree.tag_configure("warn",   foreground=C["amber"])
        self._tree.tag_configure("danger", foreground=C["red"])

    def _block_selected(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Block Network", "Select a network first.")
            return
        idx = int(sel[0])
        if idx >= len(self._networks):
            return
        net  = self._networks[idx]
        ssid = net.get("ssid", "Unknown")
        if not messagebox.askyesno("Block Network",
                                   f"Block '{ssid}' at OS level?\n"
                                   "This prevents Windows from connecting to it."):
            return
        result = _api("/block_network", "POST", {
            "network_id": net.get("_id"),
            "bssid":      net.get("bssid"),
            "ssid":       ssid,
        })
        if result and not result.get("_error"):
            messagebox.showinfo("Blocked", f"'{ssid}' has been restricted.")
            self._start_scan()
        else:
            err = (result or {}).get("_error", "Unknown error")
            messagebox.showerror("Block Failed", err)


class AlertsTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._build()
        self.after(500, self._refresh)

    def _build(self):
        bf = tk.Frame(self, bg=C["bg"], pady=8)
        bf.pack(fill=tk.X, padx=10)
        _btn(bf, "↻  Refresh", self._refresh).pack(side=tk.LEFT)
        self._auto_var = tk.BooleanVar(value=True)
        tk.Checkbutton(bf, text="Auto-refresh (10s)", variable=self._auto_var,
                       bg=C["bg"], fg=C["text_mid"], selectcolor=C["elevated"],
                       activebackground=C["bg"], font=("Consolas", 9)).pack(side=tk.LEFT, padx=10)
        self._status = _label(bf, "", C["text_low"], C["bg"], 8)
        self._status.pack(side=tk.LEFT)

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=4)

        self._feed = _scrolled(self, height=20, font_size=9)
        self._feed.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self._feed.tag_config("critical", foreground=C["red"])
        self._feed.tag_config("high",     foreground="#c05621")
        self._feed.tag_config("medium",   foreground=C["amber"])
        self._feed.tag_config("time",     foreground=C["text_low"])
        self._feed.tag_config("type",     foreground=C["blue"])
        self._feed.tag_config("ok",       foreground=C["teal"])

    def _refresh(self):
        threading.Thread(target=self._fetch, daemon=True).start()
        if self._auto_var.get():
            self.after(10000, self._refresh)

    def _fetch(self):
        alerts = _get_list("/security_alerts", "alerts")
        self.after(0, lambda: self._update(alerts))

    def _update(self, alerts):
        self._feed.config(state=tk.NORMAL)
        self._feed.delete("1.0", tk.END)

        if not alerts:
            self._feed.insert(tk.END, "✓  No active threats detected.\n\n"
                              "All monitored vectors are clear.\n", "ok")
        else:
            self._feed.insert(tk.END, f"  {len(alerts)} Active Alert(s)\n\n", "type")
            for a in alerts:
                sev    = (a.get("severity") or "INFO").upper()
                ts_raw = a.get("timestamp")
                ts_str = time.strftime("%H:%M:%S", time.localtime(ts_raw)) if ts_raw else "—"
                tag    = sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM") else "medium"

                self._feed.insert(tk.END, f"[{ts_str}]  ", "time")
                self._feed.insert(tk.END, f"{sev}  ", tag)
                self._feed.insert(tk.END, f"{a.get('type', 'ALERT')}\n", "type")
                self._feed.insert(tk.END, f"  {a.get('message', '')}\n\n")

        self._feed.config(state=tk.DISABLED)
        self._status.config(text=f"Updated {time.strftime('%H:%M:%S')}")


class GatewayTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._build()

    def _build(self):
        bf = tk.Frame(self, bg=C["bg"], pady=8)
        bf.pack(fill=tk.X, padx=10)
        self._audit_btn = _btn(bf, "▶  Run Gateway Audit", self._run_audit)
        self._audit_btn.pack(side=tk.LEFT)
        self._status = _label(bf, "  Click to audit your gateway.", C["text_low"], C["bg"], 8)
        self._status.pack(side=tk.LEFT, padx=8)

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=4)

        # DNS section
        _label(self, "  DNS INTEGRITY", C["text_low"], C["bg"],
               font_size=8, bold=True).pack(anchor="w", padx=10, pady=(6, 2))
        self._dns_text = _scrolled(self, height=7)
        self._dns_text.pack(fill=tk.X, padx=10)
        self._dns_text.tag_config("safe",    foreground=C["teal"])
        self._dns_text.tag_config("danger",  foreground=C["red"])
        self._dns_text.tag_config("warning", foreground=C["amber"])
        self._dns_text.tag_config("label",   foreground=C["blue"])

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=6)

        # Port section
        _label(self, "  PORT EXPOSURE", C["text_low"], C["bg"],
               font_size=8, bold=True).pack(anchor="w", padx=10, pady=(0, 2))
        self._port_text = _scrolled(self, height=7)
        self._port_text.pack(fill=tk.X, padx=10, pady=(0, 10))
        self._port_text.tag_config("critical", foreground=C["red"])
        self._port_text.tag_config("ok",       foreground=C["teal"])
        self._port_text.tag_config("port",     foreground=C["amber"])

    def _run_audit(self):
        self._audit_btn.config(state=tk.DISABLED, text="Auditing...")
        self._status.config(text="  Probing gateway...")
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        result = _api("/gateway_audit")
        self.after(0, lambda: self._update(result))

    def _update(self, result):
        self._audit_btn.config(state=tk.NORMAL, text="▶  Run Gateway Audit")

        if not result or result.get("_error"):
            self._status.config(text=f"  ✕ {(result or {}).get('_error', 'Failed')}")
            return

        data = result.get("data", result)
        dns  = data.get("dns", {})
        pr   = data.get("port_risk", {})

        # ── DNS ──
        self._dns_text.config(state=tk.NORMAL)
        self._dns_text.delete("1.0", tk.END)
        status = dns.get("status", "Unknown")
        tag    = "safe" if status == "Safe" else "danger" if status == "Danger" else "warning"
        self._dns_text.insert(tk.END, f"Status: ", "label")
        self._dns_text.insert(tk.END, f"{status}\n", tag)
        self._dns_text.insert(tk.END, f"Message: {dns.get('message', '—')}\n\n")

        for d in dns.get("details", []):
            s = d.get("status", "")
            t = "safe" if s == "Safe" else "danger" if s == "Danger" else "warning"
            self._dns_text.insert(tk.END,
                f"  {d.get('host','?')}  →  {d.get('resolved','N/A')}  [{s}]\n", t)
        self._dns_text.config(state=tk.DISABLED)

        # ── Ports ──
        self._port_text.config(state=tk.NORMAL)
        self._port_text.delete("1.0", tk.END)
        level = pr.get("level", "—")
        ptag  = "ok" if level == "LOW" else "critical"
        self._port_text.insert(tk.END, f"Risk Level: ", "label" if hasattr(self, '_dns_text') else "")
        self._port_text.insert(tk.END, f"{level}\n", ptag)
        self._port_text.insert(tk.END, f"{pr.get('detail', '—')}\n\n")

        risky = pr.get("risky", [])
        if risky:
            self._port_text.insert(tk.END, "Dangerous ports: ", )
            self._port_text.insert(tk.END, ", ".join(str(p) for p in risky) + "\n", "critical")

        normal = pr.get("normal", [])
        if normal:
            self._port_text.insert(tk.END, "Normal router ports: ", )
            self._port_text.insert(tk.END, ", ".join(str(p) for p in normal) + "\n", "ok")
        self._port_text.config(state=tk.DISABLED)

        self._status.config(text=f"  ✓ Audit complete — {time.strftime('%H:%M:%S')}")


class BlockedTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._blocked = []
        self._build()
        self.after(500, self._refresh)

    def _build(self):
        bf = tk.Frame(self, bg=C["bg"], pady=8)
        bf.pack(fill=tk.X, padx=10)
        _btn(bf, "↻  Refresh",         self._refresh).pack(side=tk.LEFT)
        _btn(bf, "⊘  Release Selected", self._release,
             bg=C["amber"]).pack(side=tk.LEFT, padx=(8, 0))
        self._status = _label(bf, "", C["text_low"], C["bg"], 8)
        self._status.pack(side=tk.LEFT, padx=8)

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=4)

        cols = ("#", "SSID", "BSSID", "Date Blocked")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c, w in zip(cols, [30, 200, 150, 180]):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w)
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self._tree.tag_configure("blocked", foreground=C["red"])

    def _refresh(self):
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        blocked = _get_list("/blocked", "blocked")
        self.after(0, lambda: self._update(blocked))

    def _update(self, blocked):
        self._blocked = blocked
        for row in self._tree.get_children():
            self._tree.delete(row)
        for i, net in enumerate(blocked, 1):
            ts_raw = net.get("blocked_at") or net.get("timestamp")
            if ts_raw:
                try:
                    from datetime import datetime, timezone
                    if isinstance(ts_raw, str):
                        dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    else:
                        dt = datetime.fromtimestamp(ts_raw, tz=timezone.utc)
                    ts_str = dt.strftime("%d %b %Y  %H:%M")
                except Exception:
                    ts_str = str(ts_raw)
            else:
                ts_str = "—"
            self._tree.insert("", tk.END, iid=str(i - 1),
                              values=(i, net.get("ssid", "—"), net.get("bssid", "—"), ts_str),
                              tags=("blocked",))
        self._status.config(text=f"{len(blocked)} active restriction(s) — {time.strftime('%H:%M:%S')}")

    def _release(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Release", "Select a network to release.")
            return
        idx = int(sel[0])
        if idx >= len(self._blocked):
            return
        net  = self._blocked[idx]
        ssid = net.get("ssid", "Unknown")
        if not messagebox.askyesno("Release Filter",
                                   f"Release OS-level filter for '{ssid}'?"):
            return
        result = _api("/unblock_network", "POST", {
            "network_id": net.get("_id"),
            "ssid":       ssid,
        })
        if result and not result.get("_error"):
            messagebox.showinfo("Released", f"'{ssid}' is now unrestricted.")
            self._refresh()
        else:
            err = (result or {}).get("_error", "Unknown error")
            messagebox.showerror("Failed", err)


class LogTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self._build()
        self.after(500, self._refresh)

    def _build(self):
        bf = tk.Frame(self, bg=C["bg"], pady=8)
        bf.pack(fill=tk.X, padx=10)
        _btn(bf, "↻  Refresh", self._refresh).pack(side=tk.LEFT)
        _btn(bf, "🗑  Clear Archive", self._clear,
             bg="#2a1010", fg=C["red"]).pack(side=tk.LEFT, padx=(8, 0))
        self._status = _label(bf, "", C["text_low"], C["bg"], 8)
        self._status.pack(side=tk.LEFT, padx=8)

        _separator(self, C["border"]).pack(fill=tk.X, padx=10, pady=4)

        self._log = _scrolled(self, height=20)
        self._log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self._log.tag_config("threat", foreground=C["red"])
        self._log.tag_config("clean",  foreground=C["teal"])
        self._log.tag_config("ssid",   foreground=C["blue"])
        self._log.tag_config("meta",   foreground=C["text_low"])

    def _refresh(self):
        threading.Thread(target=self._fetch, daemon=True).start()

    def _fetch(self):
        history = _get_list("/history", "scans")
        self.after(0, lambda: self._update(history))

    def _update(self, history):
        self._log.config(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)

        if not history:
            self._log.insert(tk.END, "No scan history found.\nRun a scan to populate the archive.\n", "meta")
        else:
            for h in history[:100]:
                ts_raw = h.get("timestamp")
                ts_str = time.strftime("%d %b %H:%M:%S", time.localtime(
                    ts_raw if ts_raw and ts_raw > 1e10 else (ts_raw or 0) * 1000 / 1000
                )) if ts_raw else "—"
                thrs = h.get("threats", [])
                self._log.insert(tk.END, f"[{ts_str}]  ", "meta")
                self._log.insert(tk.END, f"{h.get('ssid', '—')}", "ssid")
                self._log.insert(tk.END,
                    f"  {h.get('encryption', '—')}  score={h.get('trust_score', '—')}\n", "meta")
                if thrs:
                    for t in thrs:
                        self._log.insert(tk.END, f"  ⚠ {t}\n", "threat")
                else:
                    self._log.insert(tk.END, "  ✓ Clean\n", "clean")
                self._log.insert(tk.END, "\n")

        self._log.config(state=tk.DISABLED)
        self._status.config(text=f"{len(history)} records — {time.strftime('%H:%M:%S')}")

    def _clear(self):
        if not messagebox.askyesno("Clear Archive",
                                   "Permanently delete all scan history?"):
            return
        result = _api("/history", "DELETE")
        if result and not result.get("_error"):
            messagebox.showinfo("Cleared", "Archive purged successfully.")
            self._refresh()
        else:
            messagebox.showerror("Failed", "Could not clear archive.")


# ---------------------------------------------------------------------------
# Status bar
# ---------------------------------------------------------------------------

class StatusBar(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=C["surface"], pady=4)
        self._dot   = tk.Label(self, text="●", bg=C["surface"], font=("Consolas", 9))
        self._dot.pack(side=tk.LEFT, padx=(10, 4))
        self._text  = tk.Label(self, text="Connecting...", fg=C["text_low"],
                               bg=C["surface"], font=("Consolas", 8))
        self._text.pack(side=tk.LEFT)
        self._clock = tk.Label(self, text="", fg=C["text_low"],
                               bg=C["surface"], font=("Consolas", 8))
        self._clock.pack(side=tk.RIGHT, padx=10)
        self._tick_clock()
        self._check_backend()

    def _tick_clock(self):
        self._clock.config(text=time.strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _check_backend(self):
        threading.Thread(target=self._ping, daemon=True).start()
        self.after(8000, self._check_backend)

    def _ping(self):
        result = _api("/health", timeout=3)
        online = result and not result.get("_error")
        self.after(0, lambda: self._set_status(online))

    def _set_status(self, online: bool):
        if online:
            self._dot.config(fg=C["teal"])
            self._text.config(text="Backend connected", fg=C["teal"])
        else:
            self._dot.config(fg=C["red"])
            self._text.config(text="Backend offline — start app.py", fg=C["red"])


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class BastionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi Bastion — Threat Intelligence Platform")
        self.configure(bg=C["bg"])
        self.geometry("1100x700")
        self.minsize(900, 600)
        self._build_ui()

    def _build_ui(self):
        # Title bar
        header = tk.Frame(self, bg=C["surface"], pady=10)
        header.pack(fill=tk.X)
        tk.Label(header, text="  Wi-Fi Bastion",
                 fg=C["text_high"], bg=C["surface"],
                 font=("Consolas", 14, "bold")).pack(side=tk.LEFT, padx=6)
        tk.Label(header, text="Threat Intelligence Platform",
                 fg=C["text_low"], bg=C["surface"],
                 font=("Consolas", 9)).pack(side=tk.LEFT)
        tk.Frame(header, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y, padx=12)
        tk.Label(header, text="v1.0.0",
                 fg=C["text_low"], bg=C["surface"],
                 font=("Consolas", 8)).pack(side=tk.LEFT)

        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X)

        # Notebook
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.TNotebook",
                        background=C["surface"], borderwidth=0, tabmargins=0)
        style.configure("Dark.TNotebook.Tab",
                        background=C["surface"], foreground=C["text_low"],
                        padding=(16, 6), font=("Consolas", 9),
                        borderwidth=0)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", C["bg"]), ("active", C["elevated"])],
                  foreground=[("selected", C["blue"]),  ("active", C["text_high"])])

        nb = ttk.Notebook(self, style="Dark.TNotebook")
        nb.pack(fill=tk.BOTH, expand=True)

        tabs = [
            ("Overview",      DashboardTab),
            ("Scanner",       ScannerTab),
            ("Alerts",        AlertsTab),
            ("Gateway",       GatewayTab),
            ("Restricted",    BlockedTab),
            ("Archive",       LogTab),
        ]
        for name, cls in tabs:
            frame = cls(nb)
            nb.add(frame, text=f"  {name}  ")

        # Status bar
        tk.Frame(self, bg=C["border"], height=1).pack(fill=tk.X)
        StatusBar(self).pack(fill=tk.X, side=tk.BOTTOM)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    # On Windows, hide the console window if launched via pythonw
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass

    app = BastionApp()
    app.mainloop()


if __name__ == "__main__":
    main()