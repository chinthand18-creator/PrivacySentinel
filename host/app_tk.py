"""Privacy Sentinel - Tkinter desktop app.

Tkinter ships with Python, so nothing needs to be installed.
Run:  python app_tk.py
"""

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from security_engine import analyze_url, gather_live_intelligence, sha256_file

BG = "#090e18"
CARD = "#131a29"
INPUT_BG = "#1f2a3b"
TEAL = "#26e0c7"
BLUE = "#4785ff"
WHITE = "#ecf5ff"
MUTED = "#a1b0c9"
GREEN = "#40e094"
AMBER = "#ffb84d"
RED = "#ff5966"
FONT = ("Segoe UI", 10)


def resource_path(name):
    """Find a bundled file both in normal runs and inside the PyInstaller exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def format_live_result(result):
    lines = [
        f"Live status: {result.get('status', 'unknown').upper()}",
        result.get("message", ""),
        "",
    ]
    for name, details in result.get("results", {}).items():
        lines.append(f"{name}: {details.get('status', 'unknown')}")
        lines.append(details.get("message", ""))
        if name == "DNS":
            for address in details.get("addresses", []):
                kind = "public" if address["is_global"] else "non-public"
                lines.append(f"  • {address['address']} - {kind}")
        if name == "TLS" and details.get("status") == "success":
            lines.append(f"  TLS version: {details.get('tls_version', 'Unknown')}")
            lines.append(f"  Cipher: {details.get('cipher', 'Unknown')}")
            lines.append(f"  Valid until: {details.get('valid_until', 'Unknown')}")
        if name == "RDAP" and details.get("status") == "success":
            for event in details.get("events", []):
                if event.get("eventAction") in ("registration", "expiration"):
                    lines.append(
                        f"  {event['eventAction'].title()}: "
                        f"{event.get('eventDate', 'Unknown')}"
                    )
        lines.append("")
    return "\n".join(lines)


class PrivacySentinel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Privacy Sentinel")
        self.geometry("900x820")
        self.minsize(520, 640)
        self.configure(bg=BG)
        try:
            self.iconbitmap(resource_path("app.ico"))
        except tk.TclError:
            pass                      # icon is cosmetic; ignore on other platforms
        self.events = queue.Queue()   # worker threads -> UI thread
        self._build()
        self.after(100, self._poll)

    # ---------- layout helpers ----------
    def _label(self, parent, text, size=10, color=WHITE, bold=False, wrap=0):
        return tk.Label(
            parent, text=text, bg=parent["bg"], fg=color, anchor="w",
            justify="left", wraplength=wrap,
            font=("Segoe UI", size, "bold" if bold else "normal"),
        )

    def _button(self, parent, text, command, bg=TEAL, fg=BG):
        return tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg,
            activebackground=bg, activeforeground=fg, relief="flat",
            bd=0, padx=14, pady=9, cursor="hand2",
            font=("Segoe UI", 10, "bold"),
        )

    def _card(self, title, subtitle, side="top", expand=False):
        card = tk.Frame(self, bg=CARD, padx=16, pady=14)
        card.pack(
            side=side, fill="both" if expand else "x", expand=expand,
            padx=18, pady=(0, 12),
        )
        self._label(card, title, 12, TEAL, True).pack(fill="x")
        if subtitle:
            self._label(card, subtitle, 9, MUTED).pack(fill="x", pady=(2, 8))
        return card

    def _result_box(self, parent, height):
        frame = tk.Frame(parent, bg=CARD)
        frame.pack(fill="both", expand=True, pady=(10, 0))
        box = tk.Text(
            frame, height=height, wrap="word", bg=INPUT_BG, fg=MUTED,
            relief="flat", bd=0, padx=10, pady=8, font=("Consolas", 10),
            state="disabled",
        )
        bar = tk.Scrollbar(frame, command=box.yview)
        box.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        box.pack(side="left", fill="both", expand=True)
        return box

    def _set_text(self, box, text, color):
        box.configure(state="normal", fg=color)
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    # ---------- UI ----------
    def _build(self):
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=18, pady=(16, 10))
        self._label(head, "◈  PRIVACY SENTINEL", 20, TEAL, True).pack(fill="x")
        self._label(
            head,
            "Personal security toolkit  •  URL analysis  •  File integrity",
            10, MUTED,
        ).pack(fill="x")

        # Notes and file cards dock to the bottom so they are never clipped;
        # the URL card takes whatever space is left and its results scroll.
        note = self._card("03  /  PRIVACY NOTES", "", side="bottom")
        self._label(
            note,
            "• Local URL analysis does not contact the website.\n"
            "• Live checks send the hostname or URL to external services, and the "
            "TLS check connects directly to the website.\n"
            "• Safe Browsing requires an API key in the PRIVACY_SENTINEL_GSB_KEY "
            "environment variable.\n"
            "• A low risk score is not a guarantee that a website is safe.",
            9, MUTED, wrap=820,
        ).pack(fill="x")

        file_card = self._card(
            "02  /  FILE INTEGRITY",
            "Calculate a SHA-256 fingerprint for a selected file.",
            side="bottom",
        )
        self._button(
            file_card, "Choose File and Calculate SHA-256", self.choose_file
        ).pack(fill="x")
        self.file_box = self._result_box(file_card, 3)
        self._set_text(self.file_box, "No file selected.", MUTED)

        url_card = self._card(
            "01  /  URL SECURITY CHECK",
            "Enter a website address to inspect common warning signs.",
            expand=True,
        )
        self.url_entry = tk.Entry(
            url_card, bg=INPUT_BG, fg=WHITE, insertbackground=TEAL,
            relief="flat", bd=0, font=("Segoe UI", 11),
        )
        self.url_entry.pack(fill="x", ipady=9)
        self.url_entry.bind("<Return>", lambda _e: self.run_local_analysis())

        row = tk.Frame(url_card, bg=CARD)
        row.pack(fill="x", pady=(10, 0))
        self._button(row, "Analyze URL", self.run_local_analysis).pack(
            side="left", expand=True, fill="x", padx=(0, 6))
        self.live_button = self._button(
            row, "Live Checks", self.confirm_live_lookup, BLUE, "white")
        self.live_button.pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.url_box = self._result_box(url_card, 8)
        self._set_text(self.url_box, "Your analysis results will appear here.", MUTED)

    # ---------- URL analysis ----------
    def run_local_analysis(self):
        result = analyze_url(self.url_entry.get())
        color = {"INVALID": RED, "HIGH": RED, "REVIEW": AMBER}.get(
            result["level"], GREEN)

        lines = [f"Risk level: {result['level']}   |   Score: {result['score']}/100", ""]
        lines.extend(f"• {finding}" for finding in result["findings"])
        if result.get("url_details"):
            lines += [
                "",
                f"Hostname: {result.get('hostname', '-')}",
                f"Protocol: {result.get('scheme', '-').upper()}",
            ]
        self._set_text(self.url_box, "\n".join(lines), color)

    def confirm_live_lookup(self):
        url = self.url_entry.get().strip()
        if not url:
            self._set_text(self.url_box, "Enter a URL first.", AMBER)
            return
        if not messagebox.askokcancel(
            "Confirm live lookup",
            "Live checks send the hostname or URL to external services (DNS "
            "resolver, rdap.org, and Google Safe Browsing if configured), and "
            "the TLS check connects directly to the website, which can see "
            "your IP address.\n\nContinue only if you are comfortable with that.",
            parent=self,
        ):
            return

        self.live_button.configure(state="disabled")
        self._set_text(self.url_box, "Running live checks… please wait.", AMBER)

        def worker():
            try:
                result = gather_live_intelligence(url)
                text = format_live_result(result)
                threat = any(
                    d.get("status") == "threats_found"
                    for d in result.get("results", {}).values()
                )
                color = RED if threat else WHITE
            except Exception as exc:  # never leave the UI stuck on "please wait"
                text, color = f"Live checks failed unexpectedly: {exc}", RED
            self.events.put(("url", text, color))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- file hashing ----------
    def choose_file(self):
        selected = filedialog.askopenfilename(
            parent=self, title="Choose a file", initialdir=str(Path.home()))
        if not selected:
            return
        name = Path(selected).name
        self._set_text(self.file_box, f"Calculating SHA-256 for {name}…", AMBER)

        def worker():
            try:
                text = f"File: {name}\nSHA-256:\n{sha256_file(selected)}"
                color = GREEN
            except (OSError, ValueError) as exc:
                text, color = f"Could not read file: {exc}", RED
            self.events.put(("file", text, color))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- thread-safe UI updates ----------
    def _poll(self):
        try:
            while True:
                kind, text, color = self.events.get_nowait()
                if kind == "url":
                    self._set_text(self.url_box, text, color)
                    self.live_button.configure(state="normal")
                else:
                    self._set_text(self.file_box, text, color)
        except queue.Empty:
            pass
        self.after(100, self._poll)


if __name__ == "__main__":
    PrivacySentinel().mainloop()
