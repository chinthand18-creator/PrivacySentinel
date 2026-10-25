
"""Privacy Sentinel — Kivy desktop dashboard."""

from pathlib import Path
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput

from security_engine import analyze_url, gather_live_intelligence, sha256_file

BG = (0.035, 0.055, 0.095, 1)
CARD = (0.075, 0.105, 0.16, 1)
INPUT_BG = (0.12, 0.16, 0.23, 1)
TEAL = (0.15, 0.88, 0.78, 1)
BLUE = (0.28, 0.52, 1, 1)
WHITE = (0.93, 0.96, 1, 1)
MUTED = (0.63, 0.69, 0.79, 1)
GREEN = (0.25, 0.88, 0.58, 1)
AMBER = (1, 0.72, 0.30, 1)
RED = (1, 0.35, 0.4, 1)


def make_label(text, size=14, color=WHITE, bold=False, height=None):
    label = Label(
        text=text,
        font_size=dp(size),
        color=color,
        bold=bold,
        halign="left",
        valign="middle",
        size_hint_y=None,
        height=dp(height or 32),
    )
    label.bind(size=lambda obj, _: setattr(obj, "text_size", (obj.width, None)))
    return label


def make_button(text, color=TEAL, text_color=BG):
    button = Button(
        text=text,
        size_hint_y=None,
        height=dp(44),
        background_normal="",
        background_down="",
        background_color=color,
        color=text_color,
        bold=True,
        font_size=dp(14),
    )
    return button


def make_card():
    card = BoxLayout(
        orientation="vertical",
        spacing=dp(9),
        padding=dp(15),
        size_hint_y=None,
    )
    card.bind(minimum_height=card.setter("height"))
    with card.canvas.before:
        card._bg_color = Color(*CARD)
        card._bg_rect = RoundedRectangle(
            pos=card.pos, size=card.size, radius=[dp(14)]
        )
    card.bind(
        pos=lambda obj, _: setattr(obj._bg_rect, "pos", obj.pos),
        size=lambda obj, _: setattr(obj._bg_rect, "size", obj.size),
    )
    return card


class PrivacySentinel(App):
    title = "Privacy Sentinel"

    def build(self):
        Window.clearcolor = BG
        Window.size = (1000, 850)
        Window.minimum_width = 360
        Window.minimum_height = 600

        root = BoxLayout(
            orientation="vertical",
            padding=dp(16),
            spacing=dp(12),
        )

        header = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            height=dp(90),
            spacing=dp(3),
        )
        header.add_widget(make_label("◈  PRIVACY SENTINEL", 24, TEAL, True, 38))
        header.add_widget(make_label(
            "Personal security toolkit  •  URL analysis  •  File integrity",
            12, MUTED, False, 25,
        ))
        root.add_widget(header)

        scroll = ScrollView(do_scroll_x=False)
        content = BoxLayout(
            orientation="vertical",
            spacing=dp(12),
            size_hint_y=None,
        )
        content.bind(minimum_height=content.setter("height"))
        scroll.add_widget(content)
        root.add_widget(scroll)

        # URL analysis panel
        url_card = make_card()
        url_card.add_widget(make_label("01  /  URL SECURITY CHECK", 16, TEAL, True))
        url_card.add_widget(make_label(
            "Enter a website address to inspect common warning signs.",
            12, MUTED, False, 28,
        ))

        self.url_input = TextInput(
            hint_text="https://example.com",
            multiline=False,
            size_hint_y=None,
            height=dp(48),
            padding=(dp(12), dp(12)),
            background_normal="",
            background_active="",
            background_color=INPUT_BG,
            foreground_color=WHITE,
            hint_text_color=MUTED,
            cursor_color=TEAL,
        )
        url_card.add_widget(self.url_input)

        button_row = BoxLayout(
            size_hint_y=None, height=dp(44), spacing=dp(8)
        )
        analyze_button = make_button("Analyze URL", TEAL)
        live_button = make_button("Live Checks", BLUE, WHITE)
        analyze_button.bind(on_release=self.run_local_analysis)
        live_button.bind(on_release=self.confirm_live_lookup)
        button_row.add_widget(analyze_button)
        button_row.add_widget(live_button)
        url_card.add_widget(button_row)

        self.url_results = make_label(
            "Your analysis results will appear here.",
            13, MUTED, False, 70,
        )
        url_card.add_widget(self.url_results)
        content.add_widget(url_card)

        # File hashing panel
        file_card = make_card()
        file_card.add_widget(make_label("02  /  FILE INTEGRITY", 16, TEAL, True))
        file_card.add_widget(make_label(
            "Calculate a SHA-256 fingerprint for a selected file.",
            12, MUTED, False, 28,
        ))
        choose_button = make_button("Choose File and Calculate SHA-256")
        choose_button.bind(on_release=self.open_file_picker)
        file_card.add_widget(choose_button)

        self.file_results = make_label(
            "No file selected.", 12, MUTED, False, 85
        )
        file_card.add_widget(self.file_results)
        content.add_widget(file_card)

        # Privacy notice
        note_card = make_card()
        note_card.add_widget(make_label("03  /  PRIVACY NOTES", 16, TEAL, True))
        note_card.add_widget(make_label(
            "• Local URL analysis does not contact the website.\n"
            "• Live checks send the submitted URL or hostname to external services.\n"
            "• Safe Browsing requires an API key in an environment variable.\n"
            "• A low risk score is not a guarantee that a website is safe.",
            12, MUTED, False, 105,
        ))
        content.add_widget(note_card)

        root.add_widget(make_label(
            "PRIVACY SENTINEL  •  Student cybersecurity project",
            10, MUTED, False, 22,
        ))
        return root

    def run_local_analysis(self, _button):
        result = analyze_url(self.url_input.text)
        if result["level"] == "INVALID":
            self.url_results.color = RED
        elif result["level"] == "HIGH":
            self.url_results.color = RED
        elif result["level"] == "REVIEW":
            self.url_results.color = AMBER
        else:
            self.url_results.color = GREEN

        lines = [
            f"Risk level: {result['level']}   |   Score: {result['score']}/100",
            "",
        ]
        lines.extend(f"• {finding}" for finding in result["findings"])
        if result.get("url_details"):
            lines.extend([
                "",
                f"Hostname: {result.get('hostname', '—')}",
                f"Protocol: {result.get('scheme', '—').upper()}",
            ])
        self.url_results.text = "\n".join(lines)
        self.url_results.height = dp(max(100, 25 * len(lines)))

    def confirm_live_lookup(self, _button):
        url = self.url_input.text.strip()
        if not url:
            self.url_results.text = "Enter a URL first."
            return

        content = BoxLayout(
            orientation="vertical", spacing=dp(12), padding=dp(16)
        )
        content.add_widget(make_label(
            "Live checks may send the URL or hostname to external services. "
            "Continue only if you are comfortable sharing it.",
            13, WHITE, False, 90,
        ))
        buttons = BoxLayout(size_hint_y=None, height=dp(44), spacing=dp(8))
        cancel = make_button("Cancel", CARD, WHITE)
        proceed = make_button("Continue", TEAL, BG)
        buttons.add_widget(cancel)
        buttons.add_widget(proceed)
        content.add_widget(buttons)

        popup = Popup(
            title="Confirm live lookup",
            content=content,
            size_hint=(0.88, None),
            height=dp(230),
            background_color=CARD,
        )
        cancel.bind(on_release=popup.dismiss)
        proceed.bind(on_release=lambda *_: self.start_live_lookup(url, popup))
        popup.open()

    def start_live_lookup(self, url, popup):
        popup.dismiss()
        self.url_results.color = AMBER
        self.url_results.text = "Running live checks… please wait."
        self.url_results.height = dp(100)

        def worker():
            try:
                result = gather_live_intelligence(url)
                message = self.format_live_result(result)
                color = RED if any(
                    d.get("status") == "threats_found"
                    for d in result.get("results", {}).values()
                ) else WHITE
            except Exception as exc:  # never leave the UI stuck on "please wait"
                message = f"Live checks failed unexpectedly: {exc}"
                color = RED
            Clock.schedule_once(
                lambda _dt: self.show_live_result(message, color), 0
            )

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
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
                    lines.append(f"  • {address['address']} — {kind}")
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

    def show_live_result(self, message, color=WHITE):
        self.url_results.color = color
        self.url_results.text = message
        self.url_results.height = dp(max(160, 24 * (message.count("\n") + 1)))

    def open_file_picker(self, _button):
        chooser = FileChooserListView(
            path=str(Path.home()),
            dirselect=False,
        )
        select_button = make_button("Calculate SHA-256")
        cancel_button = make_button("Cancel", CARD, WHITE)

        buttons = BoxLayout(
            size_hint_y=None, height=dp(44), spacing=dp(8)
        )
        buttons.add_widget(cancel_button)
        buttons.add_widget(select_button)

        panel = BoxLayout(
            orientation="vertical", spacing=dp(8), padding=dp(10)
        )
        panel.add_widget(chooser)
        panel.add_widget(buttons)

        popup = Popup(
            title="Choose a file",
            content=panel,
            size_hint=(0.95, 0.9),
            background_color=CARD,
        )
        cancel_button.bind(on_release=popup.dismiss)

        def select_file(_button):
            if not chooser.selection:
                self.file_results.text = "Please select a file first."
                return

            selected = chooser.selection[0]
            popup.dismiss()
            self.file_results.color = AMBER
            self.file_results.text = (
                f"Calculating SHA-256 for {Path(selected).name}…"
            )

            def worker():
                try:
                    fingerprint = sha256_file(selected)
                    message = (
                        f"File: {Path(selected).name}\n"
                        f"SHA-256:\n{fingerprint}"
                    )
                    color = GREEN
                except (OSError, ValueError) as exc:
                    message = f"Could not read file: {exc}"
                    color = RED

                def update_ui(_dt):
                    self.file_results.text = message
                    self.file_results.color = color
                    self.file_results.height = dp(100)

                Clock.schedule_once(update_ui, 0)

            threading.Thread(target=worker, daemon=True).start()

        select_button.bind(on_release=select_file)
        popup.open()


if __name__ == "__main__":
    PrivacySentinel().run()
