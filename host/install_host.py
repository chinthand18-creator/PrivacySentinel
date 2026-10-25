#!/usr/bin/env python3
"""Register the Privacy Sentinel native messaging host with your browser.

Usage:
    python install_host.py                    # asks for the extension ID
    python install_host.py --id <extension-id> [--browser chrome|edge|chromium|all]
    python install_host.py --uninstall [--browser ...]

Find the extension ID on chrome://extensions (turn on Developer mode).
Re-run this script if you move this folder or change Python versions.
"""

import argparse
import json
import os
import re
import stat
import struct
import subprocess
import sys
from pathlib import Path

HOST_NAME = "com.privacysentinel.host"
HERE = Path(__file__).resolve().parent
ID_PATTERN = re.compile(r"^[a-p]{32}$")

WIN_KEYS = {
    "chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "chromium": r"Software\Chromium\NativeMessagingHosts",
}
MAC_DIRS = {
    "chrome": "Library/Application Support/Google/Chrome/NativeMessagingHosts",
    "edge": "Library/Application Support/Microsoft Edge/NativeMessagingHosts",
    "chromium": "Library/Application Support/Chromium/NativeMessagingHosts",
}
LINUX_DIRS = {
    "chrome": ".config/google-chrome/NativeMessagingHosts",
    "edge": ".config/microsoft-edge/NativeMessagingHosts",
    "chromium": ".config/chromium/NativeMessagingHosts",
}


def write_launcher() -> Path:
    host = HERE / "host.py"
    if os.name == "nt":
        launcher = HERE / "host_launcher.bat"
        launcher.write_text(
            f'@echo off\r\n"{sys.executable}" "{host}"\r\n', encoding="utf-8"
        )
    else:
        launcher = HERE / "host_launcher.sh"
        launcher.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{host}"\n', encoding="utf-8"
        )
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return launcher


def manifest_text(launcher: Path, extension_id: str) -> str:
    return json.dumps({
        "name": HOST_NAME,
        "description": "Privacy Sentinel local Python engine",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{extension_id}/"],
    }, indent=2)


def manifest_dir(browser: str) -> Path:
    home = Path.home()
    table = MAC_DIRS if sys.platform == "darwin" else LINUX_DIRS
    return home / table[browser]


def self_test(launcher: Path) -> bool:
    """Send a framed ping through the real launcher and check the reply."""
    body = json.dumps({"action": "ping"}).encode()
    request = struct.pack("=I", len(body)) + body
    try:
        done = subprocess.run(
            [str(launcher)], input=request, capture_output=True, timeout=15
        )
        size = struct.unpack("=I", done.stdout[:4])[0]
        reply = json.loads(done.stdout[4:4 + size])
        return reply.get("ok") is True
    except Exception as exc:  # noqa: BLE001
        print("Self-test error:", exc)
        return False


def install(extension_id: str, browsers: list) -> None:
    launcher = write_launcher()
    manifest = manifest_text(launcher, extension_id)

    for browser in browsers:
        if os.name == "nt":
            import winreg
            target = HERE / f"{HOST_NAME}.json"
            target.write_text(manifest, encoding="utf-8")
            with winreg.CreateKey(
                winreg.HKEY_CURRENT_USER, rf"{WIN_KEYS[browser]}\{HOST_NAME}"
            ) as key:
                winreg.SetValue(key, "", winreg.REG_SZ, str(target))
            print(f"[{browser}] registered: {target}")
        else:
            folder = manifest_dir(browser)
            folder.mkdir(parents=True, exist_ok=True)
            target = folder / f"{HOST_NAME}.json"
            target.write_text(manifest, encoding="utf-8")
            print(f"[{browser}] wrote: {target}")

    print("Self-test:", "OK" if self_test(launcher) else "FAILED")
    print("Now fully restart the browser, or click Reload on the extension.")


def uninstall(browsers: list) -> None:
    for browser in browsers:
        if os.name == "nt":
            import winreg
            try:
                winreg.DeleteKey(
                    winreg.HKEY_CURRENT_USER,
                    rf"{WIN_KEYS[browser]}\{HOST_NAME}",
                )
                print(f"[{browser}] registry key removed")
            except FileNotFoundError:
                print(f"[{browser}] was not registered")
            (HERE / f"{HOST_NAME}.json").unlink(missing_ok=True)
        else:
            (manifest_dir(browser) / f"{HOST_NAME}.json").unlink(missing_ok=True)
            print(f"[{browser}] manifest removed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--id", help="extension ID from chrome://extensions")
    parser.add_argument("--browser", default="chrome",
                        choices=["chrome", "edge", "chromium", "all"])
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    browsers = list(WIN_KEYS) if args.browser == "all" else [args.browser]

    if args.uninstall:
        uninstall(browsers)
        return 0

    extension_id = (args.id or input("Extension ID: ")).strip().lower()
    if not ID_PATTERN.match(extension_id):
        print("That does not look like an extension ID "
              "(32 letters, a-p only).")
        return 1
    install(extension_id, browsers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
