#!/usr/bin/env python3
"""Privacy Sentinel native messaging host.

Chrome starts this process, sends one or more length-prefixed JSON messages on
stdin and reads length-prefixed JSON replies on stdout. Nothing here touches
the network for "analyze_url" (offline heuristics). The "live_check" action
does contact the network (DNS, the site's TLS port, rdap.org, and optionally
Google Safe Browsing); the extension only sends it after the user confirms.

IMPORTANT: never print() to stdout. It carries the protocol; stray output
corrupts it. stdout is redirected to stderr after the real stream is captured.
"""

import json
import os
import ssl
import struct
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_engine import analyze_url, gather_live_intelligence  # noqa: E402

MAX_INCOMING = 1024 * 1024   # Chrome's limit for messages sent to a host
MAX_OUTGOING = 1024 * 1024   # ... and for messages a host sends back
MAX_URL_LENGTH = 4096


def _binary_stdio():
    if sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr          # protect the protocol stream
    return stdin, stdout


def _read_exact(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.read(count - len(data))
        if not chunk:
            raise EOFError("Input closed mid-message.")
        data += chunk
    return data


def read_message(stream):
    header = stream.read(4)
    if not header:
        return None                  # clean EOF: Chrome closed the pipe
    if len(header) < 4:
        raise EOFError("Truncated message header.")
    (length,) = struct.unpack("=I", header)
    if length > MAX_INCOMING:
        raise ValueError("Message too large.")
    return json.loads(_read_exact(stream, length).decode("utf-8"))


def write_message(stream, payload):
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_OUTGOING:
        data = b'{"ok":false,"error":"Response too large."}'
    stream.write(struct.pack("=I", len(data)))
    stream.write(data)
    stream.flush()


def error(message):
    return {"ok": False, "error": message}


def _parse_rdap_date(text):
    try:
        moment = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def build_details(result):
    """Condense gather_live_intelligence() output for the extension popup."""
    signals = []
    details = {
        "status": result.get("status", "unknown"),
        "message": result.get("message", ""),
        "hostname": result.get("hostname", ""),
        "signals": signals,
    }
    results = result.get("results") or {}
    if not results:                       # invalid or blocked input
        return details

    # DNS
    dns = results.get("DNS", {})
    addresses = dns.get("addresses", [])[:10]
    details["dns"] = {
        "status": dns.get("status", "unknown"),
        "message": dns.get("message", ""),
        "addresses": addresses,
    }
    if any(not a.get("is_global", False) for a in addresses):
        signals.append({"level": "warn",
                        "text": "DNS returned a non-public address for this site."})

    # TLS
    tls = results.get("TLS", {})
    tls_out = {k: tls.get(k) for k in
               ("status", "message", "tls_version", "cipher", "issuer",
                "subject", "valid_until")}
    days_left = None
    if tls.get("status") == "success" and tls.get("valid_until"):
        try:
            days_left = int((ssl.cert_time_to_seconds(tls["valid_until"])
                             - time.time()) // 86400)
        except (ValueError, OverflowError):
            days_left = None
    tls_out["days_left"] = days_left
    details["tls"] = tls_out
    if tls.get("status") == "error":
        signals.append({"level": "warn", "text":
                        "The HTTPS certificate could not be verified. "
                        + str(tls.get("message", ""))})
    elif tls.get("status") == "skipped":
        signals.append({"level": "info",
                        "text": "TLS was not inspected: " + str(tls.get("message", ""))})
    elif days_left is not None and days_left < 14:
        signals.append({"level": "warn",
                        "text": f"The certificate expires in {max(days_left, 0)} day(s)."})

    # RDAP / domain registration history
    rdap = results.get("RDAP", {})
    events = {}
    for event in rdap.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        moment = _parse_rdap_date(event.get("eventDate", ""))
        if moment and action not in events:
            events[action] = moment
    registered = events.get("registration")
    age_days = None
    if registered:
        age_days = (datetime.now(timezone.utc) - registered).days
    iso = lambda m: m.date().isoformat() if m else None  # noqa: E731
    details["rdap"] = {
        "status": rdap.get("status", "unknown"),
        "message": rdap.get("message", ""),
        "registered": iso(registered),
        "last_changed": iso(events.get("last changed")),
        "expires": iso(events.get("expiration")),
        "age_days": age_days,
    }
    if age_days is not None:
        if age_days < 30:
            signals.append({"level": "warn", "text":
                            f"The domain was registered only {age_days} day(s) ago."})
        elif age_days < 180:
            signals.append({"level": "info", "text":
                            f"The domain is fairly new ({age_days} days old)."})

    # Safe Browsing
    sb = results.get("Safe Browsing", {})
    threat_types = sorted({str(m.get("threatType", "UNKNOWN"))
                           for m in sb.get("matches", [])})
    details["safe_browsing"] = {
        "status": sb.get("status", "unknown"),
        "message": sb.get("message", ""),
        "threat_types": threat_types,
    }
    if sb.get("status") == "threats_found":
        signals.append({"level": "bad", "text":
                        "Google Safe Browsing reports a threat: "
                        + ", ".join(threat_types)})

    if not signals:
        signals.append({"level": "ok", "text":
                        "No warning signs in these checks. This does not prove the site is safe."})
    return details


def handle(message):
    if not isinstance(message, dict):
        return error("Malformed request.")

    action = message.get("action")

    if action == "ping":
        return {"ok": True, "result": {"pong": True}}

    if action == "analyze_url":
        url = message.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
            return error("A URL string of up to 4096 characters is required.")

        analysis = analyze_url(url)
        level = analysis["level"]
        score = analysis["score"]
        if level == "INVALID":
            summary = "This URL could not be analyzed."
            score = None
        else:
            summary = f"{level} risk by local heuristics ({score}/100)."

        return {
            "ok": True,
            "result": {
                "score": score,
                "level": level,
                "summary": summary,
                "findings": [str(f) for f in analysis["findings"]][:12],
                "hostname": analysis.get("hostname", ""),
                "scheme": analysis.get("scheme", ""),
            },
        }

    if action == "live_check":
        url = message.get("url")
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
            return error("A URL string of up to 4096 characters is required.")
        return {"ok": True, "result": build_details(gather_live_intelligence(url))}

    return error("Unsupported action.")


def main():
    stdin, stdout = _binary_stdio()
    while True:
        try:
            message = read_message(stdin)
        except (EOFError, ValueError, UnicodeDecodeError):
            write_message(stdout, error("Could not read the request."))
            return 1
        if message is None:
            return 0
        try:
            reply = handle(message)
        except Exception:            # never leak details or crash the pipe
            reply = error("Internal error in the Python engine.")
        write_message(stdout, reply)


if __name__ == "__main__":
    sys.exit(main())
