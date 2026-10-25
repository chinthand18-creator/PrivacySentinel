
"""Privacy Sentinel security engine.

Offline URL inspection, guarded DNS/TLS inspection, optional reputation lookup,
and file SHA-256 hashing. Live results are advisory, not proof of safety.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import Request, urlopen

TIMEOUT = 5
MAX_RESPONSE_BYTES = 1_000_000
USER_AGENT = "PrivacySentinel/1.0"

# Network failures that must never crash a caller (note: UnicodeError and
# json.JSONDecodeError are both ValueError subclasses).
_NET_ERRORS = (
    HTTPError, URLError, TimeoutError, OSError, ValueError,
    http.client.HTTPException,
)

_NUM = r"(?:0x[0-9a-f]+|[0-9]+)"
_LEGACY_IPV4 = re.compile(rf"^{_NUM}(?:\.{_NUM}){{0,3}}$", re.IGNORECASE)


def _legacy_ipv4(host: str):
    """Return an IPv4Address for shorthand forms like 127.1 or 2130706433."""
    if not _LEGACY_IPV4.match(host):
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except OSError:
        return None


def _valid_url(raw_url: str) -> dict:
    """Validate and normalize a URL without making a network request."""
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Enter a URL first.")

    candidate = value if "://" in value else "https://" + value
    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL has no valid hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    if any(ch.isspace() for ch in parsed.hostname):
        raise ValueError("The hostname contains whitespace.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535.")

    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise ValueError("The hostname is invalid.")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        # Reject empty or obviously malformed domain labels.
        if ":" in host or ".." in host:
            raise ValueError("The hostname is invalid.")
        if len(host) > 253:
            raise ValueError("The hostname is too long.")
        try:
            host.encode("idna")  # rejects empty and >63-character labels
        except UnicodeError:
            raise ValueError("The hostname is invalid.")

    host_part = f"[{host}]" if ":" in host else host
    netloc = host_part + (f":{port}" if port is not None else "")
    normalized = urlunparse(parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=netloc,
        fragment="",
    ))

    return {
        "input": value,
        "parsed": parsed,
        "hostname": host,
        "scheme": parsed.scheme.lower(),
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "normalized_url": normalized,
        "path": parsed.path or "/",
        "query": parsed.query,
    }


def analyze_url(raw_url: str) -> dict:
    """Run local heuristic checks only. No network access occurs here."""
    try:
        info = _valid_url(raw_url)
    except ValueError as exc:
        return {
            "score": 0,
            "level": "INVALID",
            "findings": [str(exc)],
            "url_details": {},
        }

    host = info["hostname"]
    findings = []
    score = 0

    if info["scheme"] == "http":
        score += 25
        findings.append("The URL uses HTTP rather than HTTPS.")

    address = None
    shorthand = False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = _legacy_ipv4(host)
        shorthand = address is not None

    if address is not None:
        score += 15
        findings.append(
            f"The hostname is an IP address (IPv{address.version})."
        )
        if shorthand:
            score += 15
            findings.append(
                "The IP is written in a non-standard shorthand form that is "
                "sometimes used to disguise the destination."
            )
        if not address.is_global:
            score += 25
            findings.append(
                "The IP is not globally routable. Treat this destination carefully."
            )
    elif "." not in host:
        score += 10
        findings.append("The hostname is not a conventional public domain.")

    if not host.isascii() or any(
        label.startswith("xn--") for label in host.split(".")
    ):
        score += 15
        findings.append(
            "The hostname contains internationalized characters; check for look-alike characters."
        )

    if len(host) > 45:
        score += 10
        findings.append("The hostname is unusually long.")

    if host.count("-") >= 4:
        score += 5
        findings.append("The hostname contains many hyphens.")

    if len(info["query"]) > 200:
        findings.append(
            "The URL has a long query string. Check that it contains no private tokens."
        )

    score = min(score, 100)
    level = "HIGH" if score >= 40 else "REVIEW" if score >= 20 else "LOW"

    if not findings:
        findings.append(
            "No configured local warning patterns were detected. "
            "This does not prove the website is safe."
        )

    details = {
        "Submitted URL": info["input"],
        "Normalized URL": info["normalized_url"],
        "Protocol": info["scheme"].upper(),
        "Hostname": host,
        "Port": str(info["port"]),
        "Path": info["path"],
        "Query parameters": info["query"] or "(none)",
    }

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "url_details": details,
        "hostname": host,
        "normalized_url": info["normalized_url"],
        "scheme": info["scheme"],
    }


def _request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """Fetch bounded JSON from a fixed, trusted service endpoint."""
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = Request(
        url,
        data=data,
        headers=request_headers,
        method=method,
    )

    with urlopen(request, timeout=TIMEOUT) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)

    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("The response exceeded the size limit.")

    return json.loads(raw.decode("utf-8"))


def _dns_lookup(hostname: str) -> dict:
    """Resolve a hostname and flag any non-public addresses."""
    try:
        records = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
        addresses = sorted({
            record[4][0].split("%", 1)[0]
            for record in records
            if record and len(record) > 4 and record[4]
        })

        if not addresses:
            return {
                "status": "error",
                "message": "DNS returned no usable addresses.",
                "addresses": [],
            }

        results = []
        for value in addresses:
            try:
                ip = ipaddress.ip_address(value)
                results.append({
                    "address": str(ip),
                    "is_global": ip.is_global,
                })
            except ValueError:
                results.append({
                    "address": value,
                    "is_global": False,
                })

        return {
            "status": "success",
            "addresses": results,
            "message": "DNS lookup completed.",
        }
    except (socket.gaierror, OSError, UnicodeError) as exc:
        return {
            "status": "error",
            "addresses": [],
            "message": f"DNS lookup failed: {exc}",
        }


def _cert_name(field, prefer=("organizationName", "commonName")) -> str:
    """Turn a certificate issuer/subject tuple into a short readable name."""
    try:
        pairs = {key: value for rdn in field for key, value in rdn}
    except (TypeError, ValueError):
        return "Not provided"
    for key in prefer:
        if pairs.get(key):
            return str(pairs[key])
    return "Not provided"


def _tls_lookup(hostname: str, port: int) -> dict:
    """Inspect TLS only after checking DNS results.

    Connects to a validated address directly to avoid a second hostname
    resolution for the TCP connection. TLS still verifies the hostname.
    """
    try:
        try:
            literal = ipaddress.ip_address(hostname)
            if not literal.is_global:
                return {
                    "status": "skipped",
                    "message": "TLS lookup blocked for a non-public IP.",
                }
            candidates = [str(literal)]
        except ValueError:
            records = socket.getaddrinfo(
                hostname, port, type=socket.SOCK_STREAM
            )
            candidates = sorted({
                record[4][0].split("%", 1)[0]
                for record in records
                if record and len(record) > 4 and record[4]
            })

            if not candidates:
                return {
                    "status": "error",
                    "message": "DNS returned no usable addresses.",
                }

            parsed_ips = []
            for candidate in candidates:
                try:
                    parsed_ips.append(ipaddress.ip_address(candidate))
                except ValueError:
                    return {
                        "status": "error",
                        "message": "DNS returned an invalid IP address.",
                    }

            if any(not ip.is_global for ip in parsed_ips):
                return {
                    "status": "skipped",
                    "message": (
                        "TLS lookup blocked because DNS includes a non-public "
                        "address. This helps protect internal services."
                    ),
                }

        context = ssl.create_default_context()
        last_error = None

        for candidate in candidates:
            try:
                with socket.create_connection(
                    (candidate, port), timeout=TIMEOUT
                ) as raw_socket:
                    peer = raw_socket.getpeername()[0].split("%", 1)[0]
                    if ipaddress.ip_address(peer) != ipaddress.ip_address(candidate):
                        raise OSError("Connected peer differs from validated IP.")

                    with context.wrap_socket(
                        raw_socket, server_hostname=hostname
                    ) as secure_socket:
                        cert = secure_socket.getpeercert()
                        cipher = secure_socket.cipher()
                        version = secure_socket.version()

                return {
                    "status": "success",
                    "tls_version": version or "Unknown",
                    "cipher": cipher[0] if cipher else "Unknown",
                    "issuer": _cert_name(cert.get("issuer")),
                    "subject": _cert_name(
                        cert.get("subject"), ("commonName", "organizationName")
                    ),
                    "valid_until": cert.get("notAfter", "Not provided"),
                    "message": (
                        "TLS certificate validation succeeded at lookup time. "
                        "This does not prove the website is benign."
                    ),
                }
            except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
                last_error = exc

        return {
            "status": "error",
            "message": f"TLS connection failed: {last_error}",
        }
    except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
        return {"status": "error", "message": f"TLS lookup failed: {exc}"}


def _rdap_lookup(hostname: str) -> dict:
    """Look up domain registration information using RDAP."""
    try:
        # Avoid sending IP literals to the domain registration endpoint.
        ipaddress.ip_address(hostname)
        return {
            "status": "skipped",
            "message": "RDAP domain lookup skipped for an IP address.",
        }
    except ValueError:
        pass

    try:
        ascii_host = hostname.encode("idna").decode("ascii")
        data = _request_json(
            f"https://rdap.org/domain/{quote(ascii_host, safe='')}"
        )
        return {
            "status": "success",
            "ldh_name": data.get("ldhName", hostname),
            "events": data.get("events", [])[:10],
            "message": "Registration data retrieved; availability varies by domain.",
        }
    except _NET_ERRORS as exc:
        return {"status": "error", "message": f"RDAP lookup failed: {exc}"}


def _safe_browsing_lookup(url: str) -> dict:
    """Optional Google Safe Browsing lookup; requires an environment API key."""
    api_key = os.environ.get("PRIVACY_SENTINEL_GSB_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "message": "Safe Browsing lookup not configured. No API key was found.",
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={api_key}"
    )
    payload = {
        "client": {"clientId": "privacy-sentinel-student", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        data = _request_json(endpoint, method="POST", payload=payload)
        matches = data.get("matches", [])
        return {
            "status": "threats_found" if matches else "no_match",
            "matches": matches[:20],
            "message": (
                "Potential threat match found."
                if matches
                else "No match was returned. This does not prove the URL is safe."
            ),
        }
    except _NET_ERRORS as exc:
        return {"status": "error", "message": f"Safe Browsing lookup failed: {exc}"}


def gather_live_intelligence(raw_url: str) -> dict:
    """Run optional live checks after URL validation and user confirmation."""
    try:
        info = _valid_url(raw_url)
    except ValueError as exc:
        return {
            "status": "invalid",
            "message": str(exc),
            "results": {},
        }

    host = info["hostname"]

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _legacy_ipv4(host)
    if ip is not None and not ip.is_global:
        return {
            "status": "blocked",
            "message": "Live lookups are blocked for non-public IP addresses.",
            "results": {},
        }

    results = {
        "DNS": _dns_lookup(host),
        "TLS": _tls_lookup(host, info["port"]) if info["scheme"] == "https"
        else {"status": "skipped", "message": "TLS inspection requires HTTPS."},
        "RDAP": _rdap_lookup(host),
        "Safe Browsing": _safe_browsing_lookup(info["normalized_url"]),
    }

    return {
        "status": "complete",
        "hostname": host,
        "normalized_url": info["normalized_url"],
        "results": results,
        "message": (
            "Live checks completed. Interpret errors and missing results carefully; "
            "no single check can guarantee safety."
        ),
    }


def sha256_file(file_path: str) -> str:
    """Calculate a file's SHA-256 digest in bounded memory."""
    digest = hashlib.sha256()
    path = Path(file_path)

    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def compare_file_hashes(original_hash: str, current_hash: str) -> str:
    """Compare two SHA-256 strings."""
    if not original_hash or not current_hash:
        raise ValueError("Both hashes are required.")

    if original_hash.strip().lower() == current_hash.strip().lower():
        return "UNCHANGED"

    return "CHANGED"
