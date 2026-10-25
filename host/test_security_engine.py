
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from security_engine import (
    analyze_url,
    compare_file_hashes,
    gather_live_intelligence,
    sha256_file,
    _tls_lookup,
)


class SecurityEngineTests(unittest.TestCase):

    def test_https_url_is_parsed(self):
        result = analyze_url("https://example.com/path?q=hello")
        self.assertEqual(result["level"], "LOW")
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["scheme"], "https")
        self.assertEqual(result["url_details"]["Path"], "/path")

    def test_http_url_gets_warning(self):
        result = analyze_url("http://example.com")
        self.assertIn(
            "The URL uses HTTP rather than HTTPS.",
            result["findings"],
        )

    def test_empty_url_is_invalid(self):
        self.assertEqual(analyze_url("")["level"], "INVALID")

    def test_unsupported_scheme_is_invalid(self):
        self.assertEqual(
            analyze_url("ftp://example.com")["level"],
            "INVALID",
        )

    def test_invalid_port_is_rejected(self):
        self.assertEqual(
            analyze_url("https://example.com:99999")["level"],
            "INVALID",
        )

    def test_embedded_credentials_are_rejected(self):
        self.assertEqual(
            analyze_url("https://user:pass@example.com")["level"],
            "INVALID",
        )

    def test_sha256_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.txt"
            file_path.write_bytes(b"hello")
            self.assertEqual(
                sha256_file(str(file_path)),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )

    def test_hashes_match(self):
        self.assertEqual(
            compare_file_hashes("abc123", "ABC123"),
            "UNCHANGED",
        )

    def test_hashes_differ(self):
        self.assertEqual(
            compare_file_hashes("abc123", "def456"),
            "CHANGED",
        )

    def test_empty_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            compare_file_hashes("", "abc")

    def test_live_lookup_rejects_local_ip(self):
        result = gather_live_intelligence("https://127.0.0.1")
        self.assertEqual(result["status"], "blocked")

    def test_tls_blocks_loopback_ip(self):
        with patch("security_engine.socket.create_connection") as connect:
            result = _tls_lookup("127.0.0.1", 443)
        self.assertEqual(result["status"], "skipped")
        connect.assert_not_called()

    def test_tls_blocks_mixed_public_private_dns(self):
        public_record = (
            socket.AF_INET, socket.SOCK_STREAM, 6, "",
            ("8.8.8.8", 443),
        )
        private_record = (
            socket.AF_INET, socket.SOCK_STREAM, 6, "",
            ("127.0.0.1", 443),
        )

        with patch(
            "security_engine.socket.getaddrinfo",
            return_value=[public_record, private_record],
        ):
            with patch("security_engine.socket.create_connection") as connect:
                result = _tls_lookup("example.com", 443)

        self.assertEqual(result["status"], "skipped")
        connect.assert_not_called()

    def test_tls_handles_dns_failure(self):
        with patch(
            "security_engine.socket.getaddrinfo",
            side_effect=socket.gaierror("DNS unavailable"),
        ):
            result = _tls_lookup("example.com", 443)

        self.assertEqual(result["status"], "error")

    def test_live_lookup_rejects_invalid_url(self):
        result = gather_live_intelligence("not a valid URL")
        self.assertEqual(result["status"], "invalid")

    def test_overlong_label_is_invalid(self):
        self.assertEqual(
            analyze_url("https://" + "a" * 64 + ".com")["level"], "INVALID")

    def test_leading_dot_host_is_invalid(self):
        self.assertEqual(analyze_url("https://.example.com")["level"], "INVALID")

    def test_live_lookup_survives_bad_label(self):
        result = gather_live_intelligence("https://" + "a" * 64 + ".com")
        self.assertEqual(result["status"], "invalid")

    def test_unicode_hostname_is_flagged(self):
        result = analyze_url("https://\u0430pple.com")  # Cyrillic a
        self.assertTrue(any("look-alike" in f for f in result["findings"]))

    def test_shorthand_ip_is_blocked_for_live_lookup(self):
        self.assertEqual(
            gather_live_intelligence("https://127.1")["status"], "blocked")
        self.assertEqual(
            gather_live_intelligence("https://2130706433")["status"], "blocked")

    def test_shorthand_ip_is_flagged(self):
        result = analyze_url("http://127.1")
        self.assertGreaterEqual(result["score"], 40)

    def test_cert_name_is_readable(self):
        from security_engine import _cert_name
        field = ((("countryName", "US"),), (("organizationName", "Example CA"),),
                 (("commonName", "Example CA R3"),))
        self.assertEqual(_cert_name(field), "Example CA")
        self.assertEqual(_cert_name(None), "Not provided")

    def test_dns_lookup_handles_unicode_error(self):
        from security_engine import _dns_lookup
        with patch("security_engine.socket.getaddrinfo",
                   side_effect=UnicodeError("label empty or too long")):
            self.assertEqual(_dns_lookup("example.com")["status"], "error")


if __name__ == "__main__":
    unittest.main()
