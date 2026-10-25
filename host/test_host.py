import unittest
from datetime import datetime, timedelta, timezone

import host


def iso_days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class HostTests(unittest.TestCase):
    def test_unknown_action(self):
        self.assertFalse(host.handle({"action": "x"})["ok"])

    def test_live_check_rejects_bad_input(self):
        self.assertFalse(host.handle({"action": "live_check", "url": ""})["ok"])
        self.assertFalse(host.handle({"action": "live_check", "url": 5})["ok"])

    def test_live_check_blocks_private_ip_without_network(self):
        reply = host.handle({"action": "live_check", "url": "https://127.0.0.1/"})
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["result"]["status"], "blocked")

    def test_new_domain_is_flagged(self):
        details = host.build_details({
            "status": "complete", "hostname": "x.test", "message": "",
            "results": {
                "DNS": {"status": "success", "addresses": [{"address": "1.1.1.1", "is_global": True}]},
                "TLS": {"status": "success", "valid_until": "Jan  1 00:00:00 2099 GMT",
                        "issuer": "CA", "subject": "x.test"},
                "RDAP": {"status": "success", "events": [
                    {"eventAction": "registration", "eventDate": iso_days_ago(5)}]},
                "Safe Browsing": {"status": "no_match", "message": "none"},
            }})
        self.assertEqual(details["rdap"]["age_days"], 5)
        self.assertTrue(any(s["level"] == "warn" and "registered only" in s["text"]
                            for s in details["signals"]))

    def test_threat_is_reported(self):
        details = host.build_details({
            "status": "complete", "hostname": "x.test", "message": "",
            "results": {"Safe Browsing": {"status": "threats_found",
                                          "matches": [{"threatType": "MALWARE"}]}}})
        self.assertTrue(any(s["level"] == "bad" for s in details["signals"]))

    def test_clean_result_gets_ok_signal_with_caveat(self):
        details = host.build_details({
            "status": "complete", "hostname": "x.test", "message": "",
            "results": {"DNS": {"status": "success", "addresses": [{"address": "1.1.1.1", "is_global": True}]},
                        "RDAP": {"status": "success", "events": [
                            {"eventAction": "registration", "eventDate": iso_days_ago(4000)}]}}})
        self.assertEqual(details["signals"][-1]["level"], "ok")
        self.assertIn("does not prove", details["signals"][-1]["text"])


if __name__ == "__main__":
    unittest.main()
