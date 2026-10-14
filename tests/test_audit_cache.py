"""
Unit tests for Diagnostic Health Audit Matrix, Comprehensive IP Recon, and Cache Purging.
"""

import unittest
from unittest.mock import MagicMock, patch

from nexus_osint.case_manager import (
    clear_system_cache,
    format_diagnostic_audit_summary,
    format_ip_summary_lines,
    generate_markdown_report,
    generate_summary_text,
)
from nexus_osint.cli import build_cli_parser
from nexus_osint.modules.ip_recon import (
    analyze_ip,
    check_bgp_prefix,
    check_port_listener,
    check_shodan_telemetry,
    check_tls_listener,
    check_tor_exit_node,
    is_ip,
)
from nexus_osint.ui import display_audit_matrix


class TestAuditAndCache(unittest.TestCase):
    """Test suite for IP recon diagnostic audit and cache purge utilities."""

    def test_is_ip_validation(self):
        self.assertTrue(is_ip("103.240.2.54"))
        self.assertTrue(is_ip("8.8.8.8"))
        self.assertTrue(is_ip("2001:4860:4860::8888"))
        self.assertFalse(is_ip("example.com"))
        self.assertFalse(is_ip("not_an_ip"))

    def test_clear_system_cache(self):
        purged = clear_system_cache(verbose=False)
        self.assertIsInstance(purged, int)

    def test_format_ip_summary_lines(self):
        sample_ip_data = {
            "ip": "103.240.2.54",
            "classification": {
                "IP Version": "IPv4",
                "Is Global / Public": True,
                "CIDR Representation": "103.240.2.54/32",
            },
            "geolocation": {
                "Country": "Bangladesh",
                "City": "Dhaka",
                "Region / State": "Dhaka Division",
                "Postal Code": "1229",
                "ASN": "AS151835",
                "ISP": "Airnet",
                "Organization": "Torque",
                "Timezone": "Asia/Dhaka",
                "Coordinates": "23.7, 90.4",
                "Map Location": "https://maps.google.com/?q=23.7,90.4",
            },
            "reverse_dns": None,
            "bgp_routing": {
                "prefix": "103.240.2.0/24",
                "asns": "AS151835",
            },
            "shodan_telemetry": {
                "ports": [],
                "vulns": [],
            },
            "live_probes": {
                "Port 80 (HTTP)": {"status": "CLOSED", "banner": "Port closed"},
            },
            "tor_anonymity": {
                "status": "CLEAN",
                "detail": "Not a Tor exit",
            },
        }

        lines = format_ip_summary_lines(sample_ip_data, "103.240.2.54")
        text = "\n".join(lines)
        self.assertIn("103.240.2.54", text)
        self.assertIn("Dhaka", text)
        self.assertIn("AS151835", text)
        self.assertIn("103.240.2.0/24", text)
        self.assertIn("Clean (0 exposed ports indexed)", text)

    def test_format_diagnostic_audit_summary(self):
        audit_records = [
            {"probe": "IP Classification", "target": "103.240.2.54", "status": "SUCCESS", "detail": "IPv4 Public"},
            {"probe": "Reverse DNS (PTR)", "target": "103.240.2.54", "status": "NO_RECORD", "detail": "No PTR configured"},
            {"probe": "Shodan InternetDB", "target": "103.240.2.54", "status": "CLEAN", "detail": "0 ports"},
            {"probe": "HTTP Listener", "target": "103.240.2.54:80", "status": "CLOSED", "detail": "Connection refused"},
        ]
        lines = format_diagnostic_audit_summary(audit_records)
        text = "\n".join(lines)
        self.assertIn("[✔ SUCCESS]", text)
        self.assertIn("[⚠ NO_REC ]", text)
        self.assertIn("[ℹ CLEAN  ]", text)
        self.assertIn("[✖ CLOSED ]", text)

    def test_markdown_report_includes_audit_table(self):
        sample_data = {
            "ip": "103.240.2.54",
            "diagnostic_audit": [
                {"probe": "IP Classification", "target": "103.240.2.54", "status": "SUCCESS", "detail": "IPv4 Public"},
                {"probe": "Reverse DNS", "target": "103.240.2.54", "status": "NO_RECORD", "detail": "None"},
            ],
            "classification": {
                "ip_address": "103.240.2.54",
                "ip_version": "IPv4",
            },
        }
        md = generate_markdown_report("103.240.2.54", "IP", sample_data, "/tmp/case")
        self.assertIn("Diagnostic Reconnaissance & Health Audit Matrix", md)
        self.assertIn("IP Classification", md)
        self.assertIn("SUCCESS", md)
        self.assertIn("NO_RECORD", md)

    def test_cli_parser_has_clean_and_clear_cache(self):
        parser = build_cli_parser()
        args = parser.parse_args(["clean"])
        self.assertEqual(args.command, "clean")

        args2 = parser.parse_args(["ip", "1.1.1.1", "--clear-cache"])
        self.assertTrue(args2.clear_cache)

    @patch("nexus_osint.modules.ip_recon.httpx.Client")
    def test_check_shodan_clean(self, mock_client_cls):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        res = check_shodan_telemetry("103.240.2.54")
        self.assertEqual(res["status"], "CLEAN")
        self.assertFalse(res["exposed"])


if __name__ == "__main__":
    unittest.main()
