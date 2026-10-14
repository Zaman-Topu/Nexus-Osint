"""
Comprehensive Unit Tests for Advanced OSINT Intelligence Modules:
- Telegram Channel & Community Telemetry (telegram_recon)
- MAC Address & IoT Hardware OUI Resolver (mac_recon)
- Multi-Engine Reverse Image Pivot Assistant (reverse_img_recon)
- Wayback Machine Historical Asset Recovery (wayback_recon)
- SSL/TLS Deep Certificate Forensics & SAN Domain Pivoting (ssl_recon)
- Master Dossier & CLI Integrations
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from nexus_osint.modules.telegram_recon import analyze_telegram, clean_telegram_handle
from nexus_osint.modules.mac_recon import analyze_mac, normalize_mac_address
from nexus_osint.modules.reverse_img_recon import analyze_reverse_image, compute_file_hashes, generate_reverse_image_engines
from nexus_osint.modules.wayback_recon import analyze_wayback, clean_target_domain, parse_wayback_timestamp
from nexus_osint.modules.ssl_recon import analyze_ssl, parse_host_port, parse_ssl_date
from nexus_osint.modules.dossier import detect_target_type, run_master_dossier
from nexus_osint.cli import run_and_save_scan


class TestTelegramRecon(unittest.TestCase):
    def test_clean_telegram_handle(self):
        self.assertEqual(clean_telegram_handle("@durov"), "durov")
        self.assertEqual(clean_telegram_handle("https://t.me/durov"), "durov")
        self.assertEqual(clean_telegram_handle("https://t.me/s/telegram/"), "telegram")
        self.assertEqual(clean_telegram_handle("http://www.t.me/news?ref=123"), "news")

    def test_invalid_handle(self):
        res = analyze_telegram("")
        self.assertFalse(res.get("found"))
        self.assertEqual(res.get("handle"), "")

    @patch("nexus_osint.modules.telegram_recon.httpx.Client")
    def test_analyze_telegram_channel_mock(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        feed_resp = MagicMock()
        feed_resp.status_code = 200
        feed_resp.text = """
        <html>
            <div class="tgme_channel_info_header_title"><span dir="auto">Nexus OSINT Channel</span></div>
            <div class="tgme_channel_info_counter"><span class="counter_value">15 400</span> <span class="counter_type">subscribers</span></div>
            <div class="tgme_channel_info_description">Official intelligence alerts and bulletins.</div>
            <i class="verified-icon"></i>
            <img class="tgme_page_photo_image" src="https://cdn4.telesco.pe/file/sample.jpg" />
        </html>
        """
        mock_client.get.return_value = feed_resp

        res = analyze_telegram("nexus_channel", timeout=5.0)
        self.assertTrue(res.get("found"))
        self.assertEqual(res.get("handle"), "nexus_channel")
        self.assertEqual(res.get("title"), "Nexus OSINT Channel")
        self.assertEqual(res.get("type"), "Broadcast Channel")
        self.assertTrue(res.get("verified"))
        self.assertIn("15 400", res.get("members_metric"))
        self.assertIn("Official intelligence", res.get("description"))


class TestMacRecon(unittest.TestCase):
    def test_normalize_mac_address(self):
        self.assertEqual(normalize_mac_address("00:1a:2b:3c:4d:5e"), "00:1A:2B:3C:4D:5E")
        self.assertEqual(normalize_mac_address("00-1A-2B-3C-4D-5E"), "00:1A:2B:3C:4D:5E")
        self.assertEqual(normalize_mac_address("001a.2b3c.4d5e"), "00:1A:2B:3C:4D:5E")
        self.assertEqual(normalize_mac_address("001A2B3C4D5E"), "00:1A:2B:3C:4D:5E")
        self.assertIsNone(normalize_mac_address("invalid-mac"))
        self.assertIsNone(normalize_mac_address("00:11"))

    def test_analyze_mac_offline_vendor(self):
        # Apple OUI: 00:03:93
        res = analyze_mac("00:03:93:11:22:33")
        self.assertEqual(res["mac_colon"], "00:03:93:11:22:33")
        self.assertEqual(res["vendor"], "Apple, Inc.")
        self.assertEqual(res["cast_type"], "Unicast")
        self.assertFalse(res["is_randomized"])

    def test_analyze_mac_randomized_private(self):
        # Locally administered address bit 1 is set: 0xDA = 11011010 (bit 1 is 1)
        res = analyze_mac("DA:A1:19:12:34:56")
        self.assertTrue(res["is_randomized"])
        self.assertIn("Locally Administered", res["admin_type"])

    def test_analyze_mac_invalid(self):
        res = analyze_mac("not_a_mac")
        self.assertFalse(res.get("valid"))


class TestReverseImageRecon(unittest.TestCase):
    def test_compute_file_hashes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"OSINT test image buffer")
            f_path = f.name

        try:
            hashes = compute_file_hashes(f_path)
            self.assertIn("md5", hashes)
            self.assertIn("sha1", hashes)
            self.assertIn("sha256", hashes)
            self.assertEqual(len(hashes["md5"]), 32)
            self.assertEqual(len(hashes["sha256"]), 64)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_generate_reverse_image_engines(self):
        engines = generate_reverse_image_engines("https://example.com/photo.jpg")
        names = [e["engine"] for e in engines]
        self.assertIn("Google Lens", names)
        self.assertIn("Yandex Visual Search", names)
        self.assertIn("Bing Visual Search", names)
        self.assertIn("TinEye Reverse Image Search", names)
        self.assertIn("Baidu Visual Search", names)

    def test_analyze_reverse_image_local_file(self):
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(b"JPEG mock content for OSINT test")
            f_path = f.name

        try:
            res = analyze_reverse_image(f_path)
            self.assertEqual(res["is_local_file"], True)
            self.assertIn("md5", res)
            self.assertTrue(len(res["engines"]) > 0)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)


class TestWaybackRecon(unittest.TestCase):
    def test_clean_target_domain(self):
        self.assertEqual(clean_target_domain("https://www.example.com/path"), "www.example.com")
        self.assertEqual(clean_target_domain("http://sub.target.org:8080/"), "sub.target.org")

    def test_parse_wayback_timestamp(self):
        self.assertEqual(parse_wayback_timestamp("20240510143000"), "2024-05-10 14:30:00")
        self.assertEqual(parse_wayback_timestamp("20200101"), "2020-01-01")
        self.assertEqual(parse_wayback_timestamp(""), "Unknown")

    @patch("nexus_osint.modules.wayback_recon.httpx.Client")
    def test_analyze_wayback_mock(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        def mock_get(url, **kwargs):
            resp = MagicMock()
            if "available" in url:
                resp.status_code = 200
                if "19960101" in url:
                    resp.json.return_value = {
                        "archived_snapshots": {
                            "closest": {
                                "available": True,
                                "timestamp": "20100101120000",
                                "url": "http://web.archive.org/web/20100101120000/http://example.com",
                            }
                        }
                    }
                else:
                    resp.json.return_value = {
                        "archived_snapshots": {
                            "closest": {
                                "available": True,
                                "timestamp": "20240101120000",
                                "url": "http://web.archive.org/web/20240101120000/http://example.com",
                            }
                        }
                    }
            elif "cdx" in url:
                resp.status_code = 200
                resp.json.return_value = [
                    ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
                    ["org,example)/about", "20150601000000", "http://example.com/about", "text/html", "200", "xxx", "123"],
                    ["org,example)/admin", "20180201000000", "http://example.com/admin", "text/html", "403", "yyy", "456"],
                ]
            else:
                resp.status_code = 404
            return resp

        mock_client.get.side_effect = mock_get

        res = analyze_wayback("example.com", timeout=5.0)
        self.assertTrue(res["has_archives"])
        self.assertEqual(res["earliest_snapshot_date"], "2010-01-01 12:00:00")
        self.assertEqual(res["latest_snapshot_date"], "2024-01-01 12:00:00")
        self.assertEqual(len(res["historical_endpoints"]), 2)


class TestSslRecon(unittest.TestCase):
    def test_parse_host_port(self):
        self.assertEqual(parse_host_port("https://example.com:8443/login"), ("example.com", 8443))
        self.assertEqual(parse_host_port("example.com"), ("example.com", 443))
        self.assertEqual(parse_host_port("http://1.1.1.1"), ("1.1.1.1", 443))

    def test_parse_ssl_date(self):
        dt = parse_ssl_date("Oct 14 01:09:41 2026 GMT")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 10)
        self.assertEqual(dt.day, 14)

    @patch("nexus_osint.modules.ssl_recon.socket.create_connection")
    @patch("nexus_osint.modules.ssl_recon.ssl.create_default_context")
    def test_analyze_ssl_mock(self, mock_ctx_cls, mock_connect):
        mock_ctx = MagicMock()
        mock_ctx_cls.return_value = mock_ctx

        mock_sock = MagicMock()
        mock_sslsock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_sslsock

        mock_sslsock.version.return_value = "TLSv1.3"
        mock_sslsock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sslsock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Example Corp"),)),
            "issuer": ((("commonName", "DigiCert Global Root CA"),), (("organizationName", "DigiCert Inc"),)),
            "notBefore": "Jan 01 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "api.example.com"), ("DNS", "auth.example.com")),
        }

        res = analyze_ssl("example.com")
        self.assertTrue(res["connected"])
        self.assertEqual(res["subject_cn"], "example.com")
        self.assertEqual(res["issuer_cn"], "DigiCert Global Root CA")
        self.assertIn("api.example.com", res["san_domains"])
        self.assertFalse(res["is_expired"])
        self.assertEqual(res["tls_version"], "TLSv1.3")


class TestDossierAndCliIntegrations(unittest.TestCase):
    def test_detect_target_type(self):
        self.assertEqual(detect_target_type("00:1A:2B:3C:4D:5E"), "mac")
        self.assertEqual(detect_target_type("00-1A-2B-3C-4D-5E"), "mac")
        self.assertEqual(detect_target_type("001a.2b3c.4d5e"), "mac")
        self.assertEqual(detect_target_type("test@domain.com"), "email")
        self.assertEqual(detect_target_type("8.8.8.8"), "ip")
        self.assertEqual(detect_target_type("+14155552671"), "phone")
        self.assertEqual(detect_target_type("target.com"), "domain")
        self.assertEqual(detect_target_type("torvalds"), "username")

    @patch("nexus_osint.modules.dossier.analyze_mac")
    def test_dossier_mac_vector(self, mock_mac):
        mock_mac.return_value = {
            "mac_colon": "00:1A:2B:3C:4D:5E",
            "vendor": "Test Vendor",
            "cast_type": "Unicast",
            "admin_type": "Universally Administered",
            "is_randomized": False,
        }
        res = run_master_dossier("00:1A:2B:3C:4D:5E", save_folder=False)
        self.assertEqual(res["seed_type"], "mac")
        self.assertIsNotNone(res["mac_recon"])
        self.assertEqual(res["mac_recon"]["vendor"], "Test Vendor")

    @patch("nexus_osint.cli.analyze_telegram")
    def test_cli_run_telegram_scan(self, mock_tg):
        mock_tg.return_value = {"handle": "durov", "found": True}
        res = run_and_save_scan("telegram", "durov", save_folder=False)
        self.assertTrue(res.get("found"))

    @patch("nexus_osint.cli.analyze_mac")
    def test_cli_run_mac_scan(self, mock_mac):
        mock_mac.return_value = {"mac_colon": "00:1A:2B:3C:4D:5E", "vendor": "Apple, Inc."}
        res = run_and_save_scan("mac", "00:1A:2B:3C:4D:5E", save_folder=False)
        self.assertEqual(res.get("vendor"), "Apple, Inc.")


if __name__ == "__main__":
    unittest.main()
