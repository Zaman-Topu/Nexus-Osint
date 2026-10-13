"""
Unit Tests for Phase 1: Foundation & Bug Fixes in NexusOSINT.
"""

import os
import unittest
from unittest.mock import patch, MagicMock

import nexus_osint
from nexus_osint import ui
from nexus_osint.case_manager import generate_summary_text
from nexus_osint.modules.dossier import detect_target_type
from nexus_osint.modules.phone_recon import analyze_phone, parse_phone_number
from nexus_osint.modules.ip_recon import resolve_domain_to_ip
from nexus_osint.modules.shodan_recon import resolve_to_ip


class TestPhase1Foundation(unittest.TestCase):
    """Test version synchronization and dependencies."""

    def test_version_consistency(self):
        """Ensure __version__ is 2.0.0 and consistent across modules."""
        self.assertEqual(nexus_osint.__version__, "2.0.0")
        self.assertIn("v2.0.0", ui.TAGLINE)

        # Check setup.py version and requirements
        setup_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "setup.py")
        with open(setup_path, "r", encoding="utf-8") as f:
            setup_content = f.read()

        self.assertIn('version="2.0.0"', setup_content)
        self.assertIn('"httpx>=0.27.0"', setup_content)
        self.assertIn('"exifread>=3.0.0"', setup_content)
        self.assertNotIn('"requests', setup_content)
        self.assertNotIn('"pillow', setup_content)


class TestPhase1CaseManagerKeyMapping(unittest.TestCase):
    """Test dictionary key mappings in generate_summary_text."""

    def test_user_summary_keys(self):
        """Ensure username profiles are parsed without None."""
        user_data = {
            "username": "octocat",
            "total_probed": 50,
            "total_found": 2,
            "profiles": [
                {"Platform": "GitHub", "Category": "Development", "Profile URL": "https://github.com/octocat"},
                {"Platform": "Reddit", "Category": "Social", "Profile URL": "https://reddit.com/user/octocat"},
            ],
        }
        summary = generate_summary_text("octocat", "username", user_data, "/tmp/case_test")
        self.assertIn("Sites Detected  : 2", summary)
        self.assertIn("[GitHub]: https://github.com/octocat", summary)
        self.assertNotIn("None", summary)

    def test_email_summary_keys(self):
        """Ensure email recon keys (target, valid_format, is_disposable, mx_records) map properly."""
        email_data = {
            "target": "alice@company.com",
            "valid_format": True,
            "is_disposable": False,
            "mx_records": ["mail.company.com (priority 10)"],
            "gravatar": {"profile_found": False},
        }
        summary = generate_summary_text("alice@company.com", "email", email_data, "/tmp/case_test")
        self.assertIn("Target Email    : alice@company.com", summary)
        self.assertIn("Format Valid    : Yes", summary)
        self.assertIn("Disposable/Temp : No", summary)
        self.assertIn("MX Mail Server  : Active", summary)
        self.assertNotIn("None", summary)

    def test_phone_summary_keys(self):
        """Ensure phone details dict and top-level keys map properly without None."""
        phone_data = {
            "target": "+8801812345678",
            "e164": "+8801812345678",
            "valid": True,
            "country": "Bangladesh",
            "carrier": "Robi",
            "timezone": "Asia/Dhaka",
            "details": {
                "E.164 Format": "+8801812345678",
                "Is Valid": True,
                "Geographic Region": "Bangladesh",
                "Carrier / Operator": "Robi",
                "Associated Timezones": ["Asia/Dhaka"],
            },
        }
        summary = generate_summary_text("+8801812345678", "phone", phone_data, "/tmp/case_test")
        self.assertIn("Number (E.164)  : +8801812345678", summary)
        self.assertIn("Validation      : Valid", summary)
        self.assertIn("Geographic Region: Bangladesh", summary)
        self.assertIn("Operator/Carrier: Robi", summary)
        self.assertIn("Timezone        : Asia/Dhaka", summary)
        self.assertNotIn("None", summary)

    def test_shodan_summary_keys(self):
        """Ensure shodan 'vulns' key maps properly instead of vulnerabilities None."""
        shodan_data = {
            "target": "1.2.3.4",
            "ip": "1.2.3.4",
            "ports": [80, 443, 22],
            "vulns": ["CVE-2021-44228", "CVE-2022-22965"],
        }
        summary = generate_summary_text("1.2.3.4", "shodan", shodan_data, "/tmp/case_test")
        self.assertIn("Open Ports      : 80, 443, 22", summary)
        self.assertIn("Vulnerabilities : CVE-2021-44228, CVE-2022-22965", summary)
        self.assertNotIn("None reported", summary)

    def test_exif_summary_keys(self):
        """Ensure EXIF summary is formatted cleanly."""
        exif_data = {
            "target": "/images/sample.jpg",
            "exif_found": True,
            "hardware": {
                "Camera Make": "Sony",
                "Camera Model": "ILCE-7M3",
                "Date/Time Original": "2024:05:12 14:22:01",
            },
            "gps": {
                "Latitude": "23.8103",
                "Longitude": "90.4125",
                "Google Maps Link": "https://www.google.com/maps?q=23.8103,90.4125",
            },
        }
        summary = generate_summary_text("/images/sample.jpg", "exif", exif_data, "/tmp/case_test")
        self.assertIn("Image Target    : /images/sample.jpg", summary)
        self.assertIn("Camera Device   : Sony ILCE-7M3", summary)
        self.assertIn("Coordinates     : 23.8103, 90.4125", summary)


class TestPhase1PhoneRecon(unittest.TestCase):
    """Test dynamic international prefix detection and phone parsing."""

    def test_bangladesh_international_plus(self):
        res = analyze_phone("+8801812345678")
        self.assertTrue(res["valid"])
        self.assertEqual(res["e164"], "+8801812345678")
        self.assertIn("Bangladesh", res["country"])

    def test_bangladesh_national_format(self):
        """Test national 018... Bangladesh format."""
        res = analyze_phone("01812345678")
        self.assertTrue(res["valid"])
        self.assertEqual(res["e164"], "+8801812345678")
        self.assertIn("Bangladesh", res["country"])

    def test_bangladesh_prefix_without_plus(self):
        """Test 88018... prefix without leading plus."""
        res = analyze_phone("8801812345678")
        self.assertTrue(res["valid"])
        self.assertEqual(res["e164"], "+8801812345678")
        self.assertIn("Bangladesh", res["country"])

    def test_us_and_international_numbers(self):
        res = analyze_phone("+14155552671")
        self.assertTrue(res["valid"])
        self.assertEqual(res["e164"], "+14155552671")

    def test_explicit_region_parameter(self):
        """Test explicit region override."""
        res = analyze_phone("01812345678", region="BD")
        self.assertTrue(res["valid"])
        self.assertEqual(res["e164"], "+8801812345678")


class TestPhase1DossierTargetType(unittest.TestCase):
    """Test target type classification logic in dossier.py."""

    def test_image_path_detection(self):
        """Ensure file extensions and paths route to exif, NOT domain."""
        self.assertEqual(detect_target_type("photo.jpg"), "exif")
        self.assertEqual(detect_target_type("screenshot.png"), "exif")
        self.assertEqual(detect_target_type("/path/to/evidence.jpeg"), "exif")
        self.assertEqual(detect_target_type("C:\\Images\\pic.webp"), "exif")

    def test_other_target_types(self):
        self.assertEqual(detect_target_type("target@example.com"), "email")
        self.assertEqual(detect_target_type("192.168.1.1"), "ip")
        self.assertEqual(detect_target_type("+8801812345678"), "phone")
        self.assertEqual(detect_target_type("01812345678"), "phone")
        self.assertEqual(detect_target_type("415-555-2671"), "phone")
        self.assertEqual(detect_target_type("(415) 555-2671"), "phone")
        self.assertEqual(detect_target_type("018-1234-5678"), "phone")
        self.assertEqual(detect_target_type("github.com"), "domain")
        self.assertEqual(detect_target_type("torvalds"), "username")

    def test_master_dossier_summary_includes_module_findings(self):
        """Ensure Master Dossier summary includes sub-module intelligence findings."""
        dossier_data = {
            "target_seed": "example.com",
            "seed_type": "domain",
            "domain_recon": {
                "subdomains": [{"subdomain": "api.example.com", "ips": ["1.2.3.4"]}],
                "subdomain_takeovers": [{"subdomain": "docs.example.com", "vulnerable": True}],
                "email_security": {"posture": "SECURE: Strictly Protected"},
                "tech_stack": ["Nginx", "React"],
                "infostealer": {"compromised": True, "total": 12},
            },
            "shodan_recon": {
                "ports": [80, 443, 8080],
                "vulns": ["CVE-2023-1234"],
            },
            "cloud_recon": {
                "buckets": [{"Provider": "AWS S3", "Bucket Name": "example-data", "Status": "200 OK"}],
            },
        }
        summary = generate_summary_text("example.com", "all", dossier_data, "/tmp/case_test")
        self.assertIn("Subdomains Found: 1", summary)
        self.assertIn("Takeover Risks: 1 vulnerable", summary)
        self.assertIn("Mail Security   : SECURE: Strictly Protected", summary)
        self.assertIn("Web Tech Stack  : Nginx, React", summary)
        self.assertIn("Infostealers  : 12 compromised credentials", summary)
        self.assertIn("Open Ports      : 80, 443, 8080", summary)
        self.assertIn("Critical CVEs : CVE-2023-1234", summary)
        self.assertIn("Open Buckets  : 1 publicly exposed", summary)

    def test_cloud_and_urls_summary_formatters(self):
        """Ensure cloud and urls scan modes format dedicated findings in summary.txt."""
        cloud_data = {
            "target": "acme",
            "total_discovered": 2,
            "buckets": [
                {"Provider": "AWS S3", "Bucket Name": "acme-assets", "Status": "200 OK"},
                {"Provider": "Google Cloud", "Bucket Name": "acme-backup", "Status": "403 Forbidden"},
            ],
        }
        cloud_summary = generate_summary_text("acme", "cloud", cloud_data, "/tmp/case_test")
        self.assertIn("Total Found     : 2 storage bucket(s)", cloud_summary)
        self.assertIn("Open Buckets  : 1 publicly accessible", cloud_summary)
        self.assertIn("[AWS S3]: acme-assets (200 OK)", cloud_summary)

        url_data = {
            "domain": "target.com",
            "total_found": 50,
            "sensitive_findings": [
                {"keywords": ".env, credentials", "url": "https://target.com/.env"},
            ],
        }
        urls_summary = generate_summary_text("target.com", "urls", url_data, "/tmp/case_test")
        self.assertIn("Total Harvested : 50 URL(s)", urls_summary)
        self.assertIn("Sensitive URLs: 1 high-value", urls_summary)
        self.assertIn("[.env, credentials]: https://target.com/.env", urls_summary)


class TestPhase1ResolverIntegration(unittest.TestCase):
    """Test resolver usage in shodan_recon and ip_recon."""

    @patch("nexus_osint.modules.shodan_recon.resolve_records")
    def test_shodan_resolves_via_resolver(self, mock_resolve):
        mock_resolve.return_value = ["93.184.216.34"]
        ip = resolve_to_ip("example.com")
        self.assertEqual(ip, "93.184.216.34")
        mock_resolve.assert_called_with("example.com", "A")

    @patch("nexus_osint.modules.ip_recon.resolve_records")
    def test_ip_recon_resolves_via_resolver(self, mock_resolve):
        mock_resolve.return_value = ["93.184.216.34"]
        ip = resolve_domain_to_ip("example.com")
        self.assertEqual(ip, "93.184.216.34")
        mock_resolve.assert_called_with("example.com", "A")

    @patch("nexus_osint.modules.ip_recon.resolve_records")
    @patch("socket.gethostbyname")
    def test_ip_recon_unresolvable_raises_clean_value_error(self, mock_socket, mock_resolve):
        mock_resolve.return_value = []
        mock_socket.side_effect = Exception("Resolution failed")
        with self.assertRaises(ValueError):
            resolve_domain_to_ip("unresolvable-domain-xyz123.test")


if __name__ == "__main__":
    unittest.main()
