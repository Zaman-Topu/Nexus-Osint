"""
Unit Tests for Phase 2: High-Impact Zero-Key Intelligence in NexusOSINT.
"""

import unittest
from unittest.mock import patch, MagicMock

from nexus_osint.modules.email_security import analyze_mail_security_posture, parse_dmarc_record
from nexus_osint.modules.infostealer_recon import (
    analyze_infostealer,
    query_hudson_rock_domain,
    query_hudson_rock_email,
)
from nexus_osint.modules.takeover_auditor import (
    audit_subdomain_takeovers,
    check_subdomain_cname,
    verify_takeover_vulnerability,
)
from nexus_osint.modules.web_tech import (
    calculate_favicon_hash,
    fetch_favicon_hashes,
    fingerprint_web_technologies,
    mmh3_hash32,
)


class TestPhase2EmailSecurity(unittest.TestCase):
    """Test SPF/DMARC mail security posture and spoofability analysis."""

    def test_parse_dmarc_record(self):
        dmarc = "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com"
        tags = parse_dmarc_record(dmarc)
        self.assertEqual(tags.get("p"), "reject")
        self.assertEqual(tags.get("sp"), "quarantine")
        self.assertEqual(tags.get("pct"), "100")
        self.assertEqual(tags.get("rua"), "mailto:dmarc@example.com")

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_secure_dmarc_reject(self, mock_resolve):
        """p=reject should be classified as NOT spoofable and SECURE."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return ["v=DMARC1; p=reject; rua=mailto:reports@test.com"]
            if rtype == "TXT":
                return ["v=spf1 include:_spf.test.com -all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("test.com")
        self.assertFalse(sec["spoofable"])
        self.assertEqual(sec["risk_level"], "SECURE")
        self.assertEqual(sec["dmarc_policy"], "reject")
        self.assertEqual(sec["spf_qualifier"], "-all")
        self.assertIn("Strictly Protected", sec["posture"])

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_spoofable_dmarc_none(self, mock_resolve):
        """p=none should be flagged as SPOOFABLE with warning."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return ["v=DMARC1; p=none; rua=mailto:reports@test.com"]
            if rtype == "TXT":
                return ["v=spf1 include:_spf.test.com ~all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("test.com")
        self.assertTrue(sec["spoofable"])
        self.assertEqual(sec["risk_level"], "MEDIUM")
        self.assertEqual(sec["dmarc_policy"], "none")
        self.assertIn("Monitoring Only", sec["posture"])

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_missing_dmarc_spoofable(self, mock_resolve):
        """Missing DMARC should be flagged as HIGH RISK SPOOFABLE."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return []
            if rtype == "TXT":
                return ["v=spf1 -all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("test.com")
        self.assertTrue(sec["spoofable"])
        self.assertEqual(sec["risk_level"], "HIGH")
        self.assertEqual(sec["dmarc_policy"], "missing")
        self.assertIn("Missing DMARC Policy", sec["posture"])

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_subdomain_dmarc_fallback_to_org(self, mock_resolve):
        """Subdomain without DMARC inherits organizational domain policy (RFC 7489)."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain == "_dmarc.sub.example.com":
                return []
            if rtype == "TXT" and domain == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; sp=quarantine"]
            if rtype == "TXT" and domain == "sub.example.com":
                return ["v=spf1 -all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("sub.example.com")
        self.assertFalse(sec["spoofable"])
        self.assertEqual(sec["dmarc_policy"], "quarantine")
        self.assertIn("example.com", sec["assessment"])

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_dmarc_pct_zero_spoofable(self, mock_resolve):
        """pct=0 effectively disables policy enforcement (RFC 7489)."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return ["v=DMARC1; p=reject; pct=0"]
            if rtype == "TXT":
                return ["v=spf1 -all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("test.com")
        self.assertTrue(sec["spoofable"])
        self.assertEqual(sec["risk_level"], "MEDIUM")
        self.assertIn("pct=0", sec["posture"])

    @patch("nexus_osint.modules.email_security.resolve_records")
    def test_multiple_spf_records_permerror(self, mock_resolve):
        """Multiple SPF records cause RFC 7208 PermError and spoofability risk."""
        def resolve_side_effect(domain, rtype):
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return []
            if rtype == "TXT":
                return ["v=spf1 include:_spf.a.com ~all", "v=spf1 include:_spf.b.com ~all"]
            return []
        mock_resolve.side_effect = resolve_side_effect

        sec = analyze_mail_security_posture("test.com")
        self.assertTrue(sec["spoofable"])
        self.assertEqual(sec["risk_level"], "HIGH")
        self.assertIn("PermError", sec["posture"])


class TestPhase2WebTechAndFavicon(unittest.TestCase):
    """Test web tech stack fingerprinting and pure Python MurmurHash3 favicon hashing."""

    def test_mmh3_hash32_standard_vectors(self):
        """Verify MurmurHash3 x86-32 produces standard bit-exact values."""
        self.assertEqual(mmh3_hash32(b""), 0)
        self.assertEqual(mmh3_hash32(b"abc"), -1277324294)

    def test_shodan_favicon_hash_calculation(self):
        """Test Shodan favicon calculation and dork generation."""
        dummy_favicon = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        res = calculate_favicon_hash(dummy_favicon)
        self.assertIn("murmur3", res)
        self.assertIn("md5", res)
        self.assertIn("sha256", res)
        self.assertTrue(res["shodan_dork"].startswith("http.favicon.hash:"))

    def test_tech_stack_fingerprinting(self):
        """Test detection of frameworks, servers, and CDNs."""
        headers = {
            "server": "cloudflare",
            "cf-ray": "837482937abcdef-DHK",
            "x-powered-by": "Express",
            "set-cookie": "csrftoken=abcdef123456; Path=/",
        }
        html = '<div id="__NEXT_DATA__"></div><script src="/_next/static/chunks/main.js"></script>'

        res = fingerprint_web_technologies(headers, html)
        techs = res["technologies"]
        self.assertIn("Cloudflare", techs)
        self.assertIn("Express", techs)
        self.assertIn("Django", techs)
        self.assertIn("Next.js", techs)

    @patch("httpx.Client")
    def test_fetch_favicon_html_link_and_ignore_html_error(self, mock_client_cls):
        """Test extracting favicon from HTML link and skipping HTML responses."""
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client

        # Mock responses: first URL returns 200 with HTML (e.g. SPA fallback), second URL returns valid icon bytes
        resp_html = MagicMock(status_code=200, content=b"<!DOCTYPE html><html>404 Not Found</html>")
        resp_icon = MagicMock(status_code=200, content=b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x04\x00", url="https://example.com/assets/favicon.ico")

        mock_client.get.side_effect = [resp_html, resp_icon]
        html_sample = '<head><link rel="icon" href="/assets/favicon.ico"></head>'

        res = fetch_favicon_hashes("example.com", html_sample=html_sample)
        self.assertIsNotNone(res)
        self.assertIn("murmur3", res)
        self.assertIn("http.favicon.hash:", res["shodan_dork"])


class TestPhase2SubdomainTakeover(unittest.TestCase):
    """Test Subdomain Takeover auditor matching and detection."""

    @patch("nexus_osint.modules.takeover_auditor.resolve_records")
    def test_check_subdomain_cname_github(self, mock_resolve):
        mock_resolve.return_value = ["example.github.io"]
        cand = check_subdomain_cname("docs.example.com")
        self.assertIsNotNone(cand)
        self.assertEqual(cand["service"], "GitHub Pages")
        self.assertEqual(cand["cname"], "example.github.io")

    @patch("nexus_osint.modules.takeover_auditor.resolve_records")
    def test_check_subdomain_cname_s3(self, mock_resolve):
        mock_resolve.return_value = ["mybucket.s3.amazonaws.com"]
        cand = check_subdomain_cname("assets.example.com")
        self.assertIsNotNone(cand)
        self.assertEqual(cand["service"], "Amazon AWS S3")

    @patch("nexus_osint.modules.takeover_auditor.resolve_records")
    def test_check_subdomain_cname_none(self, mock_resolve):
        mock_resolve.return_value = []
        cand = check_subdomain_cname("plain.example.com")
        self.assertIsNone(cand)

    @patch("nexus_osint.modules.takeover_auditor.resolve_records")
    def test_check_subdomain_cname_chain_traversal(self, mock_resolve):
        """Test multi-hop CNAME delegation chain resolution."""
        def resolve_chain(domain, rtype):
            if rtype == "CNAME":
                if domain == "alias.example.com":
                    return ["edge.intermediate-cdn.net"]
                if domain == "edge.intermediate-cdn.net":
                    return ["target-app.herokuapp.com"]
            return []
        mock_resolve.side_effect = resolve_chain

        cand = check_subdomain_cname("alias.example.com")
        self.assertIsNotNone(cand)
        self.assertEqual(cand["service"], "Heroku")
        self.assertEqual(cand["cname"], "target-app.herokuapp.com")
        self.assertEqual(cand["cname_chain"], ["edge.intermediate-cdn.net", "target-app.herokuapp.com"])

    @patch("nexus_osint.modules.takeover_auditor.verify_takeover_vulnerability")
    def test_audit_subdomain_takeovers_with_dicts(self, mock_verify):
        """Test audit_subdomain_takeovers accepting discovery dicts with pre-resolved CNAMEs."""
        async def mock_v(client, cand, timeout=4.0):
            return {
                "subdomain": cand["subdomain"],
                "cname": cand["cname"],
                "service": cand["service"],
                "vulnerable": True,
                "status": "CONFIRMED VULNERABLE",
            }
        mock_verify.side_effect = mock_v

        sub_dicts = [
            {"subdomain": "test.example.com", "cnames": ["myteam.github.io"], "ips": []},
            {"subdomain": "clean.example.com", "cnames": [], "ips": ["1.2.3.4"]},
        ]
        res = audit_subdomain_takeovers(sub_dicts)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["service"], "GitHub Pages")
        self.assertTrue(res[0]["vulnerable"])


class TestPhase2Infostealer(unittest.TestCase):
    """Test Hudson Rock Cavalier parsing and UI analysis function."""

    @patch("httpx.Client")
    def test_hudson_rock_email_compromised(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "total_corporate_services": 5,
            "total_user_services": 20,
            "stealers": [
                {
                    "computer_name": "VICTIM-PC",
                    "operating_system": "Windows 11",
                    "date_compromised": "2024-03-01T10:00:00.000Z",
                    "malware_path": "C:\\temp\\stealer.exe",
                    "ip": "1.2.3.*",
                    "top_logins": ["user@test.com"],
                    "top_passwords": ["p***1"],
                }
            ],
            "message": "Infostealer infection found.",
        }
        mock_client.get.return_value = mock_resp

        res = query_hudson_rock_email("test@example.com")
        self.assertTrue(res["compromised"])
        self.assertEqual(res["total_stealers"], 1)
        self.assertEqual(res["total_corporate_services"], 5)
        self.assertEqual(res["stealers"][0]["computer_name"], "VICTIM-PC")

    @patch("httpx.Client")
    def test_hudson_rock_domain_clean(self, mock_client_cls):
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "total": 0,
            "employees": 0,
            "users": 0,
            "stealerFamilies": {},
        }
        mock_client.get.return_value = mock_resp

        res = query_hudson_rock_domain("cleandomain.org")
        self.assertFalse(res["compromised"])
        self.assertEqual(res["total"], 0)

    @patch("nexus_osint.modules.infostealer_recon.query_hudson_rock_email")
    def test_analyze_infostealer_email(self, mock_query):
        mock_query.return_value = {
            "target": "victim@example.com",
            "target_type": "email",
            "compromised": True,
            "total_stealers": 2,
            "total_corporate_services": 1,
            "total_user_services": 5,
            "stealers": [],
        }
        res = analyze_infostealer("victim@example.com")
        self.assertTrue(res["compromised"])
        mock_query.assert_called_once_with("victim@example.com", timeout=8.0)

    @patch("nexus_osint.modules.infostealer_recon.query_hudson_rock_domain")
    def test_analyze_infostealer_domain(self, mock_query):
        mock_query.return_value = {
            "target": "victimcorp.com",
            "target_type": "domain",
            "compromised": True,
            "total": 50,
            "employees": 10,
            "users": 40,
            "stealer_families": {"RedLine": 30, "Lumma": 20},
        }
        res = analyze_infostealer("victimcorp.com")
        self.assertTrue(res["compromised"])
        mock_query.assert_called_once_with("victimcorp.com", timeout=8.0)


if __name__ == "__main__":
    unittest.main()
