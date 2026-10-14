"""
Unit Tests for Dark Web Reconnaissance and Multi-Search Engine OSINT Modules.
"""

import unittest
from unittest.mock import MagicMock, patch

from nexus_osint.modules.darkweb_recon import (
    analyze_darkweb,
    search_darknet_gateways_ddg,
    search_tor66_darknet,
)
from nexus_osint.modules.search_recon import (
    analyze_search,
    generate_osint_dorks,
    query_duckduckgo_knowledge,
    search_duckduckgo_web,
)


SAMPLE_TOR66_HTML = """
<html>
<body>
<div class="results">
    <div class="domaingrid">
        <a href="http://expyuz5wqqfdgah56trldbdunwy2qdnghxjybmumvf3m5mgflbhgahyd.onion/index.html" title="Tor Project Official Hidden Service">
            Tor Project Mirror
        </a>
    </div>
    <div class="domaingrid">
        <a href="http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/" title="DuckDuckGo Darknet Search">
            DuckDuckGo Onion
        </a>
    </div>
</div>
</body>
</html>
"""

SAMPLE_DDG_GATEWAYS_HTML = """
<html>
<body>
<div class="results">
    <h2 class="result__title">
        <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fpastebin.com%2Fraw%2Fxyz123&rut=abc">
            <b>Target</b> Database Dump &amp; Leaks - Pastebin
        </a>
    </h2>
    <h2 class="result__title">
        <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ftargethidden.onion.pet%2Flogin&rut=abc">
            Target Onion Portal Mirror
        </a>
    </h2>
</div>
</body>
</html>
"""

SAMPLE_DDG_WEB_HTML = """
<html>
<body>
<div class="results">
    <h2 class="result__title">
        <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fabout&rut=abc">
            <b>Example</b> Domain - Official Homepage
        </a>
    </h2>
    <a class="result__snippet" href="#">
        Official documentation and examples for Example Domain organisation.
    </a>
</div>
</body>
</html>
"""


class TestDarkWebRecon(unittest.TestCase):
    """Test Dark Web search indexes, Tor hidden services, and Tor2web mirror extraction."""

    @patch("nexus_osint.modules.darkweb_recon.httpx.Client")
    def test_search_tor66_darknet(self, mock_client_cls):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = SAMPLE_TOR66_HTML
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        results = search_tor66_darknet("tor", max_results=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["domain"], "expyuz5wqqfdgah56trldbdunwy2qdnghxjybmumvf3m5mgflbhgahyd.onion")
        self.assertIn("expyuz5wqqfdgah56trldbdunwy2qdnghxjybmumvf3m5mgflbhgahyd.onion.pet", results[0]["tor2web_url"])
        self.assertEqual(results[0]["title"], "Tor Project Official Hidden Service")
        self.assertEqual(results[1]["title"], "DuckDuckGo Darknet Search")

    @patch("nexus_osint.modules.darkweb_recon.httpx.Client")
    def test_search_darknet_gateways_ddg(self, mock_client_cls):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = SAMPLE_DDG_GATEWAYS_HTML
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        results = search_darknet_gateways_ddg("target", max_results=5)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["url"], "https://pastebin.com/raw/xyz123")
        self.assertEqual(results[0]["domain"], "pastebin.com")
        self.assertIn("Pastebin", results[0]["title"])
        self.assertEqual(results[1]["url"], "https://targethidden.onion.pet/login")

    @patch("nexus_osint.modules.darkweb_recon.search_darknet_gateways_ddg")
    @patch("nexus_osint.modules.darkweb_recon.search_tor66_darknet")
    def test_analyze_darkweb_hits(self, mock_tor66, mock_ddg):
        mock_tor66.return_value = [
            {
                "title": "Breached Database Hidden Service",
                "onion_url": "http://breached1234567.onion",
                "tor2web_url": "http://breached1234567.onion.pet",
                "domain": "breached1234567.onion",
                "engine": "Tor66 Darknet Engine",
            }
        ]
        mock_ddg.return_value = [
            {
                "title": "Target Paste Leak",
                "url": "https://pastebin.com/abc",
                "domain": "pastebin.com",
                "source": "Darknet Gateway / Paste Dump",
            }
        ]

        result = analyze_darkweb("targetcorp")
        self.assertEqual(result["target"], "targetcorp")
        self.assertEqual(result["total_hits"], 2)
        self.assertIn("ELEVATED", result["threat_level"])
        self.assertEqual(len(result["onion_services"]), 1)
        self.assertEqual(len(result["gateway_leaks"]), 1)

    @patch("nexus_osint.modules.darkweb_recon.search_darknet_gateways_ddg")
    @patch("nexus_osint.modules.darkweb_recon.search_tor66_darknet")
    def test_analyze_darkweb_clean(self, mock_tor66, mock_ddg):
        mock_tor66.return_value = []
        mock_ddg.return_value = []

        result = analyze_darkweb("cleanseed")
        self.assertEqual(result["total_hits"], 0)
        self.assertIn("CLEAN", result["threat_level"])


class TestSearchRecon(unittest.TestCase):
    """Test Multi-Search Engine harvesting, DuckDuckGo Knowledge entity, and OSINT Dorking."""

    @patch("nexus_osint.modules.search_recon.httpx.Client")
    def test_search_duckduckgo_web(self, mock_client_cls):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = SAMPLE_DDG_WEB_HTML
        mock_client.post.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        results = search_duckduckgo_web("example domain", max_results=5)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://example.com/about")
        self.assertEqual(results[0]["domain"], "example.com")
        self.assertIn("Example Domain", results[0]["title"])
        self.assertIn("Official documentation", results[0]["snippet"])

    @patch("nexus_osint.modules.search_recon.httpx.Client")
    def test_query_duckduckgo_knowledge(self, mock_client_cls):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Heading": "Python (programming language)",
            "Abstract": "Python is a high-level, general-purpose programming language.",
            "AbstractSource": "Wikipedia",
            "AbstractURL": "https://en.wikipedia.org/wiki/Python_(programming_language)",
            "Type": "A",
        }
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        entity = query_duckduckgo_knowledge("python")
        self.assertEqual(entity["heading"], "Python (programming language)")
        self.assertIn("high-level", entity["abstract"])
        self.assertEqual(entity["abstract_source"], "Wikipedia")

    def test_generate_osint_dorks_domain(self):
        dorks = generate_osint_dorks("example.com")
        self.assertGreaterEqual(len(dorks), 6)
        categories = [d["category"] for d in dorks]
        self.assertTrue(any("Config" in c for c in categories))
        self.assertTrue(any("Database" in c for c in categories))
        self.assertTrue(any("Admin" in c for c in categories))
        for d in dorks:
            self.assertIn("google.com/search?q=", d["google_url"])
            self.assertIn("duckduckgo.com/?q=", d["ddg_url"])
            self.assertIn("example.com", d["dork"])

    def test_generate_osint_dorks_username(self):
        dorks = generate_osint_dorks("cyberhunter")
        self.assertGreaterEqual(len(dorks), 5)
        categories = [d["category"] for d in dorks]
        self.assertTrue(any("Account" in c or "Profiles" in c for c in categories))
        self.assertTrue(any("Developer" in c for c in categories))
        for d in dorks:
            self.assertIn("cyberhunter", d["dork"])

    @patch("nexus_osint.modules.search_recon.query_duckduckgo_knowledge")
    @patch("nexus_osint.modules.search_recon.search_duckduckgo_web")
    def test_analyze_search(self, mock_web, mock_know):
        mock_web.return_value = [
            {
                "title": "Example Domain",
                "url": "https://example.com",
                "domain": "example.com",
                "snippet": "Example Snippet",
                "source": "DuckDuckGo Web",
            }
        ]
        mock_know.return_value = {
            "heading": "Example Domain Entity",
            "abstract": "Example abstract entity description.",
            "abstract_source": "Wikipedia",
            "abstract_url": "https://en.wikipedia.org/wiki/Example",
            "entity_type": "A",
        }

        res = analyze_search("example.com")
        self.assertEqual(res["query"], "example.com")
        self.assertEqual(res["total_results"], 1)
        self.assertEqual(res["knowledge_entity"]["heading"], "Example Domain Entity")
        self.assertGreaterEqual(len(res["osint_dorks"]), 5)


class TestBreachHistoryRecon(unittest.TestCase):
    """Test Historical Breach Incidents, site detection, and relative age calculation."""

    def test_format_breach_timeline(self):
        from nexus_osint.modules.email_recon import format_breach_timeline

        self.assertEqual(format_breach_timeline(""), "Unknown")
        self.assertEqual(format_breach_timeline(None), "Unknown")

        # Past full date
        past_date = "2020-01-01"
        res = format_breach_timeline(past_date)
        self.assertIn("days ago", res)

        # 4-digit year
        year_res = format_breach_timeline("2016")
        self.assertIn("days ago", year_res)
        self.assertIn("yr", year_res)

    @patch("nexus_osint.modules.email_recon.httpx.Client")
    def test_query_email_breaches_xposed(self, mock_client_cls):
        from nexus_osint.modules.email_recon import query_email_breaches_xposed

        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ExposedBreaches": {
                "breaches_details": [
                    {
                        "breach": "LinkedIn",
                        "domain": "linkedin.com",
                        "xposed_date": "2016",
                        "xposed_data": "Email addresses;Passwords;Names",
                        "password_risk": "plaintext",
                        "details": "LinkedIn breach in 2016.",
                        "xposed_records": 164000000,
                    },
                    {
                        "breach": "Canva",
                        "domain": "canva.com",
                        "xposed_date": "2019-05-24",
                        "xposed_data": "Email addresses;Passwords",
                        "password_risk": "easytocrack",
                        "details": "Canva breach in 2019.",
                        "xposed_records": 137000000,
                    },
                ]
            }
        }
        mock_client.get.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_client

        res = query_email_breaches_xposed("victim@example.com")
        self.assertEqual(res["total_breaches"], 2)
        self.assertEqual(res["breaches"][0]["breach"], "LinkedIn")
        self.assertEqual(res["breaches"][0]["domain"], "linkedin.com")
        self.assertIn("days ago", res["breaches"][0]["timeline"])
        self.assertIn("Passwords", res["breaches"][0]["exposed_data"])

        self.assertEqual(res["breaches"][1]["breach"], "Canva")
        self.assertEqual(res["breaches"][1]["domain"], "canva.com")
        self.assertIn("days ago", res["breaches"][1]["timeline"])


if __name__ == "__main__":
    unittest.main()
