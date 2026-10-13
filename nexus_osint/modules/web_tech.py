"""
Web Technology Stack Fingerprinter & Favicon Hash Module for NexusOSINT.
Identifies CMS, web frameworks, CDNs, cloud proxies, and calculates
Shodan-compatible MurmurHash3 favicon hashes.
"""

import codecs
import hashlib
import re
from typing import Any, Dict, List, Optional
import httpx


def mmh3_hash32(key: bytes, seed: int = 0) -> int:
    """Pure Python implementation of 32-bit MurmurHash3 (x86)."""
    length = len(key)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(0, nblocks * 4, 4):
        k1 = key[i] | (key[i + 1] << 8) | (key[i + 2] << 16) | (key[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = key[nblocks * 4:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    # Convert to signed 32-bit int (Shodan standard format)
    if h1 >= 0x80000000:
        return h1 - 0x100000000
    return h1


def calculate_favicon_hash(content: bytes) -> Dict[str, Any]:
    """Calculate MurmurHash3 (Shodan compatible), MD5, and SHA256 of favicon bytes."""
    b64 = codecs.encode(content, "base64")
    shodan_mmh3 = mmh3_hash32(b64)
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    return {
        "murmur3": shodan_mmh3,
        "md5": md5_hash,
        "sha256": sha256_hash,
        "shodan_dork": f"http.favicon.hash:{shodan_mmh3}",
    }


def fetch_favicon_hashes(domain: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Fetch website favicon and calculate cryptographic and Shodan hashes."""
    clean = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/2.0"}

    urls_to_try = [
        f"https://{clean}/favicon.ico",
        f"http://{clean}/favicon.ico",
    ]

    for url in urls_to_try:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200 and len(resp.content) > 10:
                    hashes = calculate_favicon_hash(resp.content)
                    hashes["favicon_url"] = str(resp.url)
                    hashes["size_bytes"] = len(resp.content)
                    return hashes
        except Exception:
            continue

    return None


# Fingerprint signatures for technology stack analysis
TECH_SIGNATURES: List[Dict[str, Any]] = [
    # Servers
    {"name": "Nginx", "category": "Web Server", "headers": {"server": r"nginx"}},
    {"name": "Apache", "category": "Web Server", "headers": {"server": r"apache"}},
    {"name": "LiteSpeed", "category": "Web Server", "headers": {"server": r"litespeed"}},
    {"name": "Microsoft-IIS", "category": "Web Server", "headers": {"server": r"microsoft-iis"}},
    {"name": "Caddy", "category": "Web Server", "headers": {"server": r"caddy"}},
    {"name": "OpenResty", "category": "Web Server", "headers": {"server": r"openresty"}},
    {"name": "Envoy", "category": "Web Server", "headers": {"server": r"envoy"}},
    # CDNs & Proxies
    {"name": "Cloudflare", "category": "CDN / Proxy", "headers": {"server": r"cloudflare", "cf-ray": r".*"}},
    {"name": "Amazon CloudFront", "category": "CDN / Proxy", "headers": {"via": r"cloudfront", "x-amz-cf-id": r".*"}},
    {"name": "Fastly", "category": "CDN / Proxy", "headers": {"x-fastly-request-id": r".*"}},
    {"name": "Akamai", "category": "CDN / Proxy", "headers": {"x-akamai-transformed": r".*"}},
    {"name": "Vercel", "category": "Cloud / Hosting", "headers": {"x-vercel-id": r".*", "server": r"vercel"}},
    {"name": "Netlify", "category": "Cloud / Hosting", "headers": {"x-nf-request-id": r".*", "server": r"netlify"}},
    # CMS
    {"name": "WordPress", "category": "CMS", "html": [r"/wp-content/", r"/wp-includes/", r'<meta[^>]*name="generator"[^>]*WordPress', r"wp-json"]},
    {"name": "Drupal", "category": "CMS", "html": [r"Drupal\.settings", r'<meta[^>]*name="generator"[^>]*Drupal'], "headers": {"x-generator": r"drupal"}},
    {"name": "Joomla", "category": "CMS", "html": [r"/components/com_", r'<meta[^>]*name="generator"[^>]*Joomla']},
    {"name": "Shopify", "category": "E-Commerce", "html": [r"cdn\.shopify\.com", r"Shopify\.shop"], "headers": {"x-shopid": r".*"}},
    {"name": "Ghost", "category": "CMS", "html": [r'<meta[^>]*name="generator"[^>]*Ghost'], "headers": {"x-ghost-cache-status": r".*"}},
    {"name": "Squarespace", "category": "CMS / Builder", "html": [r"static1\.squarespace\.com"]},
    {"name": "Wix", "category": "CMS / Builder", "html": [r"_wix_browser_sess", r"wix-static\.com"]},
    # Web Frameworks
    {"name": "Next.js", "category": "JavaScript Framework", "html": [r"/_next/", r"__NEXT_DATA__"]},
    {"name": "Nuxt.js", "category": "JavaScript Framework", "html": [r"/_nuxt/", r"__NUXT__"]},
    {"name": "React", "category": "JavaScript Library", "html": [r"data-reactroot", r"react\.production\.min\.js", r"_reactListening"]},
    {"name": "Vue.js", "category": "JavaScript Framework", "html": [r"data-v-", r"vue\.runtime", r"vue\.min\.js"]},
    {"name": "Angular", "category": "JavaScript Framework", "html": [r"ng-version", r"ng-app"]},
    {"name": "Laravel", "category": "Backend Framework", "headers": {"set-cookie": r"laravel_session"}, "html": [r"csrf-token"]},
    {"name": "Django", "category": "Backend Framework", "headers": {"set-cookie": r"csrftoken"}},
    {"name": "Ruby on Rails", "category": "Backend Framework", "headers": {"x-runtime": r".*", "set-cookie": r"_session_id"}},
    {"name": "Express", "category": "Backend Framework", "headers": {"x-powered-by": r"express"}},
    {"name": "ASP.NET", "category": "Backend Framework", "headers": {"x-powered-by": r"asp\.net", "x-aspnet-version": r".*"}},
    # CSS & UI Libraries
    {"name": "Bootstrap", "category": "UI Framework", "html": [r"bootstrap(?:\.min)?\.css", r"bootstrap(?:\.bundle)?\.min\.js"]},
    {"name": "Tailwind CSS", "category": "UI Framework", "html": [r"tailwind(?:\.min)?\.css"]},
    {"name": "jQuery", "category": "JavaScript Library", "html": [r"jquery(?:\.min)?\.js"]},
]


def fingerprint_web_technologies(headers: Dict[str, str], html: str = "") -> Dict[str, Any]:
    """Analyze HTTP response headers and HTML content to identify tech stack."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    detected: List[str] = []
    categories: Dict[str, List[str]] = {}

    for item in TECH_SIGNATURES:
        name = item["name"]
        cat = item["category"]
        matched = False

        # Check headers
        if "headers" in item:
            for hk, pat in item["headers"].items():
                val = lower_headers.get(hk.lower(), "")
                if val and re.search(pat, val, re.IGNORECASE):
                    matched = True
                    break

        # Check HTML patterns if not matched yet
        if not matched and html and "html" in item:
            for pat in item["html"]:
                if re.search(pat, html, re.IGNORECASE):
                    matched = True
                    break

        if matched and name not in detected:
            detected.append(name)
            categories.setdefault(cat, []).append(name)

    return {
        "technologies": detected,
        "categories": categories,
    }
