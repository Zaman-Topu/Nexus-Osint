"""
Domain & Network Reconnaissance Module for NexusOSINT.
Enumerates DNS records, RDAP/Whois, HTTP security headers, and subdomains.
"""

import asyncio
from typing import Any, Dict, List, Optional
import httpx

from nexus_osint.resolver import get_resolver, resolve_records
from nexus_osint.ui import (
    console,
    display_key_value_table,
    display_list_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "app", "blog", "admin", "vpn",
    "staging", "portal", "auth", "docs", "cdn", "beta", "status",
    "git", "support", "shop", "sso", "help", "billing", "m",
    "cloud", "test", "secure", "webmail", "direct", "remote",
    "gateway", "dashboard", "hub", "demo", "stage", "internal"
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS"),
    ("Content-Security-Policy", "CSP"),
    ("X-Frame-Options", "Clickjacking Protection"),
    ("X-Content-Type-Options", "MIME Sniffing Protection"),
    ("Referrer-Policy", "Referrer Policy"),
    ("Permissions-Policy", "Feature Permissions"),
]


def clean_domain(target: str) -> str:
    """Normalize domain from URL or raw string."""
    clean = target.strip()
    clean = clean.replace("https://", "").replace("http://", "")
    clean = clean.split("/")[0].split(":")[0]
    return clean.lower()


async def check_subdomain_dns(subdomain: str, domain: str) -> Optional[Dict[str, Any]]:
    """Check if a specific subdomain resolves via DNS."""
    fqdn = f"{subdomain}.{domain}"
    resolver = get_resolver()
    try:
        loop = asyncio.get_running_loop()
        answers = await loop.run_in_executor(None, lambda: resolver.resolve(fqdn, "A"))
        ips = [rdata.to_text() for rdata in answers]
        if ips:
            return {"subdomain": fqdn, "ips": ips}
    except Exception:
        pass
    return None


async def discover_subdomains_wordlist(domain: str, max_concurrent: int = 15) -> List[Dict[str, Any]]:
    """Enumerate common subdomains using async DNS."""
    sem = asyncio.Semaphore(max_concurrent)

    async def sem_check(sub: str):
        async with sem:
            return await check_subdomain_dns(sub, domain)

    tasks = [sem_check(sub) for sub in COMMON_SUBDOMAINS]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def query_rdap(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Retrieve RDAP registration metadata."""
    url = f"https://rdap.org/domain/{domain}"
    headers = {"User-Agent": "NexusOSINT/1.0"}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                events = {ev.get("eventAction"): ev.get("eventDate") for ev in data.get("events", [])}
                entities = data.get("entities", [])
                registrar = "N/A"
                for ent in entities:
                    roles = ent.get("roles", [])
                    if "registrar" in roles:
                        vcard = ent.get("vcardArray", [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                                    break
                        if registrar == "N/A" and "handle" in ent:
                            registrar = ent["handle"]
                        break

                statuses = data.get("status", [])
                return {
                    "Registrar": registrar,
                    "Registration Date": events.get("registration", "N/A"),
                    "Expiration Date": events.get("expiration", "N/A"),
                    "Last Changed Date": events.get("last changed", "N/A"),
                    "Status": ", ".join(statuses[:3]) if statuses else "Active",
                }
    except Exception:
        pass
    return {}


def inspect_http_headers(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Inspect HTTP server responses and security headers."""
    results: Dict[str, Any] = {
        "status_code": None,
        "final_url": None,
        "server": "Not Disclosed",
        "powered_by": "Not Disclosed",
        "security_headers": {},
    }
    url = f"https://{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/1.0"}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = client.get(url, headers=headers)
            results["status_code"] = resp.status_code
            results["final_url"] = str(resp.url)
            results["server"] = resp.headers.get("server", "Not Disclosed")
            results["powered_by"] = resp.headers.get("x-powered-by", "Not Disclosed")

            for header_name, desc in SECURITY_HEADERS:
                val = resp.headers.get(header_name.lower())
                results["security_headers"][desc] = val is not None
    except Exception:
        # Fallback to HTTP if HTTPS fails
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(f"http://{domain}", headers=headers)
                results["status_code"] = resp.status_code
                results["final_url"] = str(resp.url)
                results["server"] = resp.headers.get("server", "Not Disclosed")
                results["powered_by"] = resp.headers.get("x-powered-by", "Not Disclosed")
                for header_name, desc in SECURITY_HEADERS:
                    val = resp.headers.get(header_name.lower())
                    results["security_headers"][desc] = val is not None
        except Exception:
            pass

    return results


def analyze_domain(domain_input: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Run comprehensive domain reconnaissance."""
    domain = clean_domain(domain_input)
    print_section("Domain Reconnaissance Scan", f"Target: {domain}")

    # 1. DNS Records
    log_info("Resolving core DNS records (A, AAAA, MX, NS, TXT, SOA)...")
    dns_findings = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        records = resolve_records(domain, rtype)
        if records:
            dns_findings[rtype] = records

    if dns_findings:
        dns_summary = {rtype: ", ".join(vals[:4]) + ("..." if len(vals) > 4 else "") for rtype, vals in dns_findings.items()}
        display_key_value_table("DNS Records Overview", dns_summary, border_style="cyan")
    else:
        log_warning("No DNS records resolved for this domain.")

    # 2. RDAP / Registration Info
    log_info("Querying RDAP registration details...")
    rdap_info = query_rdap(domain, timeout=timeout)
    if rdap_info:
        display_key_value_table("RDAP / Registration Info", rdap_info, border_style="magenta")
    else:
        log_info("RDAP data could not be retrieved.")

    # 3. HTTP Header & Security Audit
    log_info("Auditing HTTP server response & security headers...")
    http_data = inspect_http_headers(domain, timeout=timeout)
    if http_data["status_code"]:
        overview = {
            "Response Code": str(http_data["status_code"]),
            "Resolved URL": http_data["final_url"],
            "Server Banner": http_data["server"],
            "Powered By": http_data["powered_by"],
        }
        display_key_value_table("Web Server Profile", overview, border_style="blue")
        display_key_value_table("Security Headers Audit", http_data["security_headers"], border_style="green")

    # 4. Subdomain Discovery
    log_info(f"Scanning for active common subdomains ({len(COMMON_SUBDOMAINS)} targets)...")
    subdomains = asyncio.run(discover_subdomains_wordlist(domain))
    if subdomains:
        log_success(f"Discovered {len(subdomains)} active subdomain(s)!")
        sub_headers = ["Subdomain", "Resolved IPv4"]
        sub_rows = [[s["subdomain"], ", ".join(s["ips"])] for s in subdomains]
        display_list_table("Discovered Subdomains", sub_headers, sub_rows, border_style="yellow")
    else:
        log_info("No standard subdomains responded.")

    return {
        "target": domain,
        "dns": dns_findings,
        "rdap": rdap_info,
        "http_profile": http_data,
        "subdomains": subdomains,
    }
