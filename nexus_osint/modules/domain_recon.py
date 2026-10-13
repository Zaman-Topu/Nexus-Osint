"""
Domain & Network Reconnaissance Module for NexusOSINT.
Enumerates DNS records, RDAP/Whois, HTTP security headers, multi-source passive subdomains,
subdomain takeover risks, SPF/DMARC mail spoofability, web technology stack,
favicon MurmurHash3 hashes, and Hudson Rock Cavalier infostealer intelligence.
"""

import asyncio
import urllib.parse
from typing import Any, Dict, List, Optional, Set
import httpx

from nexus_osint.modules.email_security import analyze_mail_security_posture
from nexus_osint.modules.infostealer_recon import query_hudson_rock_domain
from nexus_osint.modules.takeover_auditor import audit_subdomain_takeovers
from nexus_osint.modules.web_tech import fetch_favicon_hashes, fingerprint_web_technologies
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

PASSIVE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/2.0",
}


def clean_domain(target: str) -> str:
    """Normalize domain from URL or raw string."""
    clean = target.strip()
    clean = clean.replace("https://", "").replace("http://", "")
    clean = clean.split("/")[0].split(":")[0]
    return clean.lower()


async def fetch_crtsh_subdomains(domain: str, timeout: float = 6.0) -> Set[str]:
    """Passively query Certificate Transparency logs via crt.sh."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    discovered = set()
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=PASSIVE_HEADERS) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                for item in data:
                    name_val = item.get("name_value", "")
                    for name in name_val.split("\n"):
                        clean_name = name.strip().lower().lstrip("*.")
                        if clean_name.endswith(f".{domain}") or clean_name == domain:
                            discovered.add(clean_name)
    except Exception:
        pass
    return discovered


async def fetch_hackertarget_subdomains(domain: str, timeout: float = 6.0) -> Set[str]:
    """Passively query HackerTarget hostsearch endpoint."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    discovered = set()
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=PASSIVE_HEADERS) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for line in resp.text.strip().splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            discovered.add(sub)
    except Exception:
        pass
    return discovered


async def fetch_alienvault_subdomains(domain: str, timeout: float = 6.0) -> Set[str]:
    """Passively query AlienVault OTX passive DNS and URL lists."""
    discovered = set()
    urls = [
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=100&page=1",
    ]
    try:
        async with httpx.AsyncClient(timeout=timeout, headers=PASSIVE_HEADERS) as client:
            for endpoint in urls:
                try:
                    resp = await client.get(endpoint)
                    if resp.status_code == 200:
                        data = resp.json()
                        # Passive DNS hostnames
                        for item in data.get("passive_dns", []):
                            host = item.get("hostname", "").strip().lower()
                            if host.endswith(f".{domain}") or host == domain:
                                discovered.add(host)
                        # URL list hostnames
                        for item in data.get("url_list", []):
                            u = item.get("url", "")
                            parsed = urllib.parse.urlparse(u)
                            host = parsed.netloc.split(":")[0].strip().lower()
                            if host.endswith(f".{domain}") or host == domain:
                                discovered.add(host)
                except Exception:
                    continue
    except Exception:
        pass
    return discovered


async def check_single_subdomain_dns(fqdn: str, sem: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
    """Resolve A and CNAME records for a candidate subdomain with concurrency control."""
    resolver = get_resolver()
    loop = asyncio.get_running_loop()
    async with sem:
        ips: List[str] = []
        cnames: List[str] = []
        try:
            answers = await loop.run_in_executor(None, lambda: resolver.resolve(fqdn, "A"))
            ips = [r.to_text() for r in answers]
        except Exception:
            pass

        try:
            cname_ans = await loop.run_in_executor(None, lambda: resolver.resolve(fqdn, "CNAME"))
            cnames = [r.target.to_text().rstrip(".") for r in cname_ans]
        except Exception:
            pass

        if ips or cnames:
            return {
                "subdomain": fqdn,
                "ips": ips,
                "cnames": cnames,
            }
    return None


async def discover_all_subdomains(
    domain: str,
    max_concurrent: int = 15,
    timeout: float = 6.0,
) -> List[Dict[str, Any]]:
    """
    Execute multi-source passive discovery (crt.sh, HackerTarget, AlienVault OTX)
    combined with active wordlist DNS probing in parallel.
    """
    # 1. Query passive sources in parallel with strict timeouts
    passive_tasks = [
        fetch_crtsh_subdomains(domain, timeout=timeout),
        fetch_hackertarget_subdomains(domain, timeout=timeout),
        fetch_alienvault_subdomains(domain, timeout=timeout),
    ]
    passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

    candidates: Set[str] = set()
    for res in passive_results:
        if isinstance(res, set):
            candidates.update(res)

    # 2. Add standard wordlist candidates
    for word in COMMON_SUBDOMAINS:
        candidates.add(f"{word}.{domain}")

    # Ensure main domain itself is checked
    candidates.add(domain)

    # 3. Resolve all candidate subdomains concurrently
    sem = asyncio.Semaphore(max_concurrent)
    dns_tasks = [check_single_subdomain_dns(fqdn, sem) for fqdn in sorted(candidates)]
    resolved_results = await asyncio.gather(*dns_tasks, return_exceptions=True)

    active_subdomains: List[Dict[str, Any]] = []
    for r in resolved_results:
        if isinstance(r, dict):
            active_subdomains.append(r)

    active_subdomains.sort(key=lambda x: x["subdomain"])
    return active_subdomains


def query_rdap(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Retrieve RDAP registration metadata."""
    url = f"https://rdap.org/domain/{domain}"
    headers = {"User-Agent": "NexusOSINT/2.0"}
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
    """Inspect HTTP server responses, security headers, and fingerprint tech stack."""
    results: Dict[str, Any] = {
        "status_code": None,
        "final_url": None,
        "server": "Not Disclosed",
        "powered_by": "Not Disclosed",
        "security_headers": {},
        "html_sample": "",
        "headers": {},
    }
    url = f"https://{domain}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/2.0"}
    resp = None

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
            resp = client.get(url, headers=headers)
    except Exception:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                resp = client.get(f"http://{domain}", headers=headers)
        except Exception:
            pass

    if resp:
        results["status_code"] = resp.status_code
        results["final_url"] = str(resp.url)
        results["server"] = resp.headers.get("server", "Not Disclosed")
        results["powered_by"] = resp.headers.get("x-powered-by", "Not Disclosed")
        results["html_sample"] = resp.text[:50000] if resp.text else ""
        results["headers"] = dict(resp.headers)

        for header_name, desc in SECURITY_HEADERS:
            val = resp.headers.get(header_name.lower())
            results["security_headers"][desc] = val is not None

    return results


def analyze_domain(domain_input: str, timeout: float = 6.0, concurrency: int = 15) -> Dict[str, Any]:
    """Run comprehensive modular domain reconnaissance."""
    domain = clean_domain(domain_input)
    print_section("Domain Reconnaissance Scan", f"Target: {domain}")

    # 1. DNS Records
    log_info("Resolving core DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)...")
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

    # 2. Mail Security Posture & Spoofability (SPF/DMARC)
    log_info("Analyzing mail security posture & anti-spoofing policy (SPF/DMARC)...")
    mail_sec = analyze_mail_security_posture(domain)
    mail_summary = {
        "SPF Configured": "Yes" if mail_sec["has_spf"] else "Missing",
        "SPF Enforcement": mail_sec["spf_qualifier"],
        "DMARC Configured": "Yes" if mail_sec["has_dmarc"] else "Missing",
        "DMARC Policy": mail_sec["dmarc_policy"].upper(),
        "Spoofability Posture": mail_sec["posture"],
    }
    display_key_value_table("Email Security & Phishing Risk", mail_summary, border_style="green" if not mail_sec["spoofable"] else "red")

    # 3. RDAP / Registration Info
    log_info("Querying RDAP registration details...")
    rdap_info = query_rdap(domain, timeout=timeout)
    if rdap_info:
        display_key_value_table("RDAP / Registration Info", rdap_info, border_style="magenta")
    else:
        log_info("RDAP data could not be retrieved.")

    # 4. HTTP Profile & Web Technology Stack
    log_info("Auditing HTTP server response, security headers & tech stack...")
    http_data = inspect_http_headers(domain, timeout=timeout)
    tech_data: Dict[str, Any] = {"technologies": [], "categories": {}}

    if http_data["status_code"]:
        overview = {
            "Response Code": str(http_data["status_code"]),
            "Resolved URL": http_data["final_url"],
            "Server Banner": http_data["server"],
            "Powered By": http_data["powered_by"],
        }
        display_key_value_table("Web Server Profile", overview, border_style="blue")
        display_key_value_table("Security Headers Audit", http_data["security_headers"], border_style="green")

        # Fingerprint web technologies
        tech_data = fingerprint_web_technologies(http_data.get("headers", {}), http_data.get("html_sample", ""))
        if tech_data["technologies"]:
            cat_summary = {cat: ", ".join(items) for cat, items in tech_data["categories"].items()}
            display_key_value_table("Web Technology Stack", cat_summary, border_style="cyan")

    # 5. Favicon Forensics & Shodan Dork
    log_info("Probing favicon for MurmurHash3 Shodan footprint...")
    favicon_data = fetch_favicon_hashes(domain, timeout=timeout)
    if favicon_data:
        display_key_value_table("Favicon Hashes & Shodan Dork", {
            "Favicon URL": favicon_data.get("favicon_url", "N/A"),
            "MurmurHash3": str(favicon_data.get("murmur3")),
            "MD5 Hash": favicon_data.get("md5"),
            "Shodan Search Query": favicon_data.get("shodan_dork"),
        }, border_style="yellow")

    # 6. Multi-Source Passive & Active Subdomain Discovery
    log_info("Running multi-source subdomain discovery (crt.sh, HackerTarget, AlienVault OTX, DNS wordlist)...")
    subdomains = asyncio.run(discover_all_subdomains(domain, max_concurrent=concurrency, timeout=timeout))

    if subdomains:
        log_success(f"Discovered [bold green]{len(subdomains)}[/bold green] active subdomain(s) across telemetry sources!")
        sub_headers = ["Subdomain", "Resolved IPv4", "CNAME"]
        sub_rows = [
            [s["subdomain"], ", ".join(s["ips"]) or "None", ", ".join(s.get("cnames", [])) or "None"]
            for s in subdomains[:25]
        ]
        display_list_table(f"Discovered Subdomains (Top {min(len(subdomains), 25)} of {len(subdomains)})", sub_headers, sub_rows, border_style="yellow")
    else:
        log_info("No active subdomains discovered.")

    # 7. Subdomain Takeover Audit
    sub_names = [s["subdomain"] for s in subdomains]
    if sub_names:
        log_info(f"Auditing {len(sub_names)} subdomain(s) for dangling CNAME takeover risks...")
        takeover_findings = audit_subdomain_takeovers(sub_names, concurrency=concurrency, timeout=4.0)
        vulnerable_takeovers = [t for t in takeover_findings if t.get("vulnerable")]

        if vulnerable_takeovers:
            log_warning(f"CRITICAL: Found [bold red]{len(vulnerable_takeovers)}[/bold red] potential Subdomain Takeover risk(s)!")
            to_rows = [
                [t["subdomain"], t["cname"], t["service"], t["status"]]
                for t in vulnerable_takeovers
            ]
            display_list_table("⚠️ Subdomain Takeover Vulnerabilities", ["Subdomain", "Dangling CNAME", "Cloud Provider", "Status"], to_rows, border_style="red")
        else:
            log_success("No dangling CNAME takeover risks identified across enumerated subdomains.")
    else:
        takeover_findings = []

    # 8. Hudson Rock Cavalier Infostealer Intelligence
    log_info("Querying Hudson Rock Cavalier for corporate domain infostealer infections...")
    infostealer_data = query_hudson_rock_domain(domain, timeout=timeout)
    if infostealer_data.get("compromised"):
        log_warning(
            f"CRITICAL: Domain compromised in [bold red]{infostealer_data['total']}[/bold red] infostealer incident(s) "
            f"({infostealer_data['employees']} employee logins, {infostealer_data['users']} user logins compromised)!"
        )
        stealer_summary = {
            "Total Compromised Credentials": str(infostealer_data["total"]),
            "Employee Compromises": str(infostealer_data["employees"]),
            "User Compromises": str(infostealer_data["users"]),
            "Last Employee Breach": infostealer_data.get("last_employee_compromised", "N/A"),
        }
        fams = infostealer_data.get("stealer_families", {})
        if fams:
            top_fams = [f"{k} ({v})" for k, v in sorted(fams.items(), key=lambda x: x[1] if isinstance(x[1], int) else 0, reverse=True)[:5] if k != "total"]
            stealer_summary["Top Malware Families"] = ", ".join(top_fams)
        display_key_value_table("Corporate Infostealer Intelligence", stealer_summary, border_style="red")
    else:
        log_success("No corporate infostealer breaches reported for this domain.")

    # Remove raw html_sample from final output dictionary to keep reports clean
    http_data.pop("html_sample", None)
    http_data.pop("headers", None)

    return {
        "target": domain,
        "domain": domain,
        "dns": dns_findings,
        "rdap": rdap_info,
        "http_profile": http_data,
        "tech_stack": tech_data.get("technologies", []),
        "tech_categories": tech_data.get("categories", {}),
        "favicon": favicon_data,
        "subdomains": subdomains,
        "subdomain_takeovers": takeover_findings,
        "email_security": mail_sec,
        "infostealer": infostealer_data,
    }
