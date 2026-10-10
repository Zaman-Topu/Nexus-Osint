"""
Passive Historical URL & Archive Discovery Module for NexusOSINT.
Queries threat intelligence and web archive registries to find historical endpoints,
sensitive file extensions, and admin surfaces.
"""

from typing import Any, Dict, List
import httpx

from nexus_osint.ui import (
    console,
    display_list_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)

SENSITIVE_KEYWORDS = [
    ".env", ".git", ".sql", ".bak", ".config", ".conf", ".log",
    "admin", "api", "login", "swagger", "graphql", "oauth", "token",
    "backup", "secret", "private", "database", "dashboard"
]


def query_alienvault_urls(domain: str, limit: int = 100, timeout: float = 6.0) -> List[str]:
    """Retrieve indexed endpoints from AlienVault OTX indicator database."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit={limit}&page=1"
    headers = {"User-Agent": "NexusOSINT/1.0"}
    urls = []
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("url_list", []):
                    entry = item.get("url")
                    if entry and entry not in urls:
                        urls.append(entry)
    except Exception:
        pass
    return urls


def analyze_passive_urls(domain_input: str, limit: int = 100, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute passive URL and historical endpoint reconnaissance."""
    clean = domain_input.strip().replace("https://", "").replace("http://", "").split("/")[0].lower()
    print_section("Passive URL & Archive Recon", f"Target: {clean}")

    log_info(f"Querying public indicators for historical URLs under: {clean}...")
    urls = query_alienvault_urls(clean, limit=limit, timeout=timeout)

    if not urls:
        log_info("No historical endpoints indexed by passive telemetry.")
        return {"domain": clean, "total_found": 0, "urls": [], "sensitive_findings": []}

    log_success(f"Discovered [bold green]{len(urls)}[/bold green] historical endpoint(s)!")

    # Categorize and filter sensitive URLs
    sensitive = []
    for u in urls:
        u_lower = u.lower()
        matched_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in u_lower]
        if matched_keywords:
            sensitive.append({
                "url": u,
                "keywords": ", ".join(matched_keywords),
            })

    if sensitive:
        log_warning(f"Identified [bold red]{len(sensitive)}[/bold red] potentially sensitive or high-value URL(s)!")
        rows = [[item["keywords"], item["url"][:80] + ("..." if len(item["url"]) > 80 else "")] for item in sensitive[:20]]
        display_list_table("High-Value / Sensitive Endpoints", ["Indicators", "Discovered URL"], rows, border_style="red")
    else:
        log_info("No immediately sensitive filenames identified in sample.")

    # Display sample endpoints
    sample_rows = [[u[:90] + ("..." if len(u) > 90 else "")] for u in urls[:15]]
    display_list_table("Sample Historical Endpoints", ["URL"], sample_rows, border_style="cyan")

    return {
        "domain": clean,
        "total_found": len(urls),
        "urls": urls,
        "sensitive_findings": sensitive,
    }
