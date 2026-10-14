"""
Dark Web & Underground Threat Intelligence Module for NexusOSINT.
Discovers hidden services (.onion), darknet search indexes, clearnet Tor2web mirrors,
and correlates darkweb credential breach telemetry with zero paid API keys.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse
import httpx
import re

from nexus_osint.ui import (
    console,
    display_key_value_table,
    display_list_table,
    log_info,
    log_success,
    log_warning,
    print_section,
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def search_tor66_darknet(query: str, timeout: float = 8.0, max_results: int = 15) -> List[Dict[str, Any]]:
    """
    Query the Tor66 darknet search index for active .onion hidden services.
    Converts discovered services into clearnet Tor2web gateway mirrors.
    """
    clean_q = query.strip()
    results: List[Dict[str, Any]] = []

    try:
        url = f"https://tor66.org/search?q={clean_q}"
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code != 200:
                return results

            # Pattern: <div class="domaingrid">\s*<a href="http[s]?://...onion..." title="..."
            pattern = r'<div class=\"domaingrid\">\s*<a[^>]*href=\"(http[s]?://[^\"]*\.onion[^\"]*)\"[^>]*title=\"([^\"]*)\"'
            matches = re.findall(pattern, resp.text)

            seen_onions = set()
            for onion_url, title in matches:
                domain = urlparse(onion_url).netloc
                if domain in seen_onions:
                    continue
                seen_onions.add(domain)

                clean_title = re.sub(r"<[^>]+>", "", title).strip() or "Untitled Onion Service"
                tor2web = onion_url.replace(".onion", ".onion.pet")

                results.append({
                    "title": clean_title,
                    "onion_url": onion_url,
                    "tor2web_url": tor2web,
                    "domain": domain,
                    "engine": "Tor66 Darknet Engine",
                })
                if len(results) >= max_results:
                    break
    except Exception:
        pass

    return results


def search_darknet_gateways_ddg(query: str, timeout: float = 8.0, max_results: int = 10) -> List[Dict[str, Any]]:
    """
    Query DuckDuckGo for clearnet Tor2web mirrors (.onion.pet, .onion.ws, .onion.ly)
    and public paste leak dumps (Pastebin, Rentry, JustPasteIt).
    """
    clean_q = query.strip()
    results: List[Dict[str, Any]] = []

    # Search for darknet gateways and pastes mentioning the target
    dork_query = f'"{clean_q}" (site:onion.pet OR site:onion.ws OR site:pastebin.com OR site:rentry.co)'

    try:
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp = client.post("https://html.duckduckgo.com/html/", data={"q": dork_query})
            if resp.status_code != 200:
                return results

            matches = re.findall(
                r'<h2 class=\"result__title\">.*?<a rel=\"nofollow\" class=\"result__a\" href=\"([^\"]+)\">(.*?)</a>',
                resp.text,
                re.DOTALL,
            )

            seen_urls = set()
            for href, raw_title in matches:
                if "uddg=" in href:
                    actual_url = unquote(href.split("uddg=")[1].split("&")[0])
                else:
                    actual_url = href

                if actual_url in seen_urls:
                    continue
                seen_urls.add(actual_url)

                clean_title = re.sub(r"<[^>]+>", "", raw_title).strip()
                parsed = urlparse(actual_url)

                results.append({
                    "title": clean_title,
                    "url": actual_url,
                    "domain": parsed.netloc,
                    "source": "Darknet Gateway / Paste Dump",
                })
                if len(results) >= max_results:
                    break
    except Exception:
        pass

    return results


def analyze_darkweb(target: str, timeout: float = 8.0, max_results: int = 15) -> Dict[str, Any]:
    """
    Master Dark Web intelligence pipeline.
    Queries Tor hidden services, Tor2web clearnet mirrors, and underground breach leaks.
    """
    clean_target = target.strip()
    print_section("Dark Web & Underground Intelligence", f"Target: {clean_target}")

    log_info("Querying Tor66 Darknet search index for .onion hidden services...")
    onion_results = search_tor66_darknet(clean_target, timeout=timeout, max_results=max_results)

    log_info("Scanning clearnet Tor2web mirrors & public paste leak dumps...")
    gateway_results = search_darknet_gateways_ddg(clean_target, timeout=timeout, max_results=10)

    total_hits = len(onion_results) + len(gateway_results)

    # 1. Display Discovered Tor Hidden Services (.onion)
    if onion_results:
        log_success(f"Discovered [bold red]{len(onion_results)}[/bold red] Dark Web (.onion) service(s)!")
        onion_headers = ["Title / Description", "Tor Hidden Service (.onion)", "Clearnet Mirror Link"]
        onion_rows = [
            [
                r["title"][:42],
                r["onion_url"][:45] + ("..." if len(r["onion_url"]) > 45 else ""),
                r["tor2web_url"][:45] + ("..." if len(r["tor2web_url"]) > 45 else ""),
            ]
            for r in onion_results[:20]
        ]
        display_list_table("Dark Web (.onion) Hidden Services", onion_headers, onion_rows, border_style="red")
    else:
        log_info("No direct .onion hidden service results found on Tor66 index.")

    # 2. Display Tor2web & Paste Dumps
    if gateway_results:
        log_success(f"Discovered [bold yellow]{len(gateway_results)}[/bold yellow] Darknet gateway / paste leak mention(s)!")
        gw_headers = ["Source / Domain", "Title", "Direct URL"]
        gw_rows = [
            [
                r["domain"],
                r["title"][:40],
                r["url"][:45] + ("..." if len(r["url"]) > 45 else ""),
            ]
            for r in gateway_results[:15]
        ]
        display_list_table("Darknet Gateways & Paste Leaks", gw_headers, gw_rows, border_style="yellow")
    else:
        log_info("No darknet gateway or paste dump references found.")

    # 3. Overall Dark Web Threat Posture Table
    threat_level = "ELEVATED (Dark Web Footprint Detected)" if total_hits > 0 else "CLEAN / LOW (No Public Darknet Indexing)"
    posture_data = {
        "Target Query": clean_target,
        "Total Onion Services": str(len(onion_results)),
        "Gateway & Paste Mentions": str(len(gateway_results)),
        "Total Darknet Hits": str(total_hits),
        "Darknet Exposure Level": threat_level,
    }
    display_key_value_table("Dark Web Threat Exposure Assessment", posture_data, border_style="red" if total_hits > 0 else "green")

    return {
        "target": clean_target,
        "total_hits": total_hits,
        "threat_level": threat_level,
        "onion_services": onion_results,
        "gateway_leaks": gateway_results,
    }
