"""
Multi-Search Engine Reconnaissance & OSINT Dorking Module for NexusOSINT.
Aggregates search engine results across DuckDuckGo, encyclopedic knowledge entities,
and automatically generates targeted Google/Bing OSINT dorks with zero paid API keys.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, unquote, urlparse
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


def search_duckduckgo_web(query: str, timeout: float = 8.0, max_results: int = 15) -> List[Dict[str, Any]]:
    """
    Scrape DuckDuckGo HTML search results for URLs, page titles, and snippets.
    Resolves redirect URLs to clean direct destinations.
    """
    clean_q = query.strip()
    results: List[Dict[str, Any]] = []

    try:
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp = client.post("https://html.duckduckgo.com/html/", data={"q": clean_q})
            if resp.status_code != 200:
                return results

            # Pattern for title & URL:
            matches = re.findall(
                r'<h2 class=\"result__title\">.*?<a rel=\"nofollow\" class=\"result__a\" href=\"([^\"]+)\">(.*?)</a>',
                resp.text,
                re.DOTALL,
            )

            # Pattern for snippets:
            snippets = re.findall(r'<a class=\"result__snippet\"[^>]*>(.*?)</a>', resp.text, re.DOTALL)

            seen_urls = set()
            for idx, (href, raw_title) in enumerate(matches):
                if "uddg=" in href:
                    actual_url = unquote(href.split("uddg=")[1].split("&")[0])
                else:
                    actual_url = href

                if actual_url in seen_urls:
                    continue
                seen_urls.add(actual_url)

                clean_title = re.sub(r"<[^>]+>", "", raw_title).strip()
                snippet = ""
                if idx < len(snippets):
                    snippet = re.sub(r"<[^>]+>", "", snippets[idx]).strip()

                domain = urlparse(actual_url).netloc
                results.append({
                    "title": clean_title,
                    "url": actual_url,
                    "domain": domain,
                    "snippet": snippet,
                    "source": "DuckDuckGo Web",
                })
                if len(results) >= max_results:
                    break
    except Exception:
        pass

    return results


def query_duckduckgo_knowledge(query: str, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Query DuckDuckGo Instant Answer API for encyclopedic definitions and official references.
    """
    clean_q = query.strip()
    try:
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp = client.get(f"https://api.duckduckgo.com/?q={clean_q}&format=json")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "heading": data.get("Heading", ""),
                    "abstract": data.get("Abstract", ""),
                    "abstract_source": data.get("AbstractSource", ""),
                    "abstract_url": data.get("AbstractURL", ""),
                    "entity_type": data.get("Type", ""),
                }
    except Exception:
        pass
    return {}


def generate_osint_dorks(target: str) -> List[Dict[str, str]]:
    """
    Generate targeted OSINT Google / Bing dorks customized to the target seed
    (Domain, Organization, Username, or Email).
    """
    clean = target.strip().lstrip("@")
    dorks: List[Dict[str, str]] = []

    # If domain-like or containing dot
    is_domain = "." in clean and " " not in clean and not clean.startswith("@")

    if is_domain:
        categories = [
            ("📁 Config & Secrets", f"site:{clean} ext:env OR ext:yml OR ext:json OR ext:xml OR ext:conf"),
            ("🗄️ Database Dumps", f"site:{clean} ext:sql OR ext:dump OR ext:bak OR ext:db"),
            ("🔑 Admin & Login Portals", f"site:{clean} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:cpanel"),
            ("📂 Directory Listings", f'site:{clean} intitle:"Index of /"'),
            ("📄 Sensitive Documents", f"site:{clean} filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv"),
            ("📋 Public Pastes & Leaks", f'"{clean}" (site:pastebin.com OR site:rentry.co OR site:justpaste.it)'),
            ("🐙 Source Code Leaks", f'"{clean}" (site:github.com OR site:gitlab.com)'),
            ("🧅 Darknet Onion References", f'"{clean}" (inurl:onion OR site:tor66.org)'),
        ]
    else:
        # Username, Brand, or Keyword
        categories = [
            ("👤 Account & Profiles", f'"{clean}" (site:linkedin.com OR site:twitter.com OR site:facebook.com)'),
            ("💻 Developer Presence", f'"{clean}" (site:github.com OR site:gitlab.com OR site:stackoverflow.com)'),
            ("📋 Public Pastes & Leaks", f'"{clean}" (site:pastebin.com OR site:rentry.co OR site:justpaste.it)'),
            ("📄 Document Mentions", f'"{clean}" filetype:pdf OR filetype:doc OR filetype:txt'),
            ("🛡️ Security & Breach Mentions", f'"{clean}" (site:breachforums.* OR site:raidforums.* OR "leak")'),
            ("🧅 Darknet Onion References", f'"{clean}" (inurl:onion OR site:tor66.org)'),
        ]

    for label, dork in categories:
        encoded_dork = quote_plus(dork)
        dorks.append({
            "category": label,
            "dork": dork,
            "google_url": f"https://www.google.com/search?q={encoded_dork}",
            "ddg_url": f"https://duckduckgo.com/?q={encoded_dork}",
        })

    return dorks


def analyze_search(query: str, timeout: float = 8.0, max_results: int = 15) -> Dict[str, Any]:
    """
    Master Multi-Search Engine reconnaissance & OSINT Dorking pipeline.
    """
    clean_q = query.strip()
    print_section("Multi-Search Engine Reconnaissance & Dorking", f"Query Target: {clean_q}")

    log_info(f"Querying DuckDuckGo web index for '{clean_q}'...")
    web_results = search_duckduckgo_web(clean_q, timeout=timeout, max_results=max_results)

    log_info("Probing encyclopedic knowledge graph entity...")
    knowledge = query_duckduckgo_knowledge(clean_q, timeout=timeout)

    log_info("Generating tailored OSINT Google & Bing Dork matrix...")
    dorks = generate_osint_dorks(clean_q)

    # 1. Display Knowledge Entity if found
    if knowledge.get("heading") and knowledge.get("abstract"):
        log_success("Authoritative encyclopedic entity identified!")
        display_key_value_table("Knowledge Graph Entity", {
            "Entity Heading": knowledge["heading"],
            "Entity Summary": knowledge["abstract"][:150] + ("..." if len(knowledge["abstract"]) > 150 else ""),
            "Source": knowledge.get("abstract_source", "Knowledge Graph"),
            "Reference URL": knowledge.get("abstract_url", "N/A"),
        }, border_style="cyan")

    # 2. Display Web Search Results
    if web_results:
        log_success(f"Retrieved [bold green]{len(web_results)}[/bold green] search engine result(s)!")
        table_headers = ["Domain", "Result Title", "Destination Link"]
        table_rows = [
            [
                r["domain"][:22],
                r["title"][:40],
                r["url"][:48] + ("..." if len(r["url"]) > 48 else ""),
            ]
            for r in web_results[:20]
        ]
        display_list_table(f"Top Search Engine Results ({clean_q})", table_headers, table_rows, border_style="cyan")
    else:
        log_warning(f"No direct search engine results retrieved for '{clean_q}'.")

    # 3. Display OSINT Dorking Matrix
    if dorks:
        dork_headers = ["Category / Objective", "Targeted Dork Query", "One-Click Search Link"]
        dork_rows = [
            [
                d["category"],
                d["dork"][:44] + ("..." if len(d["dork"]) > 44 else ""),
                d["google_url"][:46] + ("..." if len(d["google_url"]) > 46 else ""),
            ]
            for d in dorks
        ]
        display_list_table("Automated OSINT Google Dorking Matrix", dork_headers, dork_rows, border_style="yellow")

    return {
        "query": clean_q,
        "total_results": len(web_results),
        "web_results": web_results,
        "knowledge_entity": knowledge,
        "osint_dorks": dorks,
    }
