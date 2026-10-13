"""
Subdomain Takeover Auditor Module for NexusOSINT.
Scans CNAME records pointing to unclaimed third-party cloud assets
(GitHub Pages, AWS S3, Heroku, Shopify, Azure, Fastly, etc.)
and detects dangling DNS delegation vulnerabilities.
"""

import asyncio
from typing import Any, Dict, List, Optional, Set, Union
import httpx

from nexus_osint.resolver import resolve_records

TAKEOVER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
    },
    {
        "service": "Amazon AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
        ],
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokudns.com"],
        "fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "<title>No such app</title>",
        ],
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "To finish setting up your new web address, go to your Shopify admin",
        ],
    },
    {
        "service": "Microsoft Azure",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"],
        "fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
        ],
    },
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "fingerprints": [
            "The thing you were looking for is gone",
            "site not found",
        ],
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "fingerprints": [
            "project not found",
        ],
    },
    {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io"],
        "fingerprints": [
            "Repository not found",
        ],
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "fingerprints": [
            "Help Center Closed",
        ],
    },
    {
        "service": "Unbounce",
        "cname_patterns": ["unbouncepages.com"],
        "fingerprints": [
            "The requested URL was not found on this server",
        ],
    },
    {
        "service": "WordPress",
        "cname_patterns": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
        ],
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't seem to be here",
        ],
    },
    {
        "service": "Vercel",
        "cname_patterns": ["cname.vercel-dns.com", "vercel-dns.com", "vercel.app"],
        "fingerprints": [
            "The deployment could not be found on Vercel",
            "404: NOT_FOUND",
            "DEPLOYMENT_NOT_FOUND",
        ],
    },
    {
        "service": "Google Firebase",
        "cname_patterns": ["firebaseapp.com", "web.app"],
        "fingerprints": [
            "Site Not Found",
            "There's nothing here, yet",
        ],
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "fingerprints": [
            "404 Not Found",
            "Could not find that app",
        ],
    },
    {
        "service": "ReadTheDocs",
        "cname_patterns": ["readthedocs.io"],
        "fingerprints": [
            "is unknown to Read the Docs",
        ],
    },
    {
        "service": "Statuspage",
        "cname_patterns": ["statuspage.io"],
        "fingerprints": [
            "Hosted Status Pages | Statuspage",
            "Statuspage | Hosted Status Pages",
            "You are being redirected",
        ],
    },
    {
        "service": "Helpjuice",
        "cname_patterns": ["helpjuice.com"],
        "fingerprints": [
            "We could not find what you're looking for",
        ],
    },
]


def check_subdomain_cname(
    subdomain: str,
    known_cnames: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Check if subdomain has a CNAME record matching known cloud services,
    traversing multi-hop CNAME delegation chains if necessary.
    """
    clean_sub = subdomain.strip().lower()
    current = clean_sub
    chain: List[str] = []
    visited: Set[str] = set()

    for hop in range(5):
        if hop == 0 and known_cnames:
            cnames = [c.rstrip(".") for c in known_cnames]
        else:
            cnames = [c.rstrip(".") for c in resolve_records(current, "CNAME")]

        if not cnames:
            break

        next_target = cnames[0]
        if next_target in visited:
            break
        visited.add(next_target)
        chain.append(next_target)

        # Check next_target against known cloud takeover signatures
        for sig in TAKEOVER_SIGNATURES:
            for pat in sig["cname_patterns"]:
                if pat in next_target:
                    return {
                        "subdomain": clean_sub,
                        "cname": next_target,
                        "cname_chain": chain,
                        "service": sig["service"],
                        "fingerprints": sig["fingerprints"],
                    }

        current = next_target

    return None


async def verify_takeover_vulnerability(
    client: httpx.AsyncClient,
    candidate: Dict[str, Any],
    timeout: float = 4.0,
) -> Dict[str, Any]:
    """Verify whether a candidate CNAME returns takeover fingerprints without blocking the event loop."""
    sub = candidate["subdomain"]
    cname = candidate["cname"]
    service = candidate["service"]
    fingerprints = candidate["fingerprints"]
    loop = asyncio.get_running_loop()

    # 1. Non-blocking DNS resolution check for CNAME target
    target_resolves = await loop.run_in_executor(
        None,
        lambda: bool(resolve_records(cname, "A") or resolve_records(cname, "AAAA")),
    )

    # 2. Check HTTP/HTTPS response body for unclaimed fingerprints on subdomain & CNAME target
    urls_to_test = [f"http://{sub}", f"https://{sub}", f"http://{cname}", f"https://{cname}"]
    matched_fingerprint = None

    for url in urls_to_test:
        try:
            resp = await client.get(url, timeout=timeout, follow_redirects=True)
            body = resp.text
            for fp in fingerprints:
                if fp.lower() in body.lower():
                    matched_fingerprint = fp
                    break
            if matched_fingerprint:
                break
        except Exception:
            continue

    if matched_fingerprint:
        return {
            "subdomain": sub,
            "cname": cname,
            "cname_chain": candidate.get("cname_chain", [cname]),
            "service": service,
            "vulnerable": True,
            "status": "CONFIRMED VULNERABLE",
            "evidence": f"Matched provider fingerprint: '{matched_fingerprint}'",
        }
    elif not target_resolves:
        return {
            "subdomain": sub,
            "cname": cname,
            "cname_chain": candidate.get("cname_chain", [cname]),
            "service": service,
            "vulnerable": True,
            "status": "HIGH RISK: DANGLING CNAME",
            "evidence": f"CNAME target '{cname}' does not resolve to an active IP address.",
        }
    else:
        return {
            "subdomain": sub,
            "cname": cname,
            "cname_chain": candidate.get("cname_chain", [cname]),
            "service": service,
            "vulnerable": False,
            "status": "CLAIMED / SAFE",
            "evidence": "Service active and registered by tenant.",
        }


async def audit_subdomains_async(
    subdomains: Union[List[str], List[Dict[str, Any]]],
    concurrency: int = 10,
    timeout: float = 4.0,
) -> List[Dict[str, Any]]:
    """Audit subdomains for takeover vulnerabilities with concurrency and chain support."""
    # Find candidates with matching CNAMEs
    candidates = []
    loop = asyncio.get_running_loop()

    for item in subdomains:
        if isinstance(item, dict):
            sub_name = item.get("subdomain", "")
            known_cnames = item.get("cnames", [])
        else:
            sub_name = str(item)
            known_cnames = None

        if not sub_name:
            continue

        cand = await loop.run_in_executor(None, lambda s=sub_name, kc=known_cnames: check_subdomain_cname(s, known_cnames=kc))
        if cand:
            candidates.append(cand)

    if not candidates:
        return []

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/2.0"}

    async with httpx.AsyncClient(headers=headers, verify=False) as client:
        async def check_candidate(cand):
            async with sem:
                return await verify_takeover_vulnerability(client, cand, timeout=timeout)

        tasks = [check_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]


def audit_subdomain_takeovers(
    subdomains: Union[List[str], List[Dict[str, Any]]],
    concurrency: int = 10,
    timeout: float = 4.0,
) -> List[Dict[str, Any]]:
    """Synchronous entry point for subdomain takeover auditing, safe under existing event loops."""
    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(
                    lambda: asyncio.run(audit_subdomains_async(subdomains, concurrency=concurrency, timeout=timeout))
                ).result()
        else:
            return asyncio.run(audit_subdomains_async(subdomains, concurrency=concurrency, timeout=timeout))
    except Exception:
        return []
