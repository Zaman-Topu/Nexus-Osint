"""
Wayback Machine Historical Asset Recovery & Time Travel Module for NexusOSINT.
Queries the Internet Archive to unearth deleted web pages, earliest snapshots,
defunct endpoints, and legacy assets with zero paid API keys.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx
import re

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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/2.0",
    "Accept": "application/json",
}


def parse_wayback_timestamp(ts_str: str) -> str:
    """Format 14-digit Wayback timestamp YYYYMMDDhhmmss into YYYY-MM-DD HH:MM:SS."""
    if not ts_str or len(ts_str) < 8:
        return ts_str or "Unknown"
    try:
        dt = datetime.strptime(ts_str[:14], "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        try:
            dt = datetime.strptime(ts_str[:8], "%Y%m%d")
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return ts_str


def clean_target_domain(target: str) -> str:
    """Normalize input into bare domain name."""
    clean = target.strip().lower()
    clean = re.sub(r"^https?://", "", clean)
    clean = clean.split("/")[0].split(":")[0]
    return clean


def analyze_wayback(target: str, timeout: float = 8.0, limit: int = 50) -> Dict[str, Any]:
    """
    Master Wayback Machine Time Travel & Defunct Asset Recovery pipeline.
    """
    domain = clean_target_domain(target)
    print_section("Wayback Machine Historical Time Travel", f"Target Domain: {domain}")

    log_info(f"Probing Internet Archive Wayback Machine for historical snapshots of '{domain}'...")

    result: Dict[str, Any] = {
        "domain": domain,
        "has_archives": False,
        "earliest_snapshot_date": "N/A",
        "earliest_snapshot_url": "N/A",
        "latest_snapshot_date": "N/A",
        "latest_snapshot_url": "N/A",
        "archive_lifespan": "N/A",
        "calendar_url": f"https://web.archive.org/web/*/{domain}",
        "changes_url": f"https://web.archive.org/web/changes/{domain}",
        "historical_endpoints": [],
    }

    # 1. Query Availability API for earliest & latest snapshots
    try:
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            # Latest
            resp_latest = client.get(f"https://archive.org/wayback/available?url=http://{domain}")
            if resp_latest.status_code == 200:
                data_latest = resp_latest.json()
                closest_latest = data_latest.get("archived_snapshots", {}).get("closest")
                if closest_latest and closest_latest.get("available"):
                    result["has_archives"] = True
                    result["latest_snapshot_url"] = closest_latest.get("url", "N/A")
                    result["latest_snapshot_date"] = parse_wayback_timestamp(closest_latest.get("timestamp", ""))

            # Earliest (requesting from origin of web archive)
            resp_earliest = client.get(f"https://archive.org/wayback/available?url=http://{domain}&timestamp=19960101")
            if resp_earliest.status_code == 200:
                data_earliest = resp_earliest.json()
                closest_earliest = data_earliest.get("archived_snapshots", {}).get("closest")
                if closest_earliest and closest_earliest.get("available"):
                    result["has_archives"] = True
                    result["earliest_snapshot_url"] = closest_earliest.get("url", "N/A")
                    result["earliest_snapshot_date"] = parse_wayback_timestamp(closest_earliest.get("timestamp", ""))

    except Exception as e:
        log_warning(f"Wayback availability probe error: {e}")

    # Calculate archive lifespan
    if result["earliest_snapshot_date"] != "N/A" and result["latest_snapshot_date"] != "N/A":
        try:
            y_early = int(result["earliest_snapshot_date"][:4])
            y_late = int(result["latest_snapshot_date"][:4])
            span = max(0, y_late - y_early)
            result["archive_lifespan"] = f"{span} years ({y_early} to {y_late})"
        except Exception:
            pass

    # 2. Probe CDX API for interesting historical endpoints
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
            f"&output=json&limit={limit}&fl=timestamp,original,mimetype,statuscode"
        )
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp_cdx = client.get(cdx_url)
            if resp_cdx.status_code == 200:
                rows = resp_cdx.json()
                if len(rows) > 1:
                    headers = rows[0]
                    endpoints: List[Dict[str, str]] = []
                    seen_urls = set()
                    for r in rows[1:]:
                        if len(r) >= 4:
                            ts, orig_url, mime, status = r[0], r[1], r[2], r[3]
                            if orig_url in seen_urls:
                                continue
                            seen_urls.add(orig_url)
                            endpoints.append({
                                "date": parse_wayback_timestamp(ts),
                                "url": orig_url,
                                "mime": mime or "unknown",
                                "status": status or "N/A",
                                "wayback_url": f"https://web.archive.org/web/{ts}/{orig_url}",
                            })
                    result["historical_endpoints"] = endpoints
    except Exception:
        pass

    # Display findings
    if result["has_archives"]:
        log_success(f"Archived snapshots identified for [bold cyan]{domain}[/bold cyan]!")
        summary_table = {
            "Target Domain": domain,
            "Earliest Snapshot Date": result["earliest_snapshot_date"],
            "Latest Snapshot Date": result["latest_snapshot_date"],
            "Documented Lifespan": result["archive_lifespan"],
            "First Recorded Snapshot": result["earliest_snapshot_url"],
            "Recent Archive Snapshot": result["latest_snapshot_url"],
            "Interactive Archive Calendar": result["calendar_url"],
            "Historical Content Changes": result["changes_url"],
        }
        display_key_value_table("Wayback Historical Telemetry", summary_table, border_style="cyan")

        if result["historical_endpoints"]:
            log_success(f"Discovered [bold green]{len(result['historical_endpoints'])}[/bold green] historical archived endpoints!")
            ep_headers = ["Archived Date", "Original URL", "MIME / Type", "Status"]
            ep_rows = [
                [
                    ep["date"][:10],
                    ep["url"][:50] + ("..." if len(ep["url"]) > 50 else ""),
                    ep["mime"][:18],
                    ep["status"],
                ]
                for ep in result["historical_endpoints"][:15]
            ]
            display_list_table("Historical Archived Endpoints (Wayback CDX)", ep_headers, ep_rows, border_style="yellow")
    else:
        log_info(f"No publicly preserved snapshots found in the Wayback Machine for {domain}.")

    return result
