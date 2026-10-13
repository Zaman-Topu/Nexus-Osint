"""
IP Intelligence Module for NexusOSINT.
Resolves IP geolocation, ASN, network provider, reverse DNS, and classification.
"""

import ipaddress
import socket
from typing import Any, Dict
import httpx
from rich.console import Console

from nexus_osint.resolver import resolve_records, reverse_dns
from nexus_osint.ui import (
    console,
    display_key_value_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)


def is_ip(target: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def resolve_domain_to_ip(domain: str) -> str:
    """Resolve a domain name to its primary IPv4 address using Termux-safe DNS resolver."""
    clean = domain.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    records = resolve_records(clean, "A")
    if records:
        return records[0]
    records_v6 = resolve_records(clean, "AAAA")
    if records_v6:
        return records_v6[0]
    return socket.gethostbyname(clean)


def analyze_ip(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute comprehensive IP reconnaissance."""
    target = target.strip()
    original_target = target

    # Handle domain input
    if not is_ip(target):
        try:
            resolved = resolve_domain_to_ip(target)
            log_info(f"Target '{target}' resolved to IP: [bold yellow]{resolved}[/bold yellow]")
            target = resolved
        except Exception as e:
            log_error(f"Failed to resolve domain '{target}' to an IP address: {e}")
            return {"error": f"Cannot resolve {target}"}

    ip_obj = ipaddress.ip_address(target)
    print_section("IP Intelligence Scan", f"Target: {target} (v{ip_obj.version})")

    # Local classification
    classification = {
        "IP Address": str(ip_obj),
        "IP Version": f"IPv{ip_obj.version}",
        "Is Private/Internal": ip_obj.is_private,
        "Is Loopback": ip_obj.is_loopback,
        "Is Multicast": ip_obj.is_multicast,
        "Is Link-Local": ip_obj.is_link_local,
        "Is Global / Public": ip_obj.is_global,
    }

    display_key_value_table("IP Classification", classification, border_style="cyan")

    # If it is a private IP, geolocation will not yield results
    if ip_obj.is_private or ip_obj.is_loopback:
        log_warning(f"Target IP {target} is a private/loopback address. Skipping public geolocation.")
        return {
            "target": original_target,
            "ip": target,
            "classification": classification,
            "geolocation": None,
            "reverse_dns": None,
        }

    # Reverse DNS
    ptr_record = reverse_dns(target)
    if ptr_record:
        log_success(f"Reverse DNS (PTR): [bold green]{ptr_record}[/bold green]")
    else:
        log_info("Reverse DNS (PTR): No record found.")

    # Geolocation & ASN lookup via ipwho.is
    geo_info: Dict[str, Any] = {}
    try:
        url = f"https://ipwho.is/{target}"
        headers = {"User-Agent": "NexusOSINT/1.0"}
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    flag = data.get("flag", {}).get("emoji", "")
                    country = f"{flag} {data.get('country', 'N/A')} ({data.get('country_code', 'N/A')})"
                    lat = data.get("latitude")
                    lon = data.get("longitude")
                    maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "N/A"

                    conn = data.get("connection", {})
                    tz = data.get("timezone", {})

                    geo_info = {
                        "Country": country,
                        "Region / State": data.get("region", "N/A"),
                        "City": data.get("city", "N/A"),
                        "Postal Code": data.get("postal", "N/A"),
                        "Coordinates": f"{lat}, {lon}" if lat and lon else "N/A",
                        "Map Location": maps_link,
                        "ASN": f"AS{conn.get('asn', 'N/A')}",
                        "ISP": conn.get("isp", "N/A"),
                        "Organization": conn.get("org", "N/A"),
                        "Timezone": f"{tz.get('id', 'N/A')} ({tz.get('utc', 'N/A')})",
                        "Reverse DNS": ptr_record or "None",
                    }
                    display_key_value_table("Geolocation & Network Carrier", geo_info, border_style="magenta")
                else:
                    log_warning(f"Geolocation API response: {data.get('message', 'No details available')}")
            else:
                log_error(f"Geolocation lookup failed with status code: {resp.status_code}")
    except Exception as e:
        log_error(f"Network error querying geolocation API: {e}")

    return {
        "target": original_target,
        "ip": target,
        "classification": classification,
        "reverse_dns": ptr_record,
        "geolocation": geo_info,
    }
