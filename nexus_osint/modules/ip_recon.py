"""
IP Intelligence Module for NexusOSINT.
Resolves IP geolocation, ASN, network routing, BGP prefix, reverse DNS,
live service listeners, Shodan InternetDB telemetry, Tor anonymity, and diagnostic audit status.
"""

import ipaddress
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
import httpx

from nexus_osint.resolver import resolve_records, reverse_dns
from nexus_osint.ui import (
    console,
    display_audit_matrix,
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
    try:
        return socket.gethostbyname(clean)
    except Exception as e:
        raise ValueError(f"Could not resolve domain '{clean}' to an IP address: {e}")


def check_port_listener(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Test if a specific port is actively listening and retrieve banner if available."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        if res == 0:
            banner = ""
            if port == 80:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    raw = s.recv(512).decode("utf-8", errors="replace")
                    for line in raw.splitlines():
                        if line.lower().startswith("server:"):
                            banner = line.split(":", 1)[1].strip()
                            break
                        if line.startswith("HTTP/"):
                            banner = line.strip()
                except Exception:
                    pass
            s.close()
            return {"open": True, "status": "OPEN", "banner": banner or "Connection Accepted"}
        s.close()
        return {"open": False, "status": "CLOSED", "banner": "Port closed or refused"}
    except socket.timeout:
        return {"open": False, "status": "TIMEOUT", "banner": "Connection timed out"}
    except Exception as e:
        return {"open": False, "status": "FAILED", "banner": str(e)}


def check_tls_listener(ip: str, port: int = 443, timeout: float = 2.5) -> Dict[str, Any]:
    """Test if TLS is listening on port and extract basic certificate telemetry."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                return {
                    "open": True,
                    "status": "TLS_ESTABLISHED",
                    "version": version or "TLS",
                    "cipher": cipher[0] if cipher else "Unknown",
                    "detail": f"{version} ({cipher[0] if cipher else 'Active'})",
                }
    except socket.timeout:
        return {"open": False, "status": "TIMEOUT", "detail": "TLS handshake timed out"}
    except ConnectionRefusedError:
        return {"open": False, "status": "CLOSED", "detail": "Port 443 connection refused"}
    except Exception as e:
        return {"open": False, "status": "NO_TLS", "detail": str(e)[:60]}


def check_tor_exit_node(ip: str) -> Dict[str, Any]:
    """Check if IP is an active Tor exit node using official DNSEL."""
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            rev_ip = ".".join(reversed(parts))
            query_host = f"{rev_ip}.dnsel.torproject.org"
            ans = resolve_records(query_host, "A")
            if any("127.0.0.2" in a for a in ans):
                return {"is_tor": True, "status": "TOR_EXIT_NODE", "detail": "Identified as active Tor exit router"}
    except Exception:
        pass
    return {"is_tor": False, "status": "CLEAN", "detail": "Not listed in Tor exit directory"}


def check_bgp_prefix(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Query RIPE Stat for BGP prefix, routing announcement, and ASN holder."""
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
    headers = {
        "User-Agent": "NexusOSINT/2.0",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                raw_json = resp.json()
                data = raw_json.get("data", {})
                asns = data.get("asns", [])
                asn_str = ", ".join(f"AS{a.get('asn')} ({a.get('holder', 'N/A')})" for a in asns) if asns else "N/A"
                prefix = data.get("resource") or "N/A"
                if prefix == "N/A" and "messages" in raw_json:
                    for msg in raw_json.get("messages", []):
                        if len(msg) > 1 and "less-specific" in str(msg[1]):
                            m = re.search(r"\(([\d\.\/]+)\)", str(msg[1]))
                            if m:
                                prefix = m.group(1)
                                break
                return {
                    "prefix": prefix,
                    "announced": data.get("announced", True if prefix != "N/A" else False),
                    "asns": asn_str,
                    "status": "SUCCESS",
                }
    except Exception as e:
        return {"prefix": "N/A", "announced": False, "asns": "N/A", "status": f"FAILED ({e})"}
    return {"prefix": "N/A", "announced": False, "asns": "N/A", "status": "NO_DATA"}


def check_shodan_telemetry(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
    """Query unauthenticated Shodan InternetDB for open ports and known CVEs."""
    url = f"https://internetdb.shodan.io/{ip}"
    headers = {
        "User-Agent": "NexusOSINT/2.0",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                cpes = data.get("cpes", [])
                hostnames = data.get("hostnames", [])
                tags = data.get("tags", [])
                return {
                    "status": "SUCCESS",
                    "ports": ports,
                    "vulns": vulns,
                    "cpes": cpes,
                    "hostnames": hostnames,
                    "tags": tags,
                    "exposed": bool(ports or vulns),
                    "detail": f"{len(ports)} open port(s), {len(vulns)} CVE(s)",
                }
            elif resp.status_code == 404:
                return {
                    "status": "CLEAN",
                    "ports": [],
                    "vulns": [],
                    "cpes": [],
                    "hostnames": [],
                    "tags": [],
                    "exposed": False,
                    "detail": "0 open ports or CVEs indexed in Shodan InternetDB",
                }
    except Exception as e:
        return {"status": f"FAILED", "ports": [], "vulns": [], "exposed": False, "detail": str(e)}
    return {"status": "NO_DATA", "ports": [], "vulns": [], "exposed": False, "detail": "No response"}


def analyze_ip(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute comprehensive IP reconnaissance with full diagnostic audit."""
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

    diagnostic_audit: List[Dict[str, str]] = []

    # 1. Local classification
    classification = {
        "IP Address": str(ip_obj),
        "IP Version": f"IPv{ip_obj.version}",
        "Is Private/Internal": ip_obj.is_private,
        "Is Loopback": ip_obj.is_loopback,
        "Is Multicast": ip_obj.is_multicast,
        "Is Link-Local": ip_obj.is_link_local,
        "Is Global / Public": ip_obj.is_global,
        "CIDR Representation": f"{ip_obj}/32" if ip_obj.version == 4 else f"{ip_obj}/128",
        "Reverse Pointer": getattr(ip_obj, "reverse_pointer", "N/A"),
    }
    diagnostic_audit.append({
        "probe": "IP Classification",
        "target": target,
        "status": "SUCCESS",
        "detail": f"IPv{ip_obj.version} - {'Public / Global' if ip_obj.is_global else 'Private / Local'}",
    })
    display_key_value_table("IP Classification & Addressing", classification, border_style="cyan")

    # If it is a private IP, skip public lookups
    if ip_obj.is_private or ip_obj.is_loopback:
        log_warning(f"Target IP {target} is a private/loopback address. Skipping public geolocation.")
        diagnostic_audit.append({
            "probe": "Public Geolocation",
            "target": target,
            "status": "CLEAN",
            "detail": "Private/Loopback range - not routable on public Internet",
        })
        display_audit_matrix("Diagnostic Probe & Audit Matrix", diagnostic_audit)
        return {
            "target": original_target,
            "ip": target,
            "classification": classification,
            "geolocation": None,
            "reverse_dns": None,
            "bgp_routing": None,
            "shodan_telemetry": None,
            "live_probes": None,
            "tor_anonymity": None,
            "diagnostic_audit": diagnostic_audit,
        }

    # 2. Reverse DNS (PTR)
    ptr_record = reverse_dns(target)
    if ptr_record:
        log_success(f"Reverse DNS (PTR): [bold green]{ptr_record}[/bold green]")
        diagnostic_audit.append({
            "probe": "Reverse DNS (PTR)",
            "target": target,
            "status": "SUCCESS",
            "detail": f"Domain resolved: {ptr_record}",
        })
    else:
        log_info("Reverse DNS (PTR): No record found.")
        diagnostic_audit.append({
            "probe": "Reverse DNS (PTR)",
            "target": target,
            "status": "NO_RECORD",
            "detail": "No PTR reverse record configured by ISP/carrier",
        })

    # 3. Geolocation & ASN lookup via ipwho.is (with ip-api fallback)
    geo_info: Dict[str, Any] = {}
    geo_status = "FAILED"
    geo_detail = "Failed to query public geolocation API"
    try:
        url = f"https://ipwho.is/{target}"
        headers = {
            "User-Agent": "NexusOSINT/2.0",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }
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
                        "Reverse DNS": ptr_record or "None (No PTR record)",
                    }
                    geo_status = "SUCCESS"
                    geo_detail = f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')} ({conn.get('isp', 'N/A')})"
                    display_key_value_table("Geolocation & Network Carrier", geo_info, border_style="magenta")
                else:
                    log_warning(f"ipwho.is notice: {data.get('message', 'No details available')}")
    except Exception as e:
        log_warning(f"ipwho.is error ({e}), attempting fallback API...")

    # Fallback to ip-api if ipwho.is was empty
    if not geo_info:
        try:
            fb_url = f"http://ip-api.com/json/{target}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            with httpx.Client(timeout=timeout) as client:
                fb_resp = client.get(fb_url)
                if fb_resp.status_code == 200:
                    fb_data = fb_resp.json()
                    if fb_data.get("status") == "success":
                        lat = fb_data.get("lat")
                        lon = fb_data.get("lon")
                        maps_link = f"https://www.google.com/maps?q={lat},{lon}" if lat and lon else "N/A"
                        geo_info = {
                            "Country": f"{fb_data.get('country', 'N/A')} ({fb_data.get('countryCode', 'N/A')})",
                            "Region / State": fb_data.get("regionName", "N/A"),
                            "City": fb_data.get("city", "N/A"),
                            "Postal Code": fb_data.get("zip", "N/A"),
                            "Coordinates": f"{lat}, {lon}" if lat and lon else "N/A",
                            "Map Location": maps_link,
                            "ASN": fb_data.get("as", "N/A"),
                            "ISP": fb_data.get("isp", "N/A"),
                            "Organization": fb_data.get("org", "N/A"),
                            "Timezone": fb_data.get("timezone", "N/A"),
                            "Reverse DNS": ptr_record or "None (No PTR record)",
                        }
                        geo_status = "SUCCESS"
                        geo_detail = f"{fb_data.get('city')}, {fb_data.get('country')} via ip-api"
                        display_key_value_table("Geolocation & Network Carrier (Fallback)", geo_info, border_style="magenta")
        except Exception as e:
            geo_detail = f"All geolocation endpoints failed: {e}"

    diagnostic_audit.append({
        "probe": "Geolocation & Carrier",
        "target": target,
        "status": geo_status,
        "detail": geo_detail,
    })

    # 4. BGP Routing & Prefix Intelligence (RIPE Stat)
    log_info("Auditing global BGP prefix routing and Autonomous System allocation...")
    bgp_data = check_bgp_prefix(target, timeout=timeout)
    bgp_display = {
        "Announced BGP Prefix": bgp_data.get("prefix", "N/A"),
        "Routing Status": "Active / Announced" if bgp_data.get("announced") else "Not directly announced",
        "Origin ASNs & Holder": bgp_data.get("asns", "N/A"),
    }
    display_key_value_table("BGP Routing & Global Prefix", bgp_display, border_style="blue")
    diagnostic_audit.append({
        "probe": "BGP Routing & Prefix",
        "target": target,
        "status": "SUCCESS" if bgp_data.get("prefix") != "N/A" else "NO_RECORD",
        "detail": f"Prefix {bgp_data.get('prefix')} - {bgp_data.get('asns')[:45]}",
    })

    # 5. Shodan InternetDB Open Port & CVE Telemetry
    log_info("Querying Shodan InternetDB for open ports & known vulnerabilities...")
    shodan_data = check_shodan_telemetry(target, timeout=timeout)
    sho_display = {
        "Indexed Status": shodan_data.get("status", "N/A"),
        "Open Ports": shodan_data.get("ports") or "None reported (Clean)",
        "Known CVEs": shodan_data.get("vulns") or "None reported (Clean)",
        "CPE Identifiers": shodan_data.get("cpes") or "None",
        "Hostnames": shodan_data.get("hostnames") or "None",
        "Infrastructure Tags": shodan_data.get("tags") or "None",
    }
    display_key_value_table("Shodan InternetDB Security Telemetry", sho_display, border_style="red" if shodan_data.get("exposed") else "green")
    diagnostic_audit.append({
        "probe": "Shodan InternetDB",
        "target": target,
        "status": "EXPOSED" if shodan_data.get("exposed") else shodan_data.get("status", "CLEAN"),
        "detail": shodan_data.get("detail", "0 open ports indexed"),
    })

    # 6. Live Port & Protocol Service Probes (Ports 80 & 443)
    log_info("Probing live service listeners on port 80 (HTTP) and port 443 (HTTPS/TLS)...")
    p80 = check_port_listener(target, 80, timeout=2.0)
    p443 = check_tls_listener(target, 443, timeout=2.5)
    live_probes = {
        "Port 80 (HTTP)": p80,
        "Port 443 (HTTPS)": p443,
    }
    live_display = {
        "Port 80 (HTTP Web)": f"[{'bold green' if p80['open'] else 'dim red'}]{p80['status']}[/] ({p80['banner']})",
        "Port 443 (HTTPS TLS)": f"[{'bold green' if p443['open'] else 'dim red'}]{p443['status']}[/] ({p443['detail']})",
    }
    display_key_value_table("Live Service & Port Listeners", live_display, border_style="yellow")

    diagnostic_audit.append({
        "probe": "HTTP Listener (Port 80)",
        "target": f"{target}:80",
        "status": "LISTENING" if p80["open"] else p80["status"],
        "detail": p80["banner"],
    })
    diagnostic_audit.append({
        "probe": "HTTPS / TLS (Port 443)",
        "target": f"{target}:443",
        "status": "LISTENING" if p443["open"] else p443["status"],
        "detail": p443["detail"],
    })

    # 7. Tor Exit Node & Anonymity Verification
    tor_data = check_tor_exit_node(target)
    diagnostic_audit.append({
        "probe": "Tor Exit Node Check",
        "target": target,
        "status": "ANONYMOUS" if tor_data["is_tor"] else "CLEAN",
        "detail": tor_data["detail"],
    })

    # 8. Render Comprehensive Diagnostic Audit Matrix
    display_audit_matrix("Reconnaissance Diagnostic & Health Audit Matrix", diagnostic_audit)

    return {
        "target": original_target,
        "ip": target,
        "classification": classification,
        "reverse_dns": ptr_record,
        "geolocation": geo_info,
        "bgp_routing": bgp_data,
        "shodan_telemetry": shodan_data,
        "live_probes": live_probes,
        "tor_anonymity": tor_data,
        "diagnostic_audit": diagnostic_audit,
    }
