"""
Shodan InternetDB Reconnaissance Module for NexusOSINT.
Queries the Shodan InternetDB API for open ports, hostnames, CPEs, and known CVE vulnerabilities.
Requires zero API keys.
"""

import ipaddress
import socket
from typing import Any, Dict, List
import httpx

from nexus_osint.resolver import resolve_records
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


def resolve_to_ip(target: str) -> str:
    """Resolve a domain or host to an IP address using Termux-safe DNS resolver."""
    clean = target.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        records = resolve_records(clean, "A")
        if records:
            return records[0]
        records_v6 = resolve_records(clean, "AAAA")
        if records_v6:
            return records_v6[0]
        try:
            return socket.gethostbyname(clean)
        except Exception as e:
            raise ValueError(f"Could not resolve host '{clean}' to an IP address: {e}")


def query_shodan_internetdb(ip: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Query the free Shodan InternetDB endpoint."""
    url = f"https://internetdb.shodan.io/{ip}"
    headers = {"User-Agent": "NexusOSINT/1.0"}
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    except Exception as e:
        return {"error": str(e)}
    return {}


def analyze_shodan(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute passive Shodan network & vulnerability scan."""
    print_section("Shodan Threat & Port Intelligence", f"Target: {target}")

    try:
        ip = resolve_to_ip(target)
        if ip != target:
            log_info(f"Target '{target}' resolved to IP: [bold yellow]{ip}[/bold yellow]")
    except Exception as e:
        log_error(f"Failed to resolve target to an IP address: {e}")
        return {"error": str(e), "target": target}

    log_info(f"Querying Shodan InternetDB for IP: {ip}...")
    data = query_shodan_internetdb(ip, timeout=timeout)

    if "error" in data:
        log_error(f"Error querying Shodan InternetDB: {data['error']}")
        return {"target": target, "ip": ip, "error": data["error"]}

    ports = data.get("ports", [])
    vulns = data.get("vulns", [])
    cpes = data.get("cpes", [])
    hostnames = data.get("hostnames", [])
    tags = data.get("tags", [])

    overview = {
        "Target IP": ip,
        "Total Open Ports": len(ports),
        "Total CVEs Found": len(vulns),
        "Associated Hostnames": hostnames if hostnames else ["None reported"],
        "Detected Tags": tags if tags else ["None reported"],
    }
    display_key_value_table("Shodan Network Profile", overview, border_style="cyan")

    # Display open ports
    if ports:
        log_success(f"Discovered [bold green]{len(ports)}[/bold green] exposed port(s): {', '.join(str(p) for p in sorted(ports))}")
        port_rows = []
        for p in sorted(ports):
            common_service = "Custom / Unknown"
            service_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
                993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
                3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
                8443: "HTTPS-Alt", 27017: "MongoDB"
            }
            common_service = service_map.get(p, "Standard Service")
            port_rows.append([str(p), common_service])
        display_list_table("Exposed Ports", ["Port", "Likely Service"], port_rows, border_style="blue")
    else:
        log_info("No open ports found in Shodan InternetDB.")

    # Display vulnerabilities
    if vulns:
        log_warning(f"CRITICAL: Found [bold red]{len(vulns)}[/bold red] known CVE vulnerability/vulnerabilities!")
        vuln_rows = [[v, f"https://nvd.nist.gov/vuln/detail/{v}"] for v in sorted(vulns)]
        display_list_table("Detected Vulnerabilities (CVEs)", ["CVE Identifier", "Advisory Link"], vuln_rows, border_style="red")
    else:
        log_success("No unpatched CVEs indexed by Shodan InternetDB.")

    if cpes:
        display_list_table("Detected Software (CPEs)", ["CPE ID"], [[c] for c in cpes], border_style="magenta")

    return {
        "target": target,
        "ip": ip,
        "ports": ports,
        "vulns": vulns,
        "cpes": cpes,
        "hostnames": hostnames,
        "tags": tags,
    }
