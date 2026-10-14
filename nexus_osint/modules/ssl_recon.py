"""
SSL/TLS Deep Certificate Forensics & SAN Domain Pivoting Module for NexusOSINT.
Inspects X.509 certificate chains, discovers Subject Alternative Names (SAN) sibling domains,
evaluates cipher suites, expiration timelines, and detects self-signed/expired anomalies.
"""

from datetime import datetime
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
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


def parse_host_port(target: str) -> Tuple[str, int]:
    """Extract host and port from target string."""
    clean = target.strip().lower()
    clean = re.sub(r"^https?://", "", clean)
    clean = clean.split("/")[0]

    if ":" in clean:
        parts = clean.split(":")
        host = parts[0]
        port = int(parts[1]) if parts[1].isdigit() else 443
    else:
        host = clean
        port = 443

    return host, port


def parse_ssl_date(date_str: str) -> Optional[datetime]:
    """Parse standard OpenSSL ASN1 date string (e.g. 'Oct 14 01:09:41 2026 GMT')."""
    if not date_str:
        return None
    try:
        # Format: 'May 15 12:00:00 2024 GMT'
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except Exception:
        try:
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
        except Exception:
            return None


def analyze_ssl(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Perform deep SSL/TLS certificate reconnaissance and SAN domain pivoting.
    """
    host, port = parse_host_port(target)
    print_section("SSL/TLS Deep Certificate Forensics", f"Target: {host}:{port}")

    log_info(f"Initiating direct TLS handshake with {host}:{port}...")

    cert_data: Dict[str, Any] = {}
    cipher_info = ()
    tls_version = "Unknown"
    is_valid_chain = True
    error_msg = ""

    # 1. Try standard verifying context
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_data = ssock.getpeercert() or {}
                cipher_info = ssock.cipher() or ()
                tls_version = ssock.version() or "Unknown"
    except ssl.SSLCertVerificationError as e:
        is_valid_chain = False
        error_msg = f"Certificate Verification Warning: {e.verify_message}"
        log_warning(error_msg)

        # Fallback to unverified context to still harvest the certificate details
        try:
            unverified_ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_data = ssock.getpeercert(binary_form=False) or {}
                    cipher_info = ssock.cipher() or ()
                    tls_version = ssock.version() or "Unknown"
        except Exception as fallback_err:
            log_error(f"Failed establishing TLS handshake: {fallback_err}")
            return {"target": host, "port": port, "error": str(fallback_err), "connected": False}

    except Exception as e:
        log_error(f"Cannot connect to {host}:{port}: {e}")
        return {"target": host, "port": port, "error": str(e), "connected": False}

    # Parse Subject fields
    subject_dict = {}
    for rdn in cert_data.get("subject", ()):
        for k, v in rdn:
            subject_dict[k] = v

    # Parse Issuer fields
    issuer_dict = {}
    for rdn in cert_data.get("issuer", ()):
        for k, v in rdn:
            issuer_dict[k] = v

    subject_cn = subject_dict.get("commonName", "N/A")
    subject_org = subject_dict.get("organizationName", "N/A")
    subject_country = subject_dict.get("countryName", "N/A")

    issuer_cn = issuer_dict.get("commonName", "N/A")
    issuer_org = issuer_dict.get("organizationName", "N/A")

    # Subject Alternative Names (SAN)
    san_list: List[str] = []
    for item in cert_data.get("subjectAltName", ()):
        if len(item) == 2 and item[0] == "DNS":
            san_list.append(item[1])

    # Validity Period
    not_before_str = cert_data.get("notBefore", "")
    not_after_str = cert_data.get("notAfter", "")
    not_before_dt = parse_ssl_date(not_before_str)
    not_after_dt = parse_ssl_date(not_after_str)

    is_expired = False
    days_left = 0
    now = datetime.now()

    if not_after_dt:
        days_left = (not_after_dt - now).days
        is_expired = days_left < 0

    is_self_signed = (subject_cn != "N/A" and subject_cn == issuer_cn) or (
        subject_org != "N/A" and subject_org == issuer_org and "CA" not in issuer_cn
    )
    is_wildcard = any(name.startswith("*.") for name in san_list) or subject_cn.startswith("*.")

    cipher_name = cipher_info[0] if len(cipher_info) > 0 else "Unknown"
    cipher_bits = cipher_info[2] if len(cipher_info) > 2 else "Unknown"

    log_success(f"TLS handshake established ([bold cyan]{tls_version}[/bold cyan] / {cipher_name})")

    # Display Certificate Overview
    cert_table = {
        "Target Host:Port": f"{host}:{port}",
        "Subject Common Name (CN)": subject_cn,
        "Subject Organization": subject_org,
        "Subject Country": subject_country,
        "Issuer Authority (CA)": f"{issuer_cn} ({issuer_org})",
        "Issued On (Not Before)": not_before_str,
        "Expires On (Not After)": not_after_str,
        "Validity Posture": f"EXPIRED ({abs(days_left)} days ago)" if is_expired else f"VALID ({days_left} days remaining)",
        "Self-Signed Cert": "YES (Untrusted / Internal)" if is_self_signed else "No (Signed by CA)",
        "Wildcard Certificate": "Yes (*.domain)" if is_wildcard else "No (Specific FQDN)",
        "TLS Protocol Version": tls_version,
        "Negotiated Cipher": f"{cipher_name} ({cipher_bits}-bit)",
        "Chain Verification": "Trusted / Valid" if is_valid_chain else f"Warning ({error_msg})",
    }
    display_key_value_table("X.509 Certificate Telemetry", cert_table, border_style="cyan")

    # Display Subject Alternative Names (SAN)
    if san_list:
        log_success(f"Discovered [bold green]{len(san_list)}[/bold green] Subject Alternative Name (SAN) domain(s)!")
        san_headers = ["Index", "Discovered Domain / Sibling Infrastructure", "Type"]
        san_rows = [
            [
                str(i + 1),
                name,
                "Wildcard Scope" if name.startswith("*.") else "Direct Hostname",
            ]
            for i, name in enumerate(san_list)
        ]
        display_list_table("Subject Alternative Names (SAN Infrastructure Pivot)", san_headers, san_rows, border_style="green")
    else:
        log_info("No Subject Alternative Names (SAN) recorded on this certificate.")

    return {
        "host": host,
        "port": port,
        "connected": True,
        "subject_cn": subject_cn,
        "subject_org": subject_org,
        "issuer_cn": issuer_cn,
        "issuer_org": issuer_org,
        "san_domains": san_list,
        "not_before": not_before_str,
        "not_after": not_after_str,
        "days_remaining": days_left,
        "is_expired": is_expired,
        "is_self_signed": is_self_signed,
        "is_wildcard": is_wildcard,
        "tls_version": tls_version,
        "cipher_suite": cipher_name,
        "is_valid_chain": is_valid_chain,
    }
