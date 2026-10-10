"""
Email Intelligence Module for NexusOSINT.
Validates email addresses, detects disposable domains, checks MX/SPF/DMARC,
and pivots to Gravatar public profiles and connected social accounts.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional
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

# Common disposable / temporary email domains
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "guerrillamail.com", "guerrillamail.net",
    "guerrillamail.org", "sharklasers.com", "grr.la", "guerrillamailblock.com",
    "mailinator.com", "mailinator.net", "mailinater.com", "suremail.info",
    "temp-mail.org", "tempmail.net", "throwawaymail.com", "dispostable.com",
    "trashmail.com", "trashmail.net", "yopmail.com", "yopmail.fr", "yopmail.net",
    "getairmail.com", "mytemp.email", "mohmal.com", "inboxkitten.com",
    "burnermail.io", "maildrop.cc", "crazymailing.com", "nada.ltd", "getnada.com",
    "emailondeck.com", "fakeinbox.com", "discard.email", "spambog.com",
    "tempr.email", "discardmail.com", "generator.email", "fakemailgenerator.com",
    "trashmail.me", "dropmail.me", "mintemail.com", "harakirimail.com",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_format(email: str) -> bool:
    """Check if string conforms to standard email format."""
    return bool(EMAIL_REGEX.match(email.strip()))


def check_gravatar_profile(email: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Check Gravatar for public profiles and connected accounts."""
    clean_email = email.strip().lower()
    md5_hash = hashlib.md5(clean_email.encode("utf-8")).hexdigest()
    sha256_hash = hashlib.sha256(clean_email.encode("utf-8")).hexdigest()

    result: Dict[str, Any] = {
        "md5_hash": md5_hash,
        "sha256_hash": sha256_hash,
        "has_avatar": False,
        "avatar_url": f"https://www.gravatar.com/avatar/{md5_hash}",
        "profile_found": False,
        "profile_data": {},
        "connected_accounts": [],
    }

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/1.0"}

    # 1. Check profile JSON
    try:
        profile_url = f"https://gravatar.com/{md5_hash}.json"
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(profile_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entry", [])
                if entries:
                    entry = entries[0]
                    result["profile_found"] = True
                    result["has_avatar"] = True
                    result["profile_data"] = {
                        "Display Name": entry.get("displayName") or entry.get("name", {}).get("formatted") or "N/A",
                        "Preferred Username": entry.get("preferredUsername", "N/A"),
                        "Pronouns": entry.get("pronouns", "N/A"),
                        "Location": entry.get("currentLocation", "N/A"),
                        "Job Title": entry.get("job_title", "N/A"),
                        "Company": entry.get("company", "N/A"),
                        "About Me": entry.get("aboutMe", "N/A"),
                        "Profile URL": entry.get("profileUrl", "N/A"),
                    }

                    accounts = entry.get("accounts", [])
                    for acc in accounts:
                        result["connected_accounts"].append({
                            "platform": acc.get("name") or acc.get("shortname", "Unknown"),
                            "username": acc.get("username", "N/A"),
                            "url": acc.get("url", "N/A"),
                            "verified": acc.get("verified", False),
                        })
                    return result
    except Exception:
        pass

    # 2. Fallback: Check if avatar image exists
    try:
        avatar_check_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(avatar_check_url, headers=headers)
            if resp.status_code == 200:
                result["has_avatar"] = True
    except Exception:
        pass

    return result


def analyze_email(email: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute comprehensive email reconnaissance."""
    email = email.strip()
    print_section("Email Intelligence Scan", f"Target: {email}")

    is_valid_format = validate_email_format(email)
    if not is_valid_format:
        log_warning("Email address failed standard RFC syntax validation.")

    user_part, _, domain_part = email.partition("@")
    domain_part = domain_part.lower()

    # Disposable domain check
    is_disposable = domain_part in DISPOSABLE_DOMAINS
    if is_disposable:
        log_warning(f"Domain '{domain_part}' is flagged as a TEMPORARY/DISPOSABLE email service!")
    else:
        log_info(f"Domain '{domain_part}' is not flagged in known disposable lists.")

    # DNS MX record check
    log_info(f"Querying MX records for domain '{domain_part}'...")
    mx_records = resolve_records(domain_part, "MX")
    has_mx = len(mx_records) > 0

    if has_mx:
        log_success(f"Domain possesses {len(mx_records)} valid MX mail exchange server(s).")
    else:
        log_error(f"No MX records found for '{domain_part}'. Domain cannot receive emails!")

    # SPF and DMARC check
    txt_records = resolve_records(domain_part, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r]
    dmarc_records = resolve_records(f"_dmarc.{domain_part}", "TXT")

    summary_info = {
        "Target Email": email,
        "Valid Syntax": is_valid_format,
        "Username Component": user_part,
        "Domain Component": domain_part,
        "Is Disposable/Temp Mail": is_disposable,
        "Has Active MX Servers": has_mx,
        "SPF Record Configured": bool(spf_records),
        "DMARC Configured": bool(dmarc_records),
    }
    display_key_value_table("Email Overview", summary_info, border_style="cyan")

    if mx_records:
        display_key_value_table("Mail Servers (MX)", {f"Server #{i+1}": mx for i, mx in enumerate(mx_records)}, border_style="blue")

    # Gravatar intelligence
    log_info("Probing Gravatar for public identity and linked profiles...")
    gravatar_info = check_gravatar_profile(email, timeout=timeout)

    if gravatar_info["profile_found"]:
        log_success("Gravatar Public Profile DISCOVERED!")
        display_key_value_table("Gravatar Profile Intelligence", gravatar_info["profile_data"], border_style="magenta")

        if gravatar_info["connected_accounts"]:
            acc_headers = ["Platform", "Username", "URL", "Verified"]
            acc_rows = [
                [acc["platform"], acc["username"], acc["url"], "✓" if acc["verified"] else "-"]
                for acc in gravatar_info["connected_accounts"]
            ]
            display_list_table("Linked Social Accounts (Pivot Opportunities)", acc_headers, acc_rows, border_style="green")
    elif gravatar_info["has_avatar"]:
        log_info(f"Gravatar avatar image exists: {gravatar_info['avatar_url']}")
    else:
        log_info("No public Gravatar profile or custom avatar registered.")

    return {
        "target": email,
        "valid_format": is_valid_format,
        "is_disposable": is_disposable,
        "mx_records": mx_records,
        "spf_records": spf_records,
        "dmarc_records": dmarc_records,
        "gravatar": gravatar_info,
    }
