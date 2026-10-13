"""
Hudson Rock Cavalier Infostealer Intelligence Module for NexusOSINT.
Queries free zero-key Hudson Rock Cavalier threat intelligence API
for employee, corporate, and personal identity compromises via infostealer malware
(RedLine, Vidar, Raccoon, Lumma, Azorult, etc.).
"""

from typing import Any, Dict, List, Optional
import httpx

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


def query_hudson_rock_email(email: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Query Hudson Rock Cavalier API for infostealer infections related to an email."""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={email.strip()}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=HEADERS)
            if resp.status_code == 200:
                data = resp.json()
                stealers = data.get("stealers", [])
                is_compromised = len(stealers) > 0 or data.get("total_corporate_services", 0) > 0

                simplified_stealers: List[Dict[str, Any]] = []
                for s in stealers:
                    simplified_stealers.append({
                        "computer_name": s.get("computer_name", "Unknown"),
                        "operating_system": s.get("operating_system", "Unknown"),
                        "date_compromised": s.get("date_compromised", "Unknown"),
                        "malware_path": s.get("malware_path", "Unknown"),
                        "ip_mask": s.get("ip", "Unknown"),
                        "top_logins": s.get("top_logins", []),
                        "top_passwords": s.get("top_passwords", []),
                        "total_corporate": s.get("total_corporate_services", 0),
                        "total_user": s.get("total_user_services", 0),
                    })

                return {
                    "target": email,
                    "target_type": "email",
                    "compromised": is_compromised,
                    "total_stealers": len(stealers),
                    "total_corporate_services": data.get("total_corporate_services", 0),
                    "total_user_services": data.get("total_user_services", 0),
                    "message": data.get("message", ""),
                    "stealers": simplified_stealers,
                }
            elif resp.status_code == 404:
                return {
                    "target": email,
                    "target_type": "email",
                    "compromised": False,
                    "total_stealers": 0,
                    "total_corporate_services": 0,
                    "total_user_services": 0,
                    "message": "No infostealer compromise found.",
                    "stealers": [],
                }
    except Exception as e:
        return {
            "target": email,
            "target_type": "email",
            "error": str(e),
            "compromised": False,
            "stealers": [],
        }

    return {
        "target": email,
        "target_type": "email",
        "compromised": False,
        "stealers": [],
    }


def query_hudson_rock_domain(domain: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Query Hudson Rock Cavalier API for infostealer infections related to a domain."""
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain.strip()}"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=HEADERS)
            if resp.status_code == 200:
                data = resp.json()
                total = data.get("total", 0)
                employees = data.get("employees", 0)
                users = data.get("users", 0)
                stealer_families = data.get("stealerFamilies", {})
                is_compromised = total > 0 or employees > 0

                return {
                    "target": domain,
                    "target_type": "domain",
                    "compromised": is_compromised,
                    "total": total,
                    "employees": employees,
                    "users": users,
                    "third_parties": data.get("third_parties", 0),
                    "last_employee_compromised": data.get("last_employee_compromised", "N/A"),
                    "last_user_compromised": data.get("last_user_compromised", "N/A"),
                    "stealer_families": stealer_families,
                }
            elif resp.status_code == 404:
                return {
                    "target": domain,
                    "target_type": "domain",
                    "compromised": False,
                    "total": 0,
                    "employees": 0,
                    "users": 0,
                    "stealer_families": {},
                }
    except Exception as e:
        return {
            "target": domain,
            "target_type": "domain",
            "error": str(e),
            "compromised": False,
            "total": 0,
            "employees": 0,
            "users": 0,
            "stealer_families": {},
        }

    return {
        "target": domain,
        "target_type": "domain",
        "compromised": False,
        "total": 0,
        "employees": 0,
        "users": 0,
        "stealer_families": {},
    }
