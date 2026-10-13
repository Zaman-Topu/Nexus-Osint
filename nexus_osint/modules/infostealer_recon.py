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


def analyze_infostealer(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    """Execute complete infostealer reconnaissance with interactive Rich UI tables."""
    target = target.strip()
    is_email = "@" in target

    if is_email:
        print_section("Hudson Rock Infostealer Intelligence", f"Target Email: {target}")
        log_info("Querying Cavalier API for infostealer malware infections...")
        res = query_hudson_rock_email(target, timeout=timeout)

        if res.get("compromised"):
            log_warning(
                f"CRITICAL BREACH: Email compromised across [bold red]{res['total_stealers']}[/bold red] "
                f"infostealer infection(s) ({res['total_corporate_services']} corporate credentials affected)!"
            )
            overview = {
                "Target Email": target,
                "Compromised Status": "YES (INFECTED)",
                "Total Infected Devices": str(res["total_stealers"]),
                "Corporate Services Leaked": str(res["total_corporate_services"]),
                "User Services Leaked": str(res["total_user_services"]),
            }
            display_key_value_table("Infostealer Threat Overview", overview, border_style="red")

            stealer_rows = []
            for s in res.get("stealers", [])[:10]:
                logins = ", ".join(s.get("top_logins", [])[:2]) or "N/A"
                stealer_rows.append([
                    s.get("computer_name", "Unknown"),
                    s.get("operating_system", "Unknown"),
                    str(s.get("date_compromised", "Unknown"))[:10],
                    s.get("malware_path", "Unknown")[:40],
                    logins,
                ])
            if stealer_rows:
                display_list_table(
                    "Compromised Host Machines (Hudson Rock)",
                    ["Host Name", "OS", "Compromised Date", "Malware Path", "Sample Leaked Logins"],
                    stealer_rows,
                    border_style="red",
                )
        else:
            if "error" in res:
                log_error(f"Error querying Hudson Rock Cavalier: {res['error']}")
            else:
                log_success("No infostealer malware compromises found for this email address.")
            display_key_value_table(
                "Infostealer Status",
                {
                    "Target Email": target,
                    "Compromised": "NO",
                    "Total Infections": "0",
                    "Threat Assessment": "Clean in Hudson Rock intelligence repository",
                },
                border_style="green",
            )
        return res

    else:
        print_section("Hudson Rock Infostealer Intelligence", f"Target Domain: {target}")
        log_info("Querying Cavalier API for corporate domain infostealer compromises...")
        res = query_hudson_rock_domain(target, timeout=timeout)

        if res.get("compromised"):
            log_warning(
                f"CRITICAL BREACH: Domain compromised in [bold red]{res['total']}[/bold red] infostealer incident(s) "
                f"({res['employees']} employee credentials, {res['users']} client logins compromised)!"
            )
            overview = {
                "Corporate Domain": target,
                "Compromised Status": "YES (COMPROMISED)",
                "Total Compromised Logins": str(res["total"]),
                "Employee Logins Compromised": str(res["employees"]),
                "User / Client Logins Compromised": str(res["users"]),
                "Third-Party Partner Breaches": str(res.get("third_parties", 0)),
                "Last Employee Compromised": res.get("last_employee_compromised", "N/A"),
                "Last User Compromised": res.get("last_user_compromised", "N/A"),
            }
            display_key_value_table("Corporate Threat Intelligence", overview, border_style="red")

            fams = res.get("stealer_families", {})
            if fams:
                fam_rows = [[k, str(v)] for k, v in sorted(fams.items(), key=lambda x: x[1] if isinstance(x[1], int) else 0, reverse=True) if k != "total"]
                if fam_rows:
                    display_list_table(
                        "Identified Malware Families",
                        ["Stealer Family", "Infection Count"],
                        fam_rows[:10],
                        border_style="red",
                    )
        else:
            if "error" in res:
                log_error(f"Error querying Hudson Rock Cavalier: {res['error']}")
            else:
                log_success("No corporate infostealer malware breaches detected for this domain.")
            display_key_value_table(
                "Infostealer Status",
                {
                    "Corporate Domain": target,
                    "Compromised": "NO",
                    "Total Credentials": "0",
                    "Threat Assessment": "Clean in Hudson Rock intelligence repository",
                },
                border_style="green",
            )
        return res
