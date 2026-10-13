"""
Case Manager & Dedicated Output Folder Handler for NexusOSINT.
Creates dedicated investigation folders per target and packages all reports into it.
"""

from datetime import datetime
import glob
import json
import os
import re
from typing import Any, Dict, List, Optional
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.tree import Tree
from rich import box

from nexus_osint.ui import console, log_info, log_success, log_warning, print_section


def get_base_results_dir() -> str:
    """Return the base results directory (centrally in project or current dir)."""
    # Prefer central project results directory if it exists, otherwise ./results
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_results = os.path.join(project_root, "results")
    if os.path.exists(project_root) and os.path.isdir(project_root):
        os.makedirs(project_results, exist_ok=True)
        return project_results

    cwd_results = os.path.join(os.getcwd(), "results")
    os.makedirs(cwd_results, exist_ok=True)
    return cwd_results


def create_target_case_folder(target: str, scan_mode: str = "scan", custom_dir: Optional[str] = None) -> str:
    """Create a unique dedicated investigation folder for the specific target and scan mode."""
    if custom_dir:
        case_path = os.path.abspath(custom_dir)
        os.makedirs(case_path, exist_ok=True)
        return case_path

    base_dir = get_base_results_dir()
    clean_target = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", target).strip("_")
    if not clean_target:
        clean_target = "target"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{clean_target}_{scan_mode}_{timestamp}"
    case_path = os.path.join(base_dir, folder_name)
    os.makedirs(case_path, exist_ok=True)
    return case_path


def generate_summary_text(target: str, scan_mode: str, data: Dict[str, Any], case_folder: str) -> str:
    """Generate concise quick-look summary text for terminal viewing."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 64,
        "  ⚡ NEXUSOSINT RECONNAISSANCE & INVESTIGATION DOSSIER",
        "=" * 64,
        f"Target Seed  : {target}",
        f"Scan Module  : {scan_mode.upper()}",
        f"Timestamp    : {now_str}",
        f"Case Folder  : {case_folder}",
        "-" * 64,
        "KEY FINDINGS SUMMARY:",
    ]

    mode_lower = scan_mode.lower()
    if mode_lower in ("ip",) or "geolocation" in data:
        lines.append(f" • Target IP       : {data.get('ip', target)}")
        geo = data.get("geolocation", {})
        if geo:
            country = geo.get("Country") or geo.get("country") or "N/A"
            city = geo.get("City") or geo.get("city") or "N/A"
            region = geo.get("Region / State") or geo.get("region") or "N/A"
            asn = geo.get("ASN") or geo.get("asn") or "N/A"
            isp = geo.get("ISP") or geo.get("isp") or "N/A"
            coords = geo.get("Coordinates") or geo.get("coordinates") or "N/A"
            lines.append(f" • Country         : {country}")
            lines.append(f" • City / Region   : {city}, {region}")
            lines.append(f" • ASN / ISP       : {asn} - {isp}")
            lines.append(f" • Coordinates     : {coords}")
            lines.append(f" • Reverse DNS     : {data.get('reverse_dns', geo.get('Reverse DNS', geo.get('reverse_dns', 'N/A')))}")

    elif mode_lower in ("user", "username"):
        found = data.get("profiles") or data.get("found_profiles") or []
        lines.append(f" • User Handle     : {data.get('username', target)}")
        lines.append(f" • Sites Detected  : {len(found)}")
        for p in found[:15]:
            site_name = p.get("Platform") or p.get("site") or p.get("name", "Site")
            site_url = p.get("Profile URL") or p.get("url", "N/A")
            lines.append(f"    - [{site_name}]: {site_url}")

    elif mode_lower == "github":
        prof = data.get("profile", {})
        lines.append(f" • GitHub Account  : {prof.get('login', target)} ({prof.get('name', 'N/A')})")
        lines.append(f" • Company / Loc   : {prof.get('company', 'N/A')} | {prof.get('location', 'N/A')}")
        lines.append(f" • Repos / Gists   : {prof.get('public_repos', 0)} repos | {prof.get('public_gists', 0)} gists")
        emails = data.get("discovered_emails", [])
        if emails:
            lines.append(f" • Leaked Emails   : {', '.join(emails)}")
        keys = data.get("public_ssh_keys", [])
        if keys:
            lines.append(f" • Public SSH Keys : {len(keys)} key(s) detected")

    elif mode_lower == "domain":
        lines.append(f" • Target Domain   : {data.get('domain') or data.get('target', target)}")
        dns_recs = data.get("dns", {})
        if dns_recs:
            for rtype in ("A", "AAAA", "MX", "NS"):
                vals = dns_recs.get(rtype, [])
                if vals:
                    lines.append(f" • DNS {rtype:<11} : {', '.join(str(v) for v in vals[:3])}")
        subdomains = data.get("subdomains", [])
        if subdomains:
            lines.append(f" • Subdomains Found: {len(subdomains)}")
        takeovers = data.get("subdomain_takeovers", [])
        vuln_takeovers = [t for t in takeovers if t.get("vulnerable")]
        if vuln_takeovers:
            lines.append(f" • ⚠️ Takeover Risk : {len(vuln_takeovers)} vulnerable subdomain(s) detected!")
        if data.get("email_security"):
            mail_sec = data["email_security"]
            lines.append(f" • Mail Security   : {mail_sec.get('posture', 'N/A')}")
        if data.get("tech_stack"):
            lines.append(f" • Web Tech Stack  : {', '.join(data['tech_stack'][:6])}")
        if data.get("favicon") and data["favicon"].get("shodan_dork"):
            lines.append(f" • Favicon Dork    : {data['favicon']['shodan_dork']}")
        if data.get("infostealer") and data["infostealer"].get("compromised"):
            lines.append(f" • ⚠️ Infostealers  : {data['infostealer'].get('total', 0)} corporate/user compromises!")

    elif mode_lower == "email":
        lines.append(f" • Target Email    : {data.get('target') or data.get('email', target)}")
        is_fmt_valid = data.get("valid_format") if "valid_format" in data else data.get("format_valid")
        lines.append(f" • Format Valid    : {'Yes' if is_fmt_valid else 'No'}")
        is_disp = data.get("is_disposable") if "is_disposable" in data else data.get("disposable")
        lines.append(f" • Disposable/Temp : {'Yes' if is_disp else 'No'}")
        mx_val = data.get("mx_records") if "mx_records" in data else data.get("mx_present")
        has_mx = bool(mx_val) if isinstance(mx_val, list) else bool(mx_val)
        lines.append(f" • MX Mail Server  : {'Active' if has_mx else 'None'}")
        grav = data.get("gravatar", {})
        if grav.get("profile_found"):
            lines.append(f" • Gravatar Identity: {grav.get('profile_url', 'Found')}")
        if data.get("email_security"):
            lines.append(f" • Spoofability    : {data['email_security'].get('posture', 'N/A')}")
        if data.get("infostealer") and data["infostealer"].get("compromised"):
            lines.append(f" • ⚠️ Infostealers  : Compromised on {data['infostealer'].get('total_stealers', 0)} device(s)!")

    elif mode_lower == "phone":
        details = data.get("details", {})
        e164_val = data.get("e164") or details.get("E.164 Format") or target
        is_valid_val = data.get("valid") if "valid" in data else details.get("Is Valid")
        geo_val = data.get("country") or details.get("Geographic Region") or "N/A"
        carrier_val = data.get("carrier") or details.get("Carrier / Operator") or "N/A"
        tz_val = data.get("timezone") or details.get("Associated Timezones") or "N/A"
        if isinstance(tz_val, list):
            tz_val = ", ".join(tz_val)
        lines.append(f" • Number (E.164)  : {e164_val}")
        lines.append(f" • Validation      : {'Valid' if is_valid_val else 'Invalid'}")
        lines.append(f" • Geographic Region: {geo_val}")
        lines.append(f" • Operator/Carrier: {carrier_val}")
        lines.append(f" • Timezone        : {tz_val}")

    elif mode_lower == "shodan":
        ports = data.get("ports", [])
        cves = data.get("vulns") or data.get("vulnerabilities", [])
        lines.append(f" • Open Ports      : {', '.join(str(p) for p in ports) if ports else 'None reported'}")
        lines.append(f" • Vulnerabilities : {', '.join(cves) if cves else 'None reported'}")

    elif mode_lower in ("exif", "image"):
        lines.append(f" • Image Target    : {data.get('target', target)}")
        lines.append(f" • EXIF Found      : {'Yes' if data.get('exif_found') else 'No'}")
        hw = data.get("hardware", {})
        if hw:
            make = str(hw.get("Camera Make", "")).replace("N/A", "").strip()
            model = str(hw.get("Camera Model", "")).replace("N/A", "").strip()
            date = str(hw.get("Date/Time Original", "N/A"))
            lines.append(f" • Camera Device   : {f'{make} {model}'.strip() or 'N/A'}")
            lines.append(f" • Timestamp       : {date}")
        gps = data.get("gps")
        if gps:
            lines.append(f" • Coordinates     : {gps.get('Latitude', 'N/A')}, {gps.get('Longitude', 'N/A')}")
            lines.append(f" • Map Link        : {gps.get('Google Maps Link', 'N/A')}")

    elif mode_lower in ("stealer", "infostealer", "cavalier"):
        lines.append(f" • Target Seed     : {data.get('target', target)}")
        lines.append(f" • Target Type     : {data.get('target_type', 'N/A').upper()}")
        lines.append(f" • Compromised     : {'YES' if data.get('compromised') else 'NO'}")
        if data.get("target_type") == "email":
            lines.append(f" • Stealer Infections: {data.get('total_stealers', 0)}")
            lines.append(f" • Corp Services   : {data.get('total_corporate_services', 0)}")
        else:
            lines.append(f" • Total Logins    : {data.get('total', 0)}")
            lines.append(f" • Employee Logins : {data.get('employees', 0)}")
            lines.append(f" • User Logins     : {data.get('users', 0)}")

    elif mode_lower in ("cloud", "buckets", "s3"):
        lines.append(f" • Company Seed    : {data.get('target', target)}")
        lines.append(f" • Total Found     : {data.get('total_discovered', 0)} storage bucket(s)")
        buckets = data.get("buckets", [])
        open_b = [b for b in buckets if "200" in b.get("Status", "")]
        if open_b:
            lines.append(f" • ⚠️ Open Buckets  : {len(open_b)} publicly accessible bucket(s)!")
        for b in buckets[:5]:
            lines.append(f"    - [{b.get('Provider')}]: {b.get('Bucket Name')} ({b.get('Status')})")

    elif mode_lower in ("urls", "otx", "history"):
        lines.append(f" • Target Domain   : {data.get('domain', target)}")
        lines.append(f" • Total Harvested : {data.get('total_found', 0)} URL(s)")
        sens = data.get("sensitive_findings", [])
        if sens:
            lines.append(f" • ⚠️ Sensitive URLs: {len(sens)} high-value endpoints detected!")
            for s in sens[:5]:
                lines.append(f"    - [{s.get('keywords')}]: {s.get('url')[:65]}")

    elif mode_lower in ("all", "dossier"):
        lines.append(f" • Seed Target     : {data.get('target_seed', target)}")
        lines.append(f" • Detected Vector : {data.get('seed_type', 'N/A').upper()}")
        completed = [k.replace('_recon', '').upper() for k, v in data.items() if k.endswith('_recon') and v is not None]
        lines.append(f" • Executed Vectors: {', '.join(completed)}")

        # Include key findings from executed sub-modules
        if data.get("domain_recon"):
            d_data = data["domain_recon"]
            subs = d_data.get("subdomains", [])
            if subs:
                lines.append(f" • Subdomains Found: {len(subs)}")
            tos = [t for t in d_data.get("subdomain_takeovers", []) if t.get("vulnerable")]
            if tos:
                lines.append(f" • ⚠️ Takeover Risks: {len(tos)} vulnerable subdomain(s) detected!")
            if d_data.get("email_security"):
                lines.append(f" • Mail Security   : {d_data['email_security'].get('posture', 'N/A')}")
            if d_data.get("tech_stack"):
                lines.append(f" • Web Tech Stack  : {', '.join(d_data['tech_stack'][:6])}")
            if d_data.get("infostealer") and d_data["infostealer"].get("compromised"):
                lines.append(f" • ⚠️ Infostealers  : {d_data['infostealer'].get('total', 0)} compromised credentials!")

        if data.get("email_recon"):
            e_data = data["email_recon"]
            if e_data.get("email_security"):
                lines.append(f" • Email Spoofing  : {e_data['email_security'].get('posture', 'N/A')}")
            if e_data.get("infostealer") and e_data["infostealer"].get("compromised"):
                lines.append(f" • ⚠️ Infostealers  : Compromised on {e_data['infostealer'].get('total_stealers', 0)} device(s)!")
            if e_data.get("gravatar", {}).get("profile_found"):
                lines.append(f" • Gravatar Profile: {e_data['gravatar'].get('profile_url', 'Found')}")

        if data.get("github_recon"):
            g_data = data["github_recon"]
            emails = g_data.get("discovered_emails", [])
            if emails:
                lines.append(f" • Leaked Commit Emails: {', '.join(emails[:3])}")

        if data.get("shodan_recon"):
            s_data = data["shodan_recon"]
            ports = s_data.get("ports", [])
            cves = s_data.get("vulns", [])
            if ports:
                lines.append(f" • Open Ports      : {', '.join(str(p) for p in ports[:6])}")
            if cves:
                lines.append(f" • ⚠️ Critical CVEs : {', '.join(cves[:4])}")

        if data.get("cloud_recon"):
            c_data = data["cloud_recon"]
            open_b = [b for b in c_data.get("buckets", []) if "200" in b.get("Status", "")]
            if open_b:
                lines.append(f" • ⚠️ Open Buckets  : {len(open_b)} publicly exposed bucket(s)!")

        if data.get("ip_recon"):
            i_data = data["ip_recon"]
            geo = i_data.get("geolocation", {})
            if geo and isinstance(geo, dict):
                country = geo.get("Country", "N/A")
                city = geo.get("City", "N/A")
                lines.append(f" • Host Geolocation: {city}, {country}")

        if data.get("exif_recon"):
            ex_data = data["exif_recon"]
            if ex_data.get("gps"):
                lines.append(f" • EXIF GPS Coords : {ex_data['gps'].get('Latitude')}, {ex_data['gps'].get('Longitude')}")

        if data.get("phone_recon"):
            ph_data = data["phone_recon"]
            lines.append(f" • Phone Country   : {ph_data.get('country', 'N/A')} ({ph_data.get('carrier', 'N/A')})")

    else:
        for k, v in list(data.items())[:8]:
            if not isinstance(v, (dict, list)):
                lines.append(f" • {k.replace('_', ' ').title():<16}: {v}")

    lines.extend([
        "-" * 64,
        "SAVED CASE ARTIFACTS:",
        " • report.md        : Comprehensive Markdown Dossier",
        " • data.json        : Structured JSON Raw Findings",
        " • summary.txt      : Quick Terminal Summary (this file)",
    ])
    if os.path.exists(os.path.join(case_folder, "visual_graph.html")):
        lines.append(" • visual_graph.html : Interactive Vis.js Network Graph")

    lines.extend([
        "=" * 64,
        "Generated by NexusOSINT Master Intelligence Engine",
    ])
    return "\n".join(lines) + "\n"


def generate_markdown_report(target: str, scan_mode: str, data: Dict[str, Any], case_folder: str) -> str:
    """Format findings dictionary into a clean, comprehensive Markdown report."""
    md_lines = [
        f"# ⚡ NexusOSINT Reconnaissance Report",
        f"",
        f"- **Target:** `{target}`",
        f"- **Scan Mode:** `{scan_mode.upper()}`",
        f"- **Generated:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
        f"- **Case Directory:** `{case_folder}`",
        f"",
        f"---",
        f"",
        f"## 📋 Executive Summary & Scan Findings",
        f"",
    ]

    for section_name, section_content in data.items():
        if not section_content:
            continue
        title = section_name.replace("_", " ").title()
        md_lines.append(f"### 🔍 {title}")
        md_lines.append("")

        if isinstance(section_content, dict):
            for k, v in section_content.items():
                if isinstance(v, list):
                    md_lines.append(f"- **{k.title()}:**")
                    if v:
                        for item in v[:50]:
                            if isinstance(item, dict):
                                md_lines.append(f"  - " + ", ".join(f"**{ik}**: {iv}" for ik, iv in item.items()))
                            else:
                                md_lines.append(f"  - {item}")
                    else:
                        md_lines.append("  - _None_")
                elif isinstance(v, dict):
                    md_lines.append(f"- **{k.title()}:**")
                    for subk, subv in v.items():
                        md_lines.append(f"  - **{subk}**: {subv}")
                else:
                    md_lines.append(f"- **{k.title()}:** {v}")
            md_lines.append("")
        elif isinstance(section_content, list):
            if section_content:
                for item in section_content[:50]:
                    if isinstance(item, dict):
                        md_lines.append(f"- " + ", ".join(f"**{ik}**: {iv}" for ik, iv in item.items()))
                    else:
                        md_lines.append(f"- {item}")
            else:
                md_lines.append("_None detected_")
            md_lines.append("")
        else:
            md_lines.append(f"- **{title}:** {section_content}")
            md_lines.append("")

    md_lines.append("---")
    md_lines.append("*Generated by NexusOSINT All-In-One Master Framework*")
    return "\n".join(md_lines) + "\n"


def save_case_files(
    case_folder: str,
    target: str,
    scan_mode: str,
    data: Dict[str, Any],
    graph_html_content: str = "",
) -> Dict[str, str]:
    """Save all artifacts into the target's dedicated case directory."""
    os.makedirs(case_folder, exist_ok=True)
    saved_files = {}

    # 1. JSON Data File
    json_path = os.path.join(case_folder, "data.json")
    payload = {
        "tool": "NexusOSINT",
        "version": "2.0.0",
        "target": target,
        "scan_mode": scan_mode,
        "timestamp": datetime.now().isoformat(),
        "case_folder": case_folder,
        "findings": data,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    saved_files["json"] = json_path

    # 2. Markdown Dossier Report
    md_path = os.path.join(case_folder, "report.md")
    md_content = generate_markdown_report(target, scan_mode, data, case_folder)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    saved_files["markdown"] = md_path

    # 3. Interactive Vis.js HTML Graph (if provided)
    if graph_html_content:
        html_path = os.path.join(case_folder, "visual_graph.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(graph_html_content)
        saved_files["graph"] = html_path

    # 4. Summary Text file for quick terminal cat
    txt_path = os.path.join(case_folder, "summary.txt")
    txt_content = generate_summary_text(target, scan_mode, data, case_folder)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(txt_content)
    saved_files["summary"] = txt_path

    return saved_files


def print_case_banner(case_folder: str, saved_files: Dict[str, str], target: str, scan_mode: str) -> None:
    """Print an aesthetic Rich summary panel and file tree for the newly created case folder."""
    console.print()
    console.print(Panel(
        f"[bold green]✔ Investigation Completed & Case Folder Created![/bold green]\n"
        f"[bold white]Target:[/] [yellow]{target}[/] | [bold white]Mode:[/] [cyan]{scan_mode.upper()}[/]\n"
        f"[bold white]Directory:[/] [bold underline cyan]file://{case_folder}[/bold underline cyan]",
        box=box.ROUNDED,
        border_style="green",
        title="[bold yellow]📁 TARGET INVESTIGATION FOLDER[/bold yellow]",
    ))

    tree = Tree(f"[bold cyan]{os.path.basename(case_folder)}/[/bold cyan]")
    if "markdown" in saved_files:
        tree.add(f"[bold white]📄 report.md[/bold white] [dim]- Comprehensive Markdown Report[/dim]")
    if "json" in saved_files:
        tree.add(f"[bold white]🗃️ data.json[/bold white] [dim]- Complete Structured Findings (JSON)[/dim]")
    if "summary" in saved_files:
        tree.add(f"[bold white]📝 summary.txt[/bold white] [dim]- Quick Terminal Overview[/dim]")
    if "graph" in saved_files:
        tree.add(f"[bold yellow]🌐 visual_graph.html[/bold yellow] [bold cyan][Open in Browser][/bold cyan] [dim]- Interactive Network Graph[/dim]")

    console.print(tree)
    console.print(f"\n[dim cyan]💡 Quick View:[/] [white]cat {os.path.join(case_folder, 'summary.txt')}[/white]")
    if "graph" in saved_files:
        console.print(f"[dim cyan]💡 Graph View:[/] Open in browser: [white]file://{saved_files['graph']}[/white]\n")


def list_saved_cases() -> List[Dict[str, Any]]:
    """Scan and return all investigation case folders inside results directory."""
    base_dir = get_base_results_dir()
    if not os.path.exists(base_dir):
        return []

    entries = []
    for item in sorted(os.listdir(base_dir), reverse=True):
        full_path = os.path.join(base_dir, item)
        if os.path.isdir(full_path):
            files = os.listdir(full_path)
            stat = os.stat(full_path)
            # Try to read data.json if available
            target = "Unknown"
            scan_mode = "Unknown"
            json_file = os.path.join(full_path, "data.json")
            if os.path.exists(json_file):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                        target = meta.get("target", target)
                        scan_mode = meta.get("scan_mode", scan_mode)
                except Exception:
                    pass

            entries.append({
                "folder_name": item,
                "path": full_path,
                "target": target,
                "scan_mode": scan_mode,
                "created_time": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "file_count": len(files),
                "has_graph": "visual_graph.html" in files,
            })
    return entries


def display_cases_table() -> None:
    """Print a clean Rich table of all past case investigation folders."""
    cases = list_saved_cases()
    if not cases:
        log_warning("No saved case investigation folders found in results/ yet.")
        return

    table = Table(
        title=f"Saved Target Case Folders ({len(cases)} cases)",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
    )
    table.add_column("#", style="bold cyan", width=4)
    table.add_column("Case Folder", style="bold white")
    table.add_column("Target", style="yellow")
    table.add_column("Mode", style="cyan")
    table.add_column("Date", style="dim")
    table.add_column("Artifacts", style="green")

    for idx, c in enumerate(cases[:25], 1):
        graph_badge = " [bold yellow][GRAPH][/bold yellow]" if c["has_graph"] else ""
        artifacts = f"{c['file_count']} files{graph_badge}"
        table.add_row(
            str(idx),
            c["folder_name"],
            str(c["target"]),
            str(c["scan_mode"].upper()),
            c["created_time"],
            artifacts,
        )

    console.print(table)


def view_cases_interactive_menu() -> None:
    """Interactive browser for past target cases."""
    cases = list_saved_cases()
    if not cases:
        log_warning("No saved investigation case folders found yet in results/.")
        return

    display_cases_table()
    choice = Prompt.ask("\nEnter case number to inspect, or 0 to return", default="0")
    if choice.isdigit() and 1 <= int(choice) <= len(cases[:25]):
        selected = cases[int(choice) - 1]
        folder = selected["path"]
        console.print()
        console.rule(f"[bold green]Case: {selected['folder_name']}[/bold green]")
        console.print(f"Directory: [bold underline cyan]file://{folder}[/bold underline cyan]\n")

        summary_file = os.path.join(folder, "summary.txt")
        report_file = os.path.join(folder, "report.md")
        graph_file = os.path.join(folder, "visual_graph.html")

        if os.path.exists(summary_file):
            with open(summary_file, "r", encoding="utf-8") as f:
                console.print(f.read())
        elif os.path.exists(report_file):
            with open(report_file, "r", encoding="utf-8") as f:
                console.print(f.read())

        if os.path.exists(graph_file):
            console.print(f"\n[bold yellow]🌐 HTML Graph Available:[/] file://{graph_file}")
        console.rule()
