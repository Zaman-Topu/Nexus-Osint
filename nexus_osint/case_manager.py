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
        found = data.get("found_profiles", [])
        lines.append(f" • User Handle     : {target}")
        lines.append(f" • Sites Detected  : {len(found)}")
        for p in found[:15]:
            lines.append(f"    - [{p.get('site')}]: {p.get('url')}")

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
        lines.append(f" • Target Domain   : {data.get('domain', target)}")
        dns_recs = data.get("dns", {})
        if dns_recs:
            for rtype in ("A", "AAAA", "MX", "NS"):
                vals = dns_recs.get(rtype, [])
                if vals:
                    lines.append(f" • DNS {rtype:<11} : {', '.join(str(v) for v in vals[:3])}")
        subdomains = data.get("subdomains", [])
        if subdomains:
            lines.append(f" • Subdomains Found: {len(subdomains)}")

    elif mode_lower == "email":
        lines.append(f" • Target Email    : {data.get('email', target)}")
        lines.append(f" • Format Valid    : {data.get('format_valid')}")
        lines.append(f" • Disposable/Temp : {data.get('disposable')}")
        lines.append(f" • MX Mail Server  : {data.get('mx_present')}")
        grav = data.get("gravatar", {})
        if grav.get("profile_found"):
            lines.append(f" • Gravatar Identity: {grav.get('profile_url')}")

    elif mode_lower == "phone":
        lines.append(f" • Number (E.164)  : {data.get('e164', target)}")
        lines.append(f" • Validation      : {'Valid' if data.get('valid') else 'Invalid'}")
        lines.append(f" • Geographic Region: {data.get('country')}")
        lines.append(f" • Operator/Carrier: {data.get('carrier')}")
        lines.append(f" • Timezone        : {data.get('timezone')}")

    elif mode_lower == "shodan":
        ports = data.get("ports", [])
        cves = data.get("vulnerabilities", [])
        lines.append(f" • Open Ports      : {', '.join(str(p) for p in ports) if ports else 'None reported'}")
        lines.append(f" • Vulnerabilities : {', '.join(cves) if cves else 'None reported'}")

    elif mode_lower in ("all", "dossier"):
        lines.append(f" • Seed Target     : {data.get('target_seed', target)}")
        lines.append(f" • Detected Vector : {data.get('seed_type', 'N/A').upper()}")
        completed = [k.replace('_recon', '').upper() for k, v in data.items() if k.endswith('_recon') and v is not None]
        lines.append(f" • Executed Vectors: {', '.join(completed)}")

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
