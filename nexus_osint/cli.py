"""
Unified Command-Line Interface and Interactive Menu System for NexusOSINT.
All-In-One Master Intelligence Framework.
Supports commands like:
  nexusosint all <target>
  nexusosint ip <ip>
  nexusosint domain <domain>
  nexusosint user <username>
  ... and automatically generates a dedicated investigation folder with all findings.
"""

import argparse
import os
import sys
from typing import Any, Dict, Optional
from rich.prompt import Confirm, Prompt

from nexus_osint.case_manager import (
    create_target_case_folder,
    print_case_banner,
    save_case_files,
    view_cases_interactive_menu,
)
from nexus_osint.modules.cloud_recon import analyze_cloud_buckets
from nexus_osint.modules.domain_recon import analyze_domain
from nexus_osint.modules.dossier import run_master_dossier
from nexus_osint.modules.email_recon import analyze_email
from nexus_osint.modules.exif_recon import analyze_image_exif
from nexus_osint.modules.github_recon import analyze_github
from nexus_osint.modules.ip_recon import analyze_ip
from nexus_osint.modules.passive_urls import analyze_passive_urls
from nexus_osint.modules.phone_recon import analyze_phone
from nexus_osint.modules.shodan_recon import analyze_shodan
from nexus_osint.modules.username_recon import analyze_username
from nexus_osint.ui import (
    console,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_banner,
    print_section,
)


def run_and_save_scan(
    scan_mode: str,
    target: str,
    timeout: float = 6.0,
    concurrency: int = 15,
    output_dir: Optional[str] = None,
    save_folder: bool = True,
) -> Dict[str, Any]:
    """Execute a scan module and automatically create a dedicated case folder."""
    data: Dict[str, Any] = {}

    mode_lower = scan_mode.lower()
    if mode_lower in ("all", "dossier", "full"):
        return run_master_dossier(
            target_seed=target,
            timeout=timeout,
            concurrency=concurrency,
            output_dir=output_dir,
            save_folder=save_folder,
        )

    elif mode_lower in ("ip",):
        data = analyze_ip(target, timeout=timeout)

    elif mode_lower in ("domain", "dns"):
        data = analyze_domain(target, timeout=timeout)

    elif mode_lower in ("user", "username"):
        data = analyze_username(target, timeout=timeout, concurrency=concurrency)

    elif mode_lower in ("email", "mail"):
        data = analyze_email(target, timeout=timeout)

    elif mode_lower in ("phone", "tel"):
        data = analyze_phone(target)

    elif mode_lower in ("github", "git"):
        data = analyze_github(target, timeout=timeout)

    elif mode_lower in ("shodan", "ports"):
        data = analyze_shodan(target, timeout=timeout)

    elif mode_lower in ("cloud", "buckets", "s3"):
        data = analyze_cloud_buckets(target, concurrency=concurrency)

    elif mode_lower in ("urls", "otx", "history"):
        data = analyze_passive_urls(target, timeout=timeout)

    elif mode_lower in ("exif", "image", "gps"):
        data = analyze_image_exif(target, timeout=timeout)

    else:
        log_error(f"Unknown scan module: {scan_mode}")
        return {}

    # Automatically save into dedicated investigation case folder
    if save_folder and data:
        case_folder = create_target_case_folder(target, scan_mode=scan_mode, custom_dir=output_dir)
        saved_files = save_case_files(case_folder, target, scan_mode, data)
        print_case_banner(case_folder, saved_files, target, scan_mode)

    return data


def interactive_menu(timeout: float = 6.0, concurrency: int = 15) -> None:
    """Run master interactive terminal menu."""
    while True:
        print_banner()
        console.print("[bold yellow]MASTER OSINT SUITE / CAPABILITY SELECTOR[/bold yellow]")
        console.print("  [bold red][1][/bold red] 🎯 [bold red]ALL / MASTER DOSSIER[/bold red]   [dim](Autonomous Chained Multi-Vector Scan + Graph)[/dim]")
        console.print("  [bold cyan][2][/bold cyan] 👤 [white]Username Intelligence[/white]   [dim](Scan 50+ platforms & social media)[/dim]")
        console.print("  [bold cyan][3][/bold cyan] 🐙 [white]GitHub Deep Recon[/white]       [dim](Profile, public SSH keys & commit author emails)[/dim]")
        console.print("  [bold cyan][4][/bold cyan] 🌐 [white]Domain Reconnaissance[/white]   [dim](DNS, RDAP, subdomains, security headers)[/dim]")
        console.print("  [bold cyan][5][/bold cyan] 📍 [white]IP Intelligence[/white]         [dim](Geolocation, ASN, reverse DNS, ISP)[/dim]")
        console.print("  [bold cyan][6][/bold cyan] 🛡️  [white]Shodan Threat & Ports[/white]   [dim](Open ports & CVE vulnerabilities - zero API key)[/dim]")
        console.print("  [bold cyan][7][/bold cyan] ✉️  [white]Email Intelligence[/white]      [dim](MX, disposable check, Gravatar social pivot)[/dim]")
        console.print("  [bold cyan][8][/bold cyan] 📞 [white]Phone Intelligence[/white]      [dim](Carrier, country, timezone, formatting)[/dim]")
        console.print("  [bold cyan][9][/bold cyan] ☁️  [white]Cloud Bucket Hunter[/white]     [dim](AWS S3, Google Cloud, Azure Blob probing)[/dim]")
        console.print("  [bold cyan][10][/bold cyan] 🕷️ [white]Passive Historical URLs[/white] [dim](AlienVault OTX archive endpoints & secrets)[/dim]")
        console.print("  [bold cyan][11][/bold cyan] 📸 [white]Image EXIF & Forensics[/white]  [dim](Camera specs & GPS coordinates with map links)[/dim]")
        console.print("  [bold cyan][12][/bold cyan] 📁 [bold yellow]View Saved Case Folders[/bold yellow] [dim](Browse past targets, folders & reports)[/dim]")
        console.print("  [bold cyan][0][/bold cyan] 🚪 [white]Exit NexusOSINT[/white]")
        console.print()

        choice = Prompt.ask(
            "[bold green]nexusosint[/bold green] [bold cyan]>[/bold cyan]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "0"],
            default="1",
        )

        if choice == "0":
            console.print("\n[bold cyan]Exiting NexusOSINT. Mission Accomplished![/bold cyan]\n")
            sys.exit(0)

        elif choice == "1":
            target = Prompt.ask("\nEnter target seed (Email, Username, Domain, IP, or Phone)")
            if target.strip():
                run_and_save_scan("all", target.strip(), timeout=timeout, concurrency=concurrency)

        elif choice == "2":
            target = Prompt.ask("\nEnter username or online handle to scan")
            if target.strip():
                run_and_save_scan("user", target.strip(), timeout=timeout, concurrency=concurrency)

        elif choice == "3":
            target = Prompt.ask("\nEnter GitHub username (e.g. torvalds)")
            if target.strip():
                run_and_save_scan("github", target.strip(), timeout=timeout)

        elif choice == "4":
            target = Prompt.ask("\nEnter target domain (e.g. example.com)")
            if target.strip():
                run_and_save_scan("domain", target.strip(), timeout=timeout)

        elif choice == "5":
            target = Prompt.ask("\nEnter target IP or domain (e.g. 1.1.1.1 or target.com)")
            if target.strip():
                run_and_save_scan("ip", target.strip(), timeout=timeout)

        elif choice == "6":
            target = Prompt.ask("\nEnter target IP or domain for Shodan InternetDB scan")
            if target.strip():
                run_and_save_scan("shodan", target.strip(), timeout=timeout)

        elif choice == "7":
            target = Prompt.ask("\nEnter email address to investigate")
            if target.strip():
                run_and_save_scan("email", target.strip(), timeout=timeout)

        elif choice == "8":
            target = Prompt.ask("\nEnter phone number with country code (e.g. +14155552671)")
            if target.strip():
                run_and_save_scan("phone", target.strip())

        elif choice == "9":
            target = Prompt.ask("\nEnter company name or keyword for cloud storage bucket probing")
            if target.strip():
                run_and_save_scan("cloud", target.strip(), concurrency=concurrency)

        elif choice == "10":
            target = Prompt.ask("\nEnter domain to query for historical endpoints and secrets")
            if target.strip():
                run_and_save_scan("urls", target.strip(), timeout=timeout)

        elif choice == "11":
            target = Prompt.ask("\nEnter local image path or remote image URL")
            if target.strip():
                run_and_save_scan("exif", target.strip(), timeout=timeout)

        elif choice == "12":
            view_cases_interactive_menu()

        console.print()
        Prompt.ask("[dim]Press Enter to return to main menu...[/dim]", default="")


def build_cli_parser() -> argparse.ArgumentParser:
    """Construct unified CLI parser supporting commands, subcommands, and flags."""
    parser = argparse.ArgumentParser(
        prog="nexusosint",
        description="⚡ NexusOSINT - All-In-One Open-Source Intelligence (OSINT) Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nexusosint all 8.8.8.8              Run autonomous chained master scan & graph on target
  nexusosint all target.com           Run master dossier on domain
  nexusosint ip 1.1.1.1               IP geolocation, ASN, reverse DNS scan
  nexusosint domain example.com       Domain DNS, RDAP, subdomains & headers
  nexusosint user torvalds            Check username across 50+ platforms
  nexusosint email user@test.com      Email validation, MX records & Gravatar pivot
  nexusosint phone +14155552671       Phone carrier, country & line type
  nexusosint github torvalds          GitHub profile, SSH keys & commit emails
  nexusosint shodan 1.1.1.1           Shodan InternetDB port & CVE vulnerability scan
  nexusosint cloud acme_corp          Hunt exposed AWS, GCP & Azure storage buckets
  nexusosint urls example.com         AlienVault OTX archive endpoints & secrets
  nexusosint exif /path/to/img.jpg    Extract image camera EXIF & GPS coordinates
  nexusosint cases                    View and browse saved investigation case folders
  nexusosint menu                     Launch interactive terminal menu
        """,
    )

    # Subparsers for commands: nexusosint <command> <target> [options]
    subparsers = parser.add_subparsers(dest="command", help="Scan mode or management action")

    # Command options parent parser
    opts_parent = argparse.ArgumentParser(add_help=False)
    opts_parent.add_argument("-o", "--output-dir", help="Custom folder path to save investigation results")
    opts_parent.add_argument("-t", "--timeout", type=float, default=6.0, help="Network timeout in seconds (default: 6.0)")
    opts_parent.add_argument("-c", "--concurrency", type=int, default=15, help="Concurrent workers for async tasks (default: 15)")
    opts_parent.add_argument("--no-save", action="store_true", help="Output to terminal only without saving to a folder")
    opts_parent.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner display")

    # 1. 'all' command
    p_all = subparsers.add_parser("all", aliases=["dossier", "full"], parents=[opts_parent], help="Run Master Chained Dossier & Graph on target")
    p_all.add_argument("target", help="Target seed (Email, Username, Domain, IP, or Phone)")

    # 2. 'ip' command
    p_ip = subparsers.add_parser("ip", parents=[opts_parent], help="IP geolocation, ASN, reverse DNS scan")
    p_ip.add_argument("target", help="Target IP address or domain")

    # 3. 'domain' command
    p_domain = subparsers.add_parser("domain", aliases=["dns"], parents=[opts_parent], help="Domain DNS, RDAP, subdomains & security headers")
    p_domain.add_argument("target", help="Target domain (e.g. example.com)")

    # 4. 'user' command
    p_user = subparsers.add_parser("user", aliases=["username"], parents=[opts_parent], help="Username scan across 50+ platforms")
    p_user.add_argument("target", help="Target username handle")

    # 5. 'email' command
    p_email = subparsers.add_parser("email", aliases=["mail"], parents=[opts_parent], help="Email validation, MX records & Gravatar identity")
    p_email.add_argument("target", help="Target email address")

    # 6. 'phone' command
    p_phone = subparsers.add_parser("phone", aliases=["tel"], parents=[opts_parent], help="Phone carrier, country, and timezone intelligence")
    p_phone.add_argument("target", help="Target phone number (e.g. +14155552671)")

    # 7. 'github' command
    p_git = subparsers.add_parser("github", aliases=["git"], parents=[opts_parent], help="GitHub reconnaissance (commit emails & SSH keys)")
    p_git.add_argument("target", help="Target GitHub username (e.g. torvalds)")

    # 8. 'shodan' command
    p_shodan = subparsers.add_parser("shodan", aliases=["ports"], parents=[opts_parent], help="Shodan InternetDB port & CVE vulnerability scan")
    p_shodan.add_argument("target", help="Target IP address or domain")

    # 9. 'cloud' command
    p_cloud = subparsers.add_parser("cloud", aliases=["buckets", "s3"], parents=[opts_parent], help="Exposed cloud storage bucket hunter (AWS, GCP, Azure)")
    p_cloud.add_argument("target", help="Company keyword or brand name")

    # 10. 'urls' command
    p_urls = subparsers.add_parser("urls", aliases=["otx", "history"], parents=[opts_parent], help="AlienVault OTX passive archive endpoints & secrets")
    p_urls.add_argument("target", help="Target domain")

    # 11. 'exif' command
    p_exif = subparsers.add_parser("exif", aliases=["image", "gps"], parents=[opts_parent], help="Image EXIF camera forensics & GPS coordinates")
    p_exif.add_argument("target", help="Local image file path or remote image URL")

    # 12. 'cases' command
    subparsers.add_parser("cases", aliases=["reports", "list"], parents=[opts_parent], help="Browse and inspect saved target case folders")

    # 13. 'menu' command
    subparsers.add_parser("menu", parents=[opts_parent], help="Launch interactive terminal menu")

    # TOP-LEVEL FLAG COMPATIBILITY (e.g. nexusosint -i 1.1.1.1, --dossier target, etc.)
    parser.add_argument("--dossier", help="Execute Master Chained Dossier & Graph on target")
    parser.add_argument("-u", "--username", help="Target username to investigate across 50+ platforms")
    parser.add_argument("--github", help="Deep GitHub reconnaissance (commit emails & SSH keys)")
    parser.add_argument("-d", "--domain", help="Target domain for DNS, RDAP, subdomains & headers")
    parser.add_argument("-i", "--ip", help="Target IP address or domain for geolocation & ASN")
    parser.add_argument("--shodan", help="Shodan InternetDB port & CVE vulnerability scan")
    parser.add_argument("-e", "--email", help="Target email for verification & Gravatar pivot")
    parser.add_argument("-p", "--phone", help="Target phone number for carrier & location")
    parser.add_argument("--cloud", help="Company keyword to hunt for exposed storage buckets")
    parser.add_argument("--urls", help="Target domain for historical URLs & passive secrets")
    parser.add_argument("--exif", help="Local image file path or image URL for EXIF & GPS")
    parser.add_argument("-o", "--output-dir", help="Custom folder path to save investigation results")
    parser.add_argument("-t", "--timeout", type=float, default=6.0, help="Network timeout in seconds (default: 6.0)")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Concurrent workers for async scans (default: 15)")
    parser.add_argument("--no-save", action="store_true", help="Output to terminal only without saving to a folder")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner display")

    return parser


def main():
    """Main CLI entrypoint."""
    parser = build_cli_parser()
    args = parser.parse_args()

    # Determine banner suppression
    suppress_banner = getattr(args, "no_banner", False)
    if not suppress_banner:
        print_banner()

    save_folder = not getattr(args, "no_save", False)
    timeout = getattr(args, "timeout", 6.0)
    concurrency = getattr(args, "concurrency", 15)
    output_dir = getattr(args, "output_dir", None)

    # 1. Check Subcommand Execution (e.g. nexusosint all <target>, nexusosint ip <ip>, etc.)
    cmd = getattr(args, "command", None)
    if cmd:
        if cmd in ("cases", "reports", "list"):
            view_cases_interactive_menu()
            return

        if cmd == "menu":
            interactive_menu(timeout=timeout, concurrency=concurrency)
            return

        target = getattr(args, "target", None)
        if target:
            run_and_save_scan(
                scan_mode=cmd,
                target=target,
                timeout=timeout,
                concurrency=concurrency,
                output_dir=output_dir,
                save_folder=save_folder,
            )
            return

    # 2. Check Flag Compatibility Execution (e.g. nexusosint --dossier <target>, -i <ip>, etc.)
    flag_scans = [
        ("all", args.dossier),
        ("user", args.username),
        ("github", args.github),
        ("domain", args.domain),
        ("ip", args.ip),
        ("shodan", args.shodan),
        ("email", args.email),
        ("phone", args.phone),
        ("cloud", args.cloud),
        ("urls", args.urls),
        ("exif", args.exif),
    ]

    for mode, target_val in flag_scans:
        if target_val:
            run_and_save_scan(
                scan_mode=mode,
                target=target_val,
                timeout=timeout,
                concurrency=concurrency,
                output_dir=output_dir,
                save_folder=save_folder,
            )
            return

    # 3. Default fallback: Launch interactive menu if no arguments or flags given
    interactive_menu(timeout=timeout, concurrency=concurrency)


if __name__ == "__main__":
    main()
