"""
Master Auto-Pivot & Target Dossier Engine for NexusOSINT.
Autonomously chains intelligence modules based on an initial seed target
(Email, Username, Domain, IP, or Phone) and generates a complete dossier with an interactive graph.
"""

from typing import Any, Dict, List, Optional, Set
from nexus_osint.case_manager import create_target_case_folder, print_case_banner, save_case_files
from nexus_osint.exporter import export_to_json, export_to_markdown
from nexus_osint.graph_exporter import export_network_graph_html, generate_graph_html
from nexus_osint.modules.cloud_recon import analyze_cloud_buckets
from nexus_osint.modules.domain_recon import analyze_domain, clean_domain
from nexus_osint.modules.email_recon import analyze_email, validate_email_format
from nexus_osint.modules.github_recon import analyze_github
from nexus_osint.modules.ip_recon import analyze_ip, is_ip, resolve_domain_to_ip
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
    print_section,
)


class DossierGraphBuilder:
    """Builds node and edge topology for visual graph exports."""

    def __init__(self, target_seed: str):
        self.target_seed = target_seed
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.node_ids: Set[str] = set()

        self.add_node(
            node_id="target_seed",
            label=f"Target: {target_seed}",
            color="#eab308",
            size=26,
            shape="star",
        )

    def add_node(self, node_id: str, label: str, color: str = "#94a3b8", size: int = 18, shape: str = "dot") -> None:
        if node_id not in self.node_ids:
            self.node_ids.add(node_id)
            self.nodes.append({
                "id": node_id,
                "label": label,
                "color": color,
                "size": size,
                "shape": shape,
            })

    def add_edge(self, from_id: str, to_id: str, label: str = "") -> None:
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "label": label,
        })


def detect_target_type(target: str) -> str:
    """Classify the target string to determine initial reconnaissance vector."""
    target = target.strip()
    if validate_email_format(target):
        return "email"
    if is_ip(target):
        return "ip"
    if target.startswith("+") or (target.isdigit() and len(target) >= 8):
        return "phone"
    if "." in target and not target.startswith("@") and not " " in target:
        return "domain"
    return "username"


def run_master_dossier(
    target_seed: str,
    timeout: float = 6.0,
    concurrency: int = 15,
    output_dir: Optional[str] = None,
    save_folder: bool = True,
) -> Dict[str, Any]:
    """Execute autonomous chained reconnaissance from a single seed."""
    target_seed = target_seed.strip()
    target_type = detect_target_type(target_seed)

    print_section(
        "Master Dossier & Chained Recon Engine",
        f"Initial Target Seed: {target_seed} (Detected Vector: {target_type.upper()})"
    )

    dossier: Dict[str, Any] = {
        "target_seed": target_seed,
        "seed_type": target_type,
        "email_recon": None,
        "username_recon": None,
        "github_recon": None,
        "domain_recon": None,
        "ip_recon": None,
        "shodan_recon": None,
        "cloud_recon": None,
        "passive_urls": None,
        "phone_recon": None,
    }

    graph = DossierGraphBuilder(target_seed)

    # -------------------------------------------------------------
    # VECTOR: EMAIL
    # -------------------------------------------------------------
    if target_type == "email":
        log_info(f"Phase 1: Analyzing primary email identity: {target_seed}...")
        email_data = analyze_email(target_seed, timeout=timeout)
        dossier["email_recon"] = email_data

        email_node = f"email_{target_seed}"
        graph.add_node(email_node, target_seed, color="#f97316")
        graph.add_edge("target_seed", email_node, "Identified Email")

        # Extract handles & domain
        user_part, _, domain_part = target_seed.partition("@")
        discovered_usernames = {user_part}

        gravatar = email_data.get("gravatar", {})
        if gravatar.get("profile_found"):
            pref_user = gravatar.get("profile_data", {}).get("Preferred Username")
            if pref_user and pref_user != "N/A":
                discovered_usernames.add(pref_user)

            for acc in gravatar.get("connected_accounts", []):
                acc_user = acc.get("username")
                platform = acc.get("platform")
                if acc_user and acc_user != "N/A":
                    discovered_usernames.add(acc_user)
                    acc_node = f"profile_{platform}_{acc_user}"
                    graph.add_node(acc_node, f"{platform}: @{acc_user}", color="#10b981")
                    graph.add_edge(email_node, acc_node, "Linked Profile")

        # Pivot: Domain
        if domain_part and domain_part not in ("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com", "proton.me"):
            log_info(f"Phase 2: Pivoting to corporate domain: {domain_part}...")
            dom_data = analyze_domain(domain_part, timeout=timeout)
            dossier["domain_recon"] = dom_data

            dom_node = f"domain_{domain_part}"
            graph.add_node(dom_node, domain_part, color="#3b82f6")
            graph.add_edge(email_node, dom_node, "Associated Domain")

            # Resolve IP & Shodan
            try:
                resolved_ip = resolve_domain_to_ip(domain_part)
                ip_data = analyze_ip(resolved_ip, timeout=timeout)
                dossier["ip_recon"] = ip_data
                shodan_data = analyze_shodan(resolved_ip, timeout=timeout)
                dossier["shodan_recon"] = shodan_data

                ip_node = f"ip_{resolved_ip}"
                graph.add_node(ip_node, f"IP: {resolved_ip}", color="#f97316")
                graph.add_edge(dom_node, ip_node, "Resolves To")

                for p in shodan_data.get("ports", []):
                    p_node = f"port_{resolved_ip}_{p}"
                    graph.add_node(p_node, f"Port {p}", color="#ef4444", size=12)
                    graph.add_edge(ip_node, p_node, "Exposed")
            except Exception:
                pass

        # Pivot: Usernames
        primary_user = list(discovered_usernames)[0]
        log_info(f"Phase 3: Scanning platforms for handle @{primary_user}...")
        user_data = analyze_username(primary_user, timeout=timeout, concurrency=concurrency)
        dossier["username_recon"] = user_data

        user_node = f"user_{primary_user}"
        graph.add_node(user_node, f"@{primary_user}", color="#06b6d4")
        graph.add_edge(email_node, user_node, "Pivot Handle")

        for prof in user_data.get("profiles", [])[:10]:
            p_node = f"plat_{prof['Platform']}_{primary_user}"
            graph.add_node(p_node, f"{prof['Platform']}", color="#10b981", size=14)
            graph.add_edge(user_node, p_node, "Active")

        # GitHub Deep Recon
        git_data = analyze_github(primary_user, timeout=timeout)
        dossier["github_recon"] = git_data

    # -------------------------------------------------------------
    # VECTOR: USERNAME
    # -------------------------------------------------------------
    elif target_type == "username":
        clean_user = target_seed.lstrip("@")
        user_node = f"user_{clean_user}"
        graph.add_node(user_node, f"@{clean_user}", color="#06b6d4", size=22)
        graph.add_edge("target_seed", user_node, "Handle")

        # 1. Platform Recon
        log_info(f"Phase 1: Scanning 50+ platforms for @{clean_user}...")
        user_data = analyze_username(clean_user, timeout=timeout, concurrency=concurrency)
        dossier["username_recon"] = user_data

        for prof in user_data.get("profiles", []):
            p_node = f"plat_{prof['Platform']}_{clean_user}"
            graph.add_node(p_node, prof["Platform"], color="#10b981", size=14)
            graph.add_edge(user_node, p_node, "Active Account")

        # 2. GitHub Deep Recon
        log_info(f"Phase 2: Deep inspection on GitHub for @{clean_user}...")
        git_data = analyze_github(clean_user, timeout=timeout)
        dossier["github_recon"] = git_data

        # Pivot to leaked commit emails
        commit_emails = git_data.get("commit_emails", [])
        real_emails = [e["email"] for e in commit_emails if not e["is_noreply"]]
        if real_emails:
            leaked_email = real_emails[0]
            log_info(f"Phase 3: Pivoting to extracted personal commit email: {leaked_email}...")
            email_data = analyze_email(leaked_email, timeout=timeout)
            dossier["email_recon"] = email_data

            email_node = f"email_{leaked_email}"
            graph.add_node(email_node, leaked_email, color="#f97316")
            graph.add_edge(user_node, email_node, "Leaked via Git Commit")

    # -------------------------------------------------------------
    # VECTOR: DOMAIN
    # -------------------------------------------------------------
    elif target_type == "domain":
        clean_dom = clean_domain(target_seed)
        dom_node = f"dom_{clean_dom}"
        graph.add_node(dom_node, clean_dom, color="#3b82f6", size=22)
        graph.add_edge("target_seed", dom_node, "Target Domain")

        # 1. Domain & Subdomain
        log_info(f"Phase 1: Enumerating DNS, RDAP, and subdomains for {clean_dom}...")
        dom_data = analyze_domain(clean_dom, timeout=timeout)
        dossier["domain_recon"] = dom_data

        for sub in dom_data.get("subdomains", []):
            s_node = f"sub_{sub['subdomain']}"
            graph.add_node(s_node, sub["subdomain"], color="#a855f7", size=14)
            graph.add_edge(dom_node, s_node, "Subdomain")

        # 2. Resolve IP & Shodan
        try:
            resolved_ip = resolve_domain_to_ip(clean_dom)
            log_info(f"Phase 2: Inspecting host IP: {resolved_ip}...")
            ip_data = analyze_ip(resolved_ip, timeout=timeout)
            dossier["ip_recon"] = ip_data

            shodan_data = analyze_shodan(resolved_ip, timeout=timeout)
            dossier["shodan_recon"] = shodan_data

            ip_node = f"ip_{resolved_ip}"
            graph.add_node(ip_node, f"IP: {resolved_ip}", color="#f97316")
            graph.add_edge(dom_node, ip_node, "A Record")

            for p in shodan_data.get("ports", []):
                p_node = f"port_{resolved_ip}_{p}"
                graph.add_node(p_node, f"Port {p}", color="#ef4444", size=12)
                graph.add_edge(ip_node, p_node, "Open Port")

            for v in shodan_data.get("vulns", []):
                v_node = f"cve_{v}"
                graph.add_node(v_node, v, color="#dc2626", size=16, shape="diamond")
                graph.add_edge(ip_node, v_node, "Vulnerability")
        except Exception:
            pass

        # 3. Cloud Buckets
        log_info(f"Phase 3: Probing cloud storage buckets for {clean_dom}...")
        cloud_data = analyze_cloud_buckets(clean_dom, concurrency=concurrency)
        dossier["cloud_recon"] = cloud_data

        for b in cloud_data.get("buckets", []):
            b_node = f"bucket_{b['Bucket Name']}"
            color = "#ef4444" if "200" in b["Status"] else "#eab308"
            graph.add_node(b_node, f"{b['Provider']}: {b['Bucket Name']}", color=color, size=15)
            graph.add_edge(dom_node, b_node, "Storage Asset")

        # 4. Passive URLs
        log_info(f"Phase 4: Harvesting historical endpoints and secret paths...")
        passive_data = analyze_passive_urls(clean_dom, limit=100, timeout=timeout)
        dossier["passive_urls"] = passive_data

    # -------------------------------------------------------------
    # VECTOR: IP
    # -------------------------------------------------------------
    elif target_type == "ip":
        ip_node = f"ip_{target_seed}"
        graph.add_node(ip_node, f"IP: {target_seed}", color="#f97316", size=22)
        graph.add_edge("target_seed", ip_node, "Target IP")

        # 1. IP Intelligence
        log_info(f"Phase 1: Resolving geolocation, ASN, and network provider...")
        ip_data = analyze_ip(target_seed, timeout=timeout)
        dossier["ip_recon"] = ip_data

        # 2. Shodan
        log_info(f"Phase 2: Scanning Shodan InternetDB for open ports & CVEs...")
        shodan_data = analyze_shodan(target_seed, timeout=timeout)
        dossier["shodan_recon"] = shodan_data

        for p in shodan_data.get("ports", []):
            p_node = f"port_{target_seed}_{p}"
            graph.add_node(p_node, f"Port {p}", color="#ef4444", size=13)
            graph.add_edge(ip_node, p_node, "Port")

        for v in shodan_data.get("vulns", []):
            v_node = f"cve_{v}"
            graph.add_node(v_node, v, color="#dc2626", size=16, shape="diamond")
            graph.add_edge(ip_node, v_node, "CVE")

        # PTR Pivot
        ptr = ip_data.get("reverse_dns")
        if ptr:
            clean_dom = clean_domain(ptr)
            log_info(f"Phase 3: Pivoting to reverse DNS domain: {clean_dom}...")
            dom_data = analyze_domain(clean_dom, timeout=timeout)
            dossier["domain_recon"] = dom_data

            dom_node = f"dom_{clean_dom}"
            graph.add_node(dom_node, clean_dom, color="#3b82f6")
            graph.add_edge(ip_node, dom_node, "PTR Record")

    # -------------------------------------------------------------
    # VECTOR: PHONE
    # -------------------------------------------------------------
    elif target_type == "phone":
        log_info(f"Phase 1: Investigating phone number: {target_seed}...")
        phone_data = analyze_phone(target_seed)
        dossier["phone_recon"] = phone_data

        phone_node = f"phone_{target_seed}"
        graph.add_node(phone_node, target_seed, color="#10b981", size=22)
        graph.add_edge("target_seed", phone_node, "Phone")

    # -------------------------------------------------------------
    # AUTOMATED DEDICATED CASE FOLDER & EXPORTS
    # -------------------------------------------------------------
    if save_folder:
        print_section("Generating Comprehensive Dossier Reports", f"Target: {target_seed}")
        graph_html = generate_graph_html(target_seed, graph.nodes, graph.edges)
        case_folder = create_target_case_folder(target_seed, scan_mode="all", custom_dir=output_dir)
        saved_files = save_case_files(case_folder, target_seed, "all", dossier, graph_html_content=graph_html)
        print_case_banner(case_folder, saved_files, target_seed, "all")
    else:
        console.print()
        console.print(f"[bold green]✔ Master Dossier Scan Complete![/bold green] Generated [bold cyan]{len(graph.nodes)}[/bold cyan] intelligence nodes.")

    return dossier
