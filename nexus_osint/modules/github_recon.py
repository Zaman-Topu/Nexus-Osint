"""
Deep GitHub Intelligence Module for NexusOSINT.
Extracts profile metadata, public SSH/GPG keys, and leaked commit author emails.
"""

import re
from typing import Any, Dict, List, Set, Tuple
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


def fetch_github_profile(username: str, client: httpx.Client) -> Dict[str, Any]:
    """Fetch user profile metadata via GitHub REST API."""
    url = f"https://api.github.com/users/{username}"
    try:
        resp = client.get(url)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def fetch_ssh_keys(username: str, client: httpx.Client) -> List[Dict[str, str]]:
    """Extract uploaded public SSH keys and fingerprints."""
    url = f"https://github.com/{username}.keys"
    keys = []
    try:
        resp = client.get(url)
        if resp.status_code == 200 and resp.text.strip():
            for line in resp.text.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    key_type = parts[0]
                    key_data = parts[1]
                    comment = parts[2] if len(parts) > 2 else "No comment"
                    keys.append({
                        "type": key_type,
                        "preview": f"{key_data[:16]}...{key_data[-12:]}",
                        "comment": comment,
                    })
    except Exception:
        pass
    return keys


def fetch_gpg_keys(username: str, client: httpx.Client) -> bool:
    """Check if public GPG signing keys are published."""
    url = f"https://github.com/{username}.gpg"
    try:
        resp = client.get(url)
        if resp.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in resp.text:
            if "Note: This user hasn't uploaded any GPG keys" not in resp.text:
                return True
    except Exception:
        pass
    return False


def extract_commit_emails(username: str, client: httpx.Client, max_events: int = 15) -> List[Dict[str, str]]:
    """Scrape public Git events to find author emails committed by the target."""
    url = f"https://api.github.com/users/{username}/events/public"
    found_emails: Set[Tuple[str, str]] = set()

    try:
        resp = client.get(url)
        if resp.status_code != 200:
            return []
        events = resp.json()
    except Exception:
        return []

    # 1. Check direct commit payloads in PushEvents
    push_events = [ev for ev in events if ev.get("type") == "PushEvent"][:max_events]
    sample_commits = []

    for ev in push_events:
        payload = ev.get("payload", {})
        repo_name = ev.get("repo", {}).get("name", "")
        commits = payload.get("commits", [])
        for c in commits:
            author = c.get("author", {})
            email = author.get("email")
            name = author.get("name")
            if email and name:
                found_emails.add((name, email))

        # Collect commit hashes to sample via patch if payload was brief
        head = payload.get("head")
        if head and repo_name and len(sample_commits) < 5:
            sample_commits.append((repo_name, head))

    # 2. If no direct emails in payload, check commit patch headers
    if not found_emails and sample_commits:
        for repo_name, commit_sha in sample_commits:
            try:
                patch_url = f"https://github.com/{repo_name}/commit/{commit_sha}.patch"
                p_resp = client.get(patch_url, follow_redirects=True)
                if p_resp.status_code == 200:
                    for line in p_resp.text.splitlines()[:10]:
                        if line.startswith("From: "):
                            match = re.search(r"From:\s+([^<]+)<([^>]+)>", line)
                            if match:
                                c_name = match.group(1).strip()
                                c_email = match.group(2).strip()
                                found_emails.add((c_name, c_email))
                                break
            except Exception:
                pass

    results = []
    for name, email in found_emails:
        is_noreply = "noreply.github.com" in email.lower()
        results.append({
            "name": name,
            "email": email,
            "is_noreply": is_noreply,
        })
    return results


def analyze_github(username: str, timeout: float = 6.0) -> Dict[str, Any]:
    """Execute deep GitHub reconnaissance."""
    clean_user = username.strip().lstrip("@")
    print_section("GitHub Deep Identity Recon", f"Target: @{clean_user}")

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/1.0",
        "Accept": "application/vnd.github.v3+json",
    }

    with httpx.Client(timeout=timeout, headers=headers) as client:
        log_info("Fetching GitHub public profile metadata...")
        profile = fetch_github_profile(clean_user, client)

        if not profile:
            log_error(f"GitHub user @{clean_user} not found or rate-limited.")
            return {"error": "User not found", "username": clean_user}

        log_success(f"Profile located for @{clean_user} (ID: {profile.get('id')})")

        profile_overview = {
            "Full Name": profile.get("name") or "Not set",
            "Bio": profile.get("bio") or "Not set",
            "Company / Org": profile.get("company") or "Not set",
            "Location": profile.get("location") or "Not set",
            "Public Email": profile.get("email") or "Hidden / None",
            "Blog / Website": profile.get("blog") or "None",
            "Twitter Handle": profile.get("twitter_username") or "None",
            "Public Repositories": str(profile.get("public_repos", 0)),
            "Public Gists": str(profile.get("public_gists", 0)),
            "Followers": str(profile.get("followers", 0)),
            "Account Created": profile.get("created_at", "N/A"),
        }
        display_key_value_table("Profile Intelligence", profile_overview, border_style="cyan")

        # SSH & GPG Keys
        log_info("Checking uploaded cryptographic keys (SSH & GPG)...")
        ssh_keys = fetch_ssh_keys(clean_user, client)
        has_gpg = fetch_gpg_keys(clean_user, client)

        if ssh_keys:
            log_success(f"Discovered [bold green]{len(ssh_keys)}[/bold green] public SSH key(s)!")
            ssh_rows = [[k["type"], k["preview"], k["comment"]] for k in ssh_keys]
            display_list_table("Public SSH Keys", ["Key Type", "Key Fingerprint Preview", "Comment"], ssh_rows, border_style="green")
        else:
            log_info("No public SSH keys published.")

        if has_gpg:
            log_success("Public GPG signing key is published and active.")
        else:
            log_info("No public GPG key uploaded.")

        # Commit emails leak discovery
        log_info("Analyzing public commit activity for personal email addresses...")
        commit_emails = extract_commit_emails(clean_user, client)

        if commit_emails:
            real_emails = [e for e in commit_emails if not e["is_noreply"]]
            if real_emails:
                log_success(f"CRITICAL: Extracted [bold green]{len(real_emails)}[/bold green] personal commit author email(s)!")
            else:
                log_info(f"Found {len(commit_emails)} commit author record(s) (GitHub noreply privacy addresses).")

            email_rows = []
            for e in commit_emails:
                privacy_badge = "[dim yellow]GitHub Noreply[/dim yellow]" if e["is_noreply"] else "[bold green]Personal Email[/bold green]"
                email_rows.append([e["name"], e["email"], privacy_badge])

            display_list_table("Commit Author Identities", ["Author Name", "Email Address", "Type"], email_rows, border_style="magenta")
        else:
            log_info("No recent commit author records found in public event history.")

    return {
        "username": clean_user,
        "profile": profile_overview,
        "ssh_keys": ssh_keys,
        "has_gpg": has_gpg,
        "commit_emails": commit_emails,
    }
