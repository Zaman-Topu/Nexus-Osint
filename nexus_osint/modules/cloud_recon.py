"""
Cloud Asset & Storage Bucket Hunter Module for NexusOSINT.
Probes AWS S3, Google Cloud Storage, and Azure Blob Storage for exposed or protected company buckets.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional
import httpx
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from nexus_osint.ui import (
    console,
    display_list_table,
    log_error,
    log_info,
    log_success,
    log_warning,
    print_section,
)

BUCKET_SUFFIXES = [
    "",
    "-data",
    "-backup",
    "-assets",
    "-public",
    "-dev",
    "-prod",
    "-storage",
    "-files",
    "-media",
    "-logs",
    "-internal",
    "-staging",
    "-corp",
    "-web",
]

PROVIDERS = [
    {
        "provider": "AWS S3",
        "url_template": "https://{name}.s3.amazonaws.com",
    },
    {
        "provider": "Google Cloud",
        "url_template": "https://storage.googleapis.com/{name}",
    },
    {
        "provider": "Azure Blob",
        "url_template": "https://{name}.blob.core.windows.net/{name}",
    },
]


def clean_target_name(target: str) -> str:
    """Normalize domain or organization name to a clean alphanumeric bucket base name."""
    clean = target.strip().lower()
    clean = clean.replace("https://", "").replace("http://", "").split("/")[0]
    # If domain like example.com, take main domain name
    parts = clean.split(".")
    if len(parts) >= 2:
        return parts[0]
    return re.sub(r"[^a-z0-9\-]", "", clean)


async def probe_bucket(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    provider: str,
    bucket_name: str,
    url: str,
) -> Optional[Dict[str, str]]:
    """Probe a single cloud storage endpoint."""
    async with sem:
        try:
            resp = await client.get(url, timeout=4.0)
            status = resp.status_code

            if status == 200:
                # Open public bucket
                return {
                    "Provider": provider,
                    "Bucket Name": bucket_name,
                    "Status": "OPEN / PUBLIC (200)",
                    "Severity": "CRITICAL",
                    "URL": url,
                }
            elif status == 403:
                # Bucket exists but is private/restricted
                return {
                    "Provider": provider,
                    "Bucket Name": bucket_name,
                    "Status": "PROTECTED (403)",
                    "Severity": "ASSET FOUND",
                    "URL": url,
                }
            elif status == 400 and provider == "Azure Blob":
                # Azure 400 usually indicates valid storage account exists
                return {
                    "Provider": provider,
                    "Bucket Name": bucket_name,
                    "Status": "ACCOUNT EXISTS (400)",
                    "Severity": "ASSET FOUND",
                    "URL": url,
                }
        except Exception:
            pass
    return None


async def scan_cloud_buckets(base_name: str, concurrency: int = 15) -> List[Dict[str, str]]:
    """Scan all bucket permutations across AWS, GCP, and Azure."""
    sem = asyncio.Semaphore(concurrency)
    targets = []

    for suffix in BUCKET_SUFFIXES:
        bucket_name = f"{base_name}{suffix}"
        for prov in PROVIDERS:
            url = prov["url_template"].format(name=bucket_name)
            targets.append((prov["provider"], bucket_name, url))

    found: List[Dict[str, str]] = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusOSINT/1.0"}

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Probing cloud storage for '{base_name}'...", total=len(targets))

        async with httpx.AsyncClient(headers=headers, verify=False) as client:
            async def run_probe(prov, bname, u):
                res = await probe_bucket(client, sem, prov, bname, u)
                progress.advance(task)
                if res:
                    found.append(res)
                return res

            tasks = [run_probe(p, b, u) for p, b, u in targets]
            await asyncio.gather(*tasks)

    return found


def analyze_cloud_buckets(target: str, concurrency: int = 15) -> Dict[str, Any]:
    """Execute cloud asset and storage bucket reconnaissance."""
    base_name = clean_target_name(target)
    print_section("Cloud Bucket & Storage Recon", f"Target Keyword: {base_name} across AWS, GCP & Azure")

    log_info(f"Generating permutations for keyword: [bold yellow]{base_name}[/bold yellow]...")
    results = asyncio.run(scan_cloud_buckets(base_name, concurrency=concurrency))

    if results:
        open_buckets = [r for r in results if "200" in r["Status"]]
        if open_buckets:
            log_warning(f"CRITICAL: Found [bold red]{len(open_buckets)}[/bold red] publicly accessible cloud bucket(s)!")
        else:
            log_success(f"Located [bold green]{len(results)}[/bold green] confirmed cloud storage asset(s) (Protected).")

        headers = ["Provider", "Bucket Name", "Access Status", "Severity", "Bucket URL"]
        rows = [[r["Provider"], r["Bucket Name"], r["Status"], r["Severity"], r["URL"]] for r in results]
        display_list_table("Discovered Cloud Assets", headers, rows, border_style="yellow")
    else:
        log_info(f"No active cloud storage buckets identified for '{base_name}'.")

    return {
        "target": target,
        "base_name": base_name,
        "total_discovered": len(results),
        "buckets": results,
    }
