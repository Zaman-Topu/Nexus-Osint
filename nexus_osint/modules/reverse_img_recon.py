"""
Multi-Engine Reverse Image Pivot Assistant for NexusOSINT.
Calculates cryptographic perceptual fingerprints and generates one-click search URLs
across Google Lens, Yandex Visual, Bing Visual, TinEye, and Baidu Image Search.
"""

import hashlib
import os
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
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


def compute_file_hashes(filepath: str) -> Dict[str, str]:
    """Calculate MD5, SHA1, and SHA256 hashes for a local file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def generate_reverse_image_engines(image_url: str) -> List[Dict[str, str]]:
    """Generate direct reverse image search URLs across leading visual engines."""
    encoded_url = quote_plus(image_url)

    return [
        {
            "engine": "Google Lens",
            "url": f"https://lens.google.com/uploadbyurl?url={encoded_url}",
            "notes": "Global object, text, face & location recognition",
        },
        {
            "engine": "Yandex Visual Search",
            "url": f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}",
            "notes": "Best-in-class facial recognition & Russian/CIS OSINT",
        },
        {
            "engine": "Bing Visual Search",
            "url": f"https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl={encoded_url}",
            "notes": "Microsoft visual index & shopping/product matches",
        },
        {
            "engine": "TinEye Reverse Image Search",
            "url": f"https://tineye.com/search?url={encoded_url}",
            "notes": "Chronological earliest appearance & image modification tracker",
        },
        {
            "engine": "Baidu Visual Search",
            "url": f"https://graph.baidu.com/details?isfromsimilarity=1&image={encoded_url}",
            "notes": "Asian / Chinese digital footprint & social platforms",
        },
    ]


def analyze_reverse_image(target: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Master Reverse Image Pivot pipeline.
    Handles local image files or remote image URLs.
    """
    clean_target = target.strip()
    print_section("Multi-Engine Reverse Image Pivot Assistant", f"Target: {clean_target}")

    is_remote = clean_target.startswith("http://") or clean_target.startswith("https://")
    is_local = os.path.isfile(clean_target)

    if not is_remote and not is_local:
        log_error(f"Target '{clean_target}' is neither an accessible local file nor a valid HTTP/HTTPS URL.")
        return {"error": "Invalid target", "target": clean_target, "valid": False}

    result: Dict[str, Any] = {
        "target": clean_target,
        "is_remote": is_remote,
        "is_local_file": is_local,
        "file_size_bytes": 0,
        "md5": "",
        "sha1": "",
        "sha256": "",
        "engines": [],
    }

    if is_local:
        log_info(f"Computing cryptographic fingerprints for local image: {os.path.basename(clean_target)}...")
        try:
            hashes = compute_file_hashes(clean_target)
            result.update(hashes)
            result["file_size_bytes"] = os.path.getsize(clean_target)

            log_success(f"Image Hash (MD5): [bold green]{result['md5']}[/bold green]")
            log_success(f"Image Hash (SHA256): [bold green]{result['sha256'][:24]}...[/bold green]")

            # For local files, also construct search engines if public mirror or hash search
            # Online hash threat intel links:
            hash_engines = [
                {
                    "engine": "VirusTotal Hash",
                    "url": f"https://www.virustotal.com/gui/file/{result['sha256']}",
                    "notes": "Malware & steganography threat verification",
                },
                {
                    "engine": "Hybrid-Analysis Hash",
                    "url": f"https://www.hybrid-analysis.com/sample/{result['sha256']}",
                    "notes": "Sandbox forensic artifact inspection",
                },
                {
                    "engine": "Google Hash Search",
                    "url": f"https://www.google.com/search?q={result['md5']}",
                    "notes": "Discover public references to exact file hash",
                },
            ]
            result["engines"] = hash_engines

            summary_info = {
                "Image Source": "Local Storage File",
                "File Path": clean_target,
                "File Size": f"{result['file_size_bytes']} bytes ({round(result['file_size_bytes'] / 1024, 2)} KB)",
                "MD5 Fingerprint": result["md5"],
                "SHA1 Fingerprint": result["sha1"],
                "SHA256 Fingerprint": result["sha256"],
            }
            display_key_value_table("Image Forensics & Hashes", summary_info, border_style="cyan")

            engine_headers = ["Forensic Database / Engine", "One-Click Investigation URL", "Investigation Objective"]
            engine_rows = [[e["engine"], e["url"][:50] + ("..." if len(e["url"]) > 50 else ""), e["notes"]] for e in hash_engines]
            display_list_table("Cryptographic Hash OSINT Pivot Links", engine_headers, engine_rows, border_style="yellow")

            log_info("Tip: For visual search across Google Lens/Yandex, upload the image directly or provide a public URL.")

        except Exception as e:
            log_error(f"Failed reading local image file: {e}")
            return result

    else:
        # Remote image URL
        log_info(f"Generating visual search engine queries for remote image URL...")
        engines = generate_reverse_image_engines(clean_target)
        result["engines"] = engines

        # Optional download head to get content size / type
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                head = client.head(clean_target)
                if head.status_code == 200:
                    content_length = head.headers.get("content-length", "0")
                    content_type = head.headers.get("content-type", "image")
                    result["file_size_bytes"] = int(content_length) if content_length.isdigit() else 0
                    result["content_type"] = content_type
        except Exception:
            pass

        url_summary = {
            "Image Source": "Remote Web Resource",
            "Direct Image URL": clean_target,
            "Content Type": result.get("content_type", "image/*"),
            "Estimated Size": f"{result['file_size_bytes']} bytes" if result["file_size_bytes"] > 0 else "Unknown",
        }
        display_key_value_table("Remote Image Telemetry", url_summary, border_style="cyan")

        engine_headers = ["Search Engine", "Direct Reverse Lookup URL", "Specialization"]
        engine_rows = [[e["engine"], e["url"][:55] + ("..." if len(e["url"]) > 55 else ""), e["notes"]] for e in engines]
        display_list_table("Multi-Engine Reverse Visual Search Links", engine_headers, engine_rows, border_style="green")

    return result
