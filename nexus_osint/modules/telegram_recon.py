"""
Telegram Channel & Community Intelligence Module for NexusOSINT.
Inspects public Telegram channels, groups, and bot profiles via open web previews
with zero API keys or authentication requirements.
"""

from typing import Any, Dict, List, Optional
import httpx
import re

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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def clean_telegram_handle(target: str) -> str:
    """Normalize input into a clean Telegram username handle."""
    clean = target.strip()
    clean = re.sub(r"^https?://(www\.)?t\.me/(s/)?", "", clean)
    clean = clean.lstrip("@").strip("/").split("?")[0]
    return clean


def analyze_telegram(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    """
    Perform deep reconnaissance on a public Telegram channel, community, or profile.
    """
    handle = clean_telegram_handle(target)
    print_section("Telegram Intelligence Reconnaissance", f"Target Handle: @{handle}")

    if not handle:
        log_error("Invalid or empty Telegram username handle.")
        return {"error": "Invalid handle", "handle": "", "found": False}

    log_info(f"Probing Telegram public web directory for @{handle}...")
    web_url = f"https://t.me/{handle}"
    channel_feed_url = f"https://t.me/s/{handle}"

    result: Dict[str, Any] = {
        "handle": handle,
        "found": False,
        "title": "",
        "type": "Unknown",
        "description": "",
        "members_metric": "N/A",
        "verified": False,
        "image_url": "",
        "channel_url": web_url,
        "preview_feed_url": channel_feed_url,
        "recent_messages_count": 0,
    }

    try:
        with httpx.Client(headers=HEADERS, timeout=timeout, follow_redirects=True) as client:
            resp = client.get(channel_feed_url)
            if resp.status_code != 200:
                resp = client.get(web_url)

            if resp.status_code == 200:
                html = resp.text

                # Check if handle exists: Telegram displays "If you have Telegram, you can contact @... right away" or specific profile classes
                channel_markers = (
                    'class="tgme_page_title"',
                    'class="tgme_channel_info_header_title"',
                    'class="tgme_channel_info_title"',
                    'class="tgme_channel_info"',
                    'property="og:title"',
                )
                if any(m in html for m in channel_markers):
                    result["found"] = True

                    # 1. Title
                    title_match = (
                        re.search(r'<div class="tgme_channel_info_header_title"[^>]*><span dir="auto">(.*?)</span>', html)
                        or re.search(r'<div class="tgme_page_title"[^>]*><span dir="auto">(.*?)</span>', html)
                        or re.search(r'<div class="tgme_channel_info_title"[^>]*><span dir="auto">(.*?)</span>', html)
                        or re.search(r'<meta property="og:title" content="(.*?)"', html)
                    )
                    if title_match:
                        result["title"] = re.sub(r"<[^>]+>", "", title_match.group(1)).strip()

                    # 2. Description
                    desc_match = (
                        re.search(r'<div class="tgme_channel_info_description"[^>]*>(.*?)</div>', html, re.DOTALL)
                        or re.search(r'<div class="tgme_page_description"[^>]*>(.*?)</div>', html, re.DOTALL)
                        or re.search(r'<meta property="og:description" content="(.*?)"', html, re.DOTALL)
                    )
                    if desc_match:
                        result["description"] = re.sub(r"<[^>]+>", "", desc_match.group(1)).strip()

                    # 3. Extra Metrics (Subscribers / Members)
                    extra_match = (
                        re.search(r'<div class="tgme_channel_info_counter"[^>]*>(.*?)</div>', html, re.DOTALL)
                        or re.search(r'<div class="tgme_page_extra"[^>]*>(.*?)</div>', html, re.DOTALL)
                    )
                    if extra_match:
                        extra_text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", extra_match.group(1))).strip()
                        result["members_metric"] = extra_text
                        if "subscriber" in extra_text.lower():
                            result["type"] = "Broadcast Channel"
                        elif "member" in extra_text.lower():
                            result["type"] = "Supergroup / Community"
                        elif "@" in extra_text or "bot" in extra_text.lower():
                            result["type"] = "Bot / Personal Account"
                        else:
                            result["type"] = "Channel / Group"
                    else:
                        result["type"] = "User / Profile"

                    # 4. Verified Status
                    result["verified"] = any(v in html for v in ("tgme_icon_verified", "verified-icon", "tgme_page_verified"))

                    # 5. Profile Picture URL
                    img_match = (
                        re.search(r'<img class="tgme_page_photo_image" src="(.*?)"', html)
                        or re.search(r'<meta property="og:image" content="(.*?)"', html)
                    )
                    if img_match:
                        result["image_url"] = img_match.group(1).strip()

                    # 6. Count recent preview messages
                    messages = re.findall(r'class="tgme_widget_message_text', html)
                    result["recent_messages_count"] = len(messages)

    except Exception as e:
        log_warning(f"Error querying Telegram web endpoint: {e}")
        return result

    if result["found"]:
        log_success(f"Telegram entity discovered for [bold cyan]@{handle}[/bold cyan]!")
        summary_table = {
            "Telegram Handle": f"@{handle}",
            "Entity Title": result["title"] or "N/A",
            "Classification": result["type"],
            "Subscribers / Members": result["members_metric"],
            "Verified Official": "Yes (Verified ✓)" if result["verified"] else "No",
            "Public Feed Messages": str(result["recent_messages_count"]),
            "Direct Web Link": result["channel_url"],
            "Web Preview Feed": result["preview_feed_url"],
        }
        display_key_value_table("Telegram Entity Intelligence", summary_table, border_style="cyan")

        if result["description"]:
            console.print()
            console.print("[bold yellow]📝 Biography / Description:[/bold yellow]")
            console.print(f"[dim white]{result['description']}[/dim white]\n")
    else:
        log_info(f"No public Telegram entity or broadcast channel found for @{handle}.")

    return result
