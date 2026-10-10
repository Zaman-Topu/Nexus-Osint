"""
Username Reconnaissance Module for NexusOSINT.
Asynchronously scans 50+ platforms to identify accounts, profiles, and online presence.
"""

import asyncio
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

# Registry of platforms with validation rules
PLATFORMS = [
    {
        "name": "GitHub",
        "category": "Development",
        "url": "https://github.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "GitLab",
        "category": "Development",
        "url": "https://gitlab.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Bitbucket",
        "category": "Development",
        "url": "https://bitbucket.org/{username}/",
        "check_type": "status_code",
    },
    {
        "name": "DockerHub",
        "category": "Development",
        "url": "https://hub.docker.com/v2/users/{username}/",
        "check_type": "status_code",
    },
    {
        "name": "PyPI",
        "category": "Development",
        "url": "https://pypi.org/user/{username}/",
        "check_type": "status_code",
    },
    {
        "name": "NPM",
        "category": "Development",
        "url": "https://www.npmjs.com/~{username}",
        "check_type": "status_code",
    },
    {
        "name": "Dev.to",
        "category": "Blogging / Tech",
        "url": "https://dev.to/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Medium",
        "category": "Blogging",
        "url": "https://medium.com/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "Hashnode",
        "category": "Blogging / Tech",
        "url": "https://hashnode.com/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "HackerNews",
        "category": "Tech Forum",
        "url": "https://news.ycombinator.com/user?id={username}",
        "check_type": "not_in_body",
        "error_str": "No such user.",
    },
    {
        "name": "Telegram",
        "category": "Messaging",
        "url": "https://t.me/{username}",
        "check_type": "in_body",
        "match_str": "tgme_page_extra",
    },
    {
        "name": "Reddit",
        "category": "Social / Community",
        "url": "https://www.reddit.com/user/{username}/about.json",
        "check_type": "status_code",
        "profile_url": "https://www.reddit.com/user/{username}",
    },
    {
        "name": "Keybase",
        "category": "Security / Identity",
        "url": "https://keybase.io/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Chess.com",
        "category": "Gaming",
        "url": "https://api.chess.com/pub/player/{username}",
        "check_type": "status_code",
        "profile_url": "https://www.chess.com/member/{username}",
    },
    {
        "name": "Lichess",
        "category": "Gaming",
        "url": "https://lichess.org/@/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Steam",
        "category": "Gaming",
        "url": "https://steamcommunity.com/id/{username}",
        "check_type": "not_in_body",
        "error_str": "The specified profile could not be found",
    },
    {
        "name": "Replit",
        "category": "Development",
        "url": "https://replit.com/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "Kaggle",
        "category": "Data Science",
        "url": "https://www.kaggle.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "LeetCode",
        "category": "Coding",
        "url": "https://leetcode.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Codewars",
        "category": "Coding",
        "url": "https://www.codewars.com/users/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Codecademy",
        "category": "Learning",
        "url": "https://www.codecademy.com/profiles/{username}",
        "check_type": "status_code",
    },
    {
        "name": "FreeCodeCamp",
        "category": "Learning",
        "url": "https://www.freecodecamp.org/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Linktree",
        "category": "Bio Link",
        "url": "https://linktr.ee/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Pinterest",
        "category": "Social / Media",
        "url": "https://www.pinterest.com/{username}/",
        "check_type": "status_code",
    },
    {
        "name": "Behance",
        "category": "Design / Portfolio",
        "url": "https://www.behance.net/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Dribbble",
        "category": "Design / Portfolio",
        "url": "https://dribbble.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "SoundCloud",
        "category": "Audio / Music",
        "url": "https://soundcloud.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Spotify",
        "category": "Audio / Music",
        "url": "https://open.spotify.com/user/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Bandcamp",
        "category": "Audio / Music",
        "url": "https://{username}.bandcamp.com",
        "check_type": "status_code",
    },
    {
        "name": "Vimeo",
        "category": "Video",
        "url": "https://vimeo.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "DailyMotion",
        "category": "Video",
        "url": "https://www.dailymotion.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Flickr",
        "category": "Photography",
        "url": "https://www.flickr.com/people/{username}",
        "check_type": "status_code",
    },
    {
        "name": "ProductHunt",
        "category": "Product / Tech",
        "url": "https://www.producthunt.com/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "BuyMeACoffee",
        "category": "Creator",
        "url": "https://www.buymeacoffee.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Patreon",
        "category": "Creator",
        "url": "https://www.patreon.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Substack",
        "category": "Newsletter",
        "url": "https://{username}.substack.com",
        "check_type": "status_code",
    },
    {
        "name": "Disqus",
        "category": "Discussion",
        "url": "https://disqus.com/by/{username}/",
        "check_type": "status_code",
    },
    {
        "name": "Pastebin",
        "category": "Text / Code",
        "url": "https://pastebin.com/u/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Wattpad",
        "category": "Writing",
        "url": "https://www.wattpad.com/user/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Goodreads",
        "category": "Books",
        "url": "https://www.goodreads.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "About.me",
        "category": "Bio Link",
        "url": "https://about.me/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Instructables",
        "category": "DIY / Tech",
        "url": "https://www.instructables.com/member/{username}",
        "check_type": "status_code",
    },
    {
        "name": "SourceForge",
        "category": "Open Source",
        "url": "https://sourceforge.net/u/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Fosstodon",
        "category": "Fediverse",
        "url": "https://fosstodon.org/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "TryHackMe",
        "category": "Cybersecurity",
        "url": "https://tryhackme.com/p/{username}",
        "check_type": "status_code",
    },
    {
        "name": "HackTheBox",
        "category": "Cybersecurity",
        "url": "https://forum.hackthebox.com/u/{username}",
        "check_type": "status_code",
    },
    {
        "name": "Gravatar",
        "category": "Identity",
        "url": "https://gravatar.com/{username}",
        "check_type": "status_code",
    },
    {
        "name": "YouTube",
        "category": "Video",
        "url": "https://www.youtube.com/@{username}",
        "check_type": "status_code",
    },
    {
        "name": "Twitch",
        "category": "Live Streaming",
        "url": "https://m.twitch.tv/{username}",
        "check_type": "status_code",
    },
]


async def check_platform(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    platform: Dict[str, Any],
    username: str,
) -> Optional[Dict[str, str]]:
    """Probe a single platform for username existence."""
    url = platform["url"].format(username=username)
    profile_url = platform.get("profile_url", url).format(username=username)

    async with sem:
        try:
            resp = await client.get(url, follow_redirects=True)
            check_type = platform.get("check_type", "status_code")

            exists = False
            if check_type == "status_code":
                exists = (resp.status_code == 200)
            elif check_type == "not_in_body":
                error_str = platform.get("error_str", "")
                exists = (resp.status_code == 200 and error_str not in resp.text)
            elif check_type == "in_body":
                match_str = platform.get("match_str", "")
                exists = (resp.status_code == 200 and match_str in resp.text)

            if exists:
                return {
                    "Platform": platform["name"],
                    "Category": platform["category"],
                    "Profile URL": profile_url,
                }
        except Exception:
            pass
    return None


async def scan_username(username: str, timeout: float = 6.0, concurrency: int = 15) -> List[Dict[str, str]]:
    """Scan all platforms asynchronously with live progress bar."""
    sem = asyncio.Semaphore(concurrency)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    found: List[Dict[str, str]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning platforms for '{username}'...", total=len(PLATFORMS))

        async with httpx.AsyncClient(timeout=timeout, headers=headers) as client:
            async def track_task(plat):
                res = await check_platform(client, sem, plat, username)
                progress.advance(task)
                if res:
                    found.append(res)
                return res

            tasks = [track_task(p) for p in PLATFORMS]
            await asyncio.gather(*tasks)

    return found


def analyze_username(username: str, timeout: float = 6.0, concurrency: int = 15) -> Dict[str, Any]:
    """Execute username reconnaissance workflow."""
    clean_user = username.strip().lstrip("@")
    print_section("Username Intelligence Scan", f"Target Handle: @{clean_user} across {len(PLATFORMS)} platforms")

    results = asyncio.run(scan_username(clean_user, timeout=timeout, concurrency=concurrency))

    if results:
        log_success(f"Discovered [bold green]{len(results)}[/bold green] active profile(s) for @{clean_user}!")
        table_headers = ["Platform", "Category", "Profile URL"]
        table_rows = [[r["Platform"], r["Category"], r["Profile URL"]] for r in results]
        display_list_table(f"Active Profiles (@{clean_user})", table_headers, table_rows, border_style="cyan")
    else:
        log_warning(f"No active profiles found for @{clean_user} across selected platforms.")

    return {
        "username": clean_user,
        "total_probed": len(PLATFORMS),
        "total_found": len(results),
        "profiles": results,
    }
