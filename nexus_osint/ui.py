"""
NexusOSINT Terminal User Interface & Styling Module
"""

from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER_ART = r"""
 [bold cyan]███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗[/]   [bold magenta]██████╗ ███████╗██╗███╗   ██╗████████╗[/]
 [bold cyan]████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝[/]  [bold magenta]██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝[/]
 [bold cyan]██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗[/]  [bold magenta]██║   ██║███████╗██║██╔██╗ ██║   ██║   [/]
 [bold cyan]██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║[/]  [bold magenta]██║   ██║╚════██║██║██║╚██╗██║   ██║   [/]
 [bold cyan]██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║[/]  [bold magenta]╚██████╔╝███████║██║██║ ╚████║   ██║   [/]
 [bold cyan]╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/]   [bold magenta]╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   [/]
"""

TAGLINE = "[dim white]Advanced Modular Intelligence & Reconnaissance Framework | v1.0.0[/dim white]"


def print_banner() -> None:
    """Print the main application banner."""
    console.print(BANNER_ART)
    console.print(Panel(
        Text.from_markup(f"[bold yellow]⚡ NexusOSINT[/bold yellow] - {TAGLINE}\n[dim]Ready for Termux & Linux environments[/dim]"),
        box=box.ROUNDED,
        border_style="cyan"
    ))


def print_section(title: str, subtitle: Optional[str] = None) -> None:
    """Print a section header panel."""
    sub = f"\n[dim white]{subtitle}[/dim white]" if subtitle else ""
    console.print()
    console.print(Panel(
        f"[bold cyan]🔍 {title}[/bold cyan]{sub}",
        box=box.ROUNDED,
        border_style="bright_blue"
    ))


def display_key_value_table(title: str, data: Dict[str, Any], border_style: str = "cyan") -> None:
    """Display a dictionary as a clean two-column table."""
    table = Table(title=title, box=box.ROUNDED, border_style=border_style, show_header=True, header_style="bold magenta")
    table.add_column("Attribute", style="bold white", width=24)
    table.add_column("Information", style="green")

    for key, value in data.items():
        if value is None:
            val_str = "[dim red]None[/dim red]"
        elif isinstance(value, list):
            val_str = "\n".join(f"• {item}" for item in value) if value else "[dim]None[/dim]"
        elif isinstance(value, bool):
            val_str = "[bold green]Yes[/bold green]" if value else "[bold red]No[/bold red]"
        else:
            val_str = str(value)
        table.add_row(key, val_str)

    console.print(table)


def display_list_table(title: str, headers: List[str], rows: List[List[str]], border_style: str = "cyan") -> None:
    """Display tabular list of rows."""
    table = Table(title=title, box=box.ROUNDED, border_style=border_style, show_header=True, header_style="bold magenta")
    for header in headers:
        table.add_column(header)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def log_success(msg: str) -> None:
    console.print(f"[bold green][+][/bold green] {msg}")


def log_info(msg: str) -> None:
    console.print(f"[bold cyan][*][/bold cyan] {msg}")


def log_warning(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_error(msg: str) -> None:
    console.print(f"[bold red][-][/bold red] {msg}")
