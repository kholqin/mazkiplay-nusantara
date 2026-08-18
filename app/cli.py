from __future__ import annotations

import os
import platform
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# ============================================================
# M4ZK1PLAY NUSANTARA
# Dark Cyber Security Console
# ============================================================

APP_NAME = "M4ZK1PLAY NUSANTARA"
APP_VERSION = "0.1.0"
APP_TAGLINE = "DARK CYBER SECURITY TOOLKIT"

REPORTS_DIR = Path("reports")

console = Console()


# ============================================================
# TERMINAL HELPERS
# ============================================================

def clear_screen() -> None:
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    """Pause before returning to menu."""
    console.print()
    console.input(
        "[bold bright_white]  Press ENTER to continue...[/bold bright_white]"
    )


def divider() -> None:
    console.print(
        "[bright_red]"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        "[/bright_red]"
    )


# ============================================================
# BRANDING
# ============================================================

def ascii_logo() -> Text:
    logo = Text()

    logo.append(
        "        ███╗   ███╗ ██████╗\n",
        style="bold bright_red",
    )
    logo.append(
        "        ████╗ ████║██╔════╝\n",
        style="bold bright_white",
    )
    logo.append(
        "        ██╔████╔██║██║\n",
        style="bold bright_red",
    )
    logo.append(
        "        ██║╚██╔╝██║██║\n",
        style="bold bright_white",
    )
    logo.append(
        "        ██║ ╚═╝ ██║╚██████╗\n",
        style="bold bright_red",
    )
    logo.append(
        "        ╚═╝     ╚═╝ ╚═════╝\n",
        style="bold bright_white",
    )

    return logo


def banner() -> None:
    logo = ascii_logo()

    title = Text()
    title.append("🦅 ", style="bright_white")
    title.append(APP_NAME, style="bold bright_red")
    title.append(" 🇮🇩", style="bold bright_white")

    subtitle = Text()
    subtitle.append(APP_TAGLINE, style="bold bright_white")
    subtitle.append(f"  v{APP_VERSION}", style="bright_red")

    content = Group(
        Align.center(logo),
        Align.center(title),
        Align.center(subtitle),
    )

    console.print(
        Panel(
            content,
            border_style="bright_red",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )


# ============================================================
# DISCLAIMER
# ============================================================

def disclaimer() -> None:
    text = Text()

    text.append("⚠  AUTHORIZED SECURITY TESTING ONLY\n\n", style="bold bright_red")

    text.append(
        "M4ZK1PLAY Nusantara is a security assessment toolkit "
        "designed for authorized testing.\n\n",
        style="bright_white",
    )

    text.append(
        "Use this software only against systems that you own "
        "or have explicit permission to assess.\n\n",
        style="bright_white",
    )

    text.append(
        "The project is not responsible for unauthorized access, "
        "disruption, damage, or misuse of this software.",
        style="grey70",
    )

    console.print(
        Panel(
            Align.center(text),
            title="[bold bright_red]⚠ DISCLAIMER[/bold bright_red]",
            border_style="bright_red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


# ============================================================
# MAIN MENU
# ============================================================

MENU_ITEMS = [
    ("01", "🔍", "WEB SECURITY SCAN"),
    ("02", "🛡️", "SECURITY HEADERS"),
    ("03", "🍪", "COOKIE CHECKER"),
    ("04", "🌐", "CORS CHECKER"),
    ("05", "📜", "CSP CHECKER"),
    ("06", "🔎", "INFORMATION DISCLOSURE"),
    ("07", "🔀", "REDIRECT ANALYZER"),
    ("08", "🕷️", "URL DISCOVERY"),
    ("09", "🤖", "ROBOTS.TXT"),
    ("10", "🗺️", "SITEMAP.XML"),
    ("11", "🔐", "TLS CHECKER"),
    ("12", "📊", "VIEW REPORTS"),
    ("13", "⚙️", "CONFIGURATION"),
    ("14", "ℹ️", "ABOUT"),
    ("00", "🚪", "EXIT"),
]


def main_menu() -> None:
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        expand=False,
    )

    table.add_column(
        "Number",
        style="bold bright_red",
        justify="right",
    )

    table.add_column(
        "Icon",
        style="bright_white",
        justify="center",
    )

    table.add_column(
        "Option",
        style="bold bright_white",
    )

    for number, icon, label in MENU_ITEMS:
        if number == "00":
            table.add_row(
                f"[bold bright_red][{number}][/bold bright_red]",
                icon,
                f"[bold bright_red]{label}[/bold bright_red]",
            )
        else:
            table.add_row(
                f"[bold bright_red][{number}][/bold bright_red]",
                icon,
                label,
            )

    console.print(
        Panel(
            table,
            title="[bold bright_red]MAIN MENU[/bold bright_red]",
            border_style="bright_red",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )


# ============================================================
# STATUS BAR
# ============================================================

def status_bar() -> None:
    python_version = platform.python_version()
    system = platform.system()

    text = Text()

    text.append(" M4ZK1PLAY@NUSANTARA ", style="bold black on bright_red")
    text.append(" :: ", style="bold bright_white")
    text.append("SECURITY CONSOLE", style="bold bright_white")
    text.append(" :: ", style="bold bright_white")
    text.append(f"Python {python_version}", style="bright_red")
    text.append(" :: ", style="bright_white")
    text.append(system, style="bright_white")

    console.print(Align.center(text))


# ============================================================
# TARGET INPUT
# ============================================================

def get_target() -> str | None:
    console.print()

    console.print(
        Panel(
            "[bold bright_white]Enter the target URL.[/bold bright_white]\n"
            "[grey70]Example: https://example.com[/grey70]",
            title="[bold bright_red]TARGET[/bold bright_red]",
            border_style="bright_red",
        )
    )

    target = console.input(
        "\n[bold bright_red]  Target URL » [/bold bright_red]"
    ).strip()

    if not target:
        console.print(
            "\n[bold bright_red]✖ Target cannot be empty.[/bold bright_red]"
        )
        return None

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return target


# ============================================================
# MODULE PLACEHOLDER
# ============================================================

def module_screen(title: str, description: str) -> None:
    clear_screen()
    banner()

    console.print(
        Panel(
            f"[bold bright_white]{description}[/bold bright_white]\n\n"
            "[bright_red]STATUS:[/bright_red] "
            "[yellow]MODULE READY FOR INTEGRATION[/yellow]",
            title=f"[bold bright_red]{title}[/bold bright_red]",
            border_style="bright_red",
        )
    )

    pause()


# ============================================================
# WEB SECURITY SCAN
# ============================================================

def web_security_scan() -> None:
    clear_screen()
    banner()

    target = get_target()

    if not target:
        pause()
        return

    console.print()

    console.print(
        Panel(
            f"[bold bright_white]Target:[/bold bright_white] "
            f"[bright_red]{target}[/bright_red]\n\n"
            "[bold bright_white]Assessment:[/bold white] "
            "[green]READY[/green]",
            title="[bold bright_red]WEB SECURITY SCAN[/bold bright_red]",
            border_style="bright_red",
        )
    )

    console.print()
    console.print(
        "[bold bright_red]⚡ Scanner engine integration point.[/bold bright_red]"
    )

    console.print(
        "[grey70]The existing scanner implementation should be "
        "connected here rather than duplicated inside the CLI.[/grey70]"
    )

    pause()


# ============================================================
# REPORT VIEWER
# ============================================================

def view_reports() -> None:
    clear_screen()
    banner()

    REPORTS_DIR.mkdir(exist_ok=True)

    reports = sorted(
        (
            path
            for path in REPORTS_DIR.iterdir()
            if path.is_file()
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not reports:
        console.print(
            Panel(
                "[yellow]No reports available yet.[/yellow]\n\n"
                f"Directory: [bright_white]{REPORTS_DIR}[/bright_white]",
                title="[bold bright_red]REPORTS[/bold bright_red]",
                border_style="bright_red",
            )
        )

        pause()
        return

    table = Table(
        title="[bold bright_red]AVAILABLE REPORTS[/bold bright_red]",
        border_style="bright_red",
        box=box.ROUNDED,
    )

    table.add_column(
        "FILE",
        style="bright_white",
    )

    table.add_column(
        "SIZE",
        style="bright_red",
        justify="right",
    )

    for report in reports:
        size = report.stat().st_size

        table.add_row(
            report.name,
            f"{size:,} B",
        )

    console.print(table)

    pause()


# ============================================================
# CONFIGURATION
# ============================================================

def configuration() -> None:
    clear_screen()
    banner()

    console.print(
        Panel(
            "[bold bright_white]Configuration Engine[/bold bright_white]\n\n"
            "Project configuration is handled through "
            "[bright_red]app/config.py[/bright_red].\n\n"
            "Configuration file:\n"
            "[bright_white]config.example.json[/bright_white]",
            title="[bold bright_red]⚙ CONFIGURATION[/bold bright_red]",
            border_style="bright_red",
        )
    )

    pause()


# ============================================================
# ABOUT
# ============================================================

def about() -> None:
    clear_screen()
    banner()

    console.print(
        Panel(
            "[bold bright_red]M4ZK1PLAY Nusantara[/bold bright_red]\n\n"
            "[bold bright_white]Dark Cyber Security Toolkit[/bold bright_white]\n\n"
            f"Version : {APP_VERSION}\n"
            f"Python  : {platform.python_version()}\n"
            f"System  : {platform.system()}\n\n"
            "[grey70]"
            "Modular security assessment framework with "
            "CLI tooling, checkers and reporting."
            "[/grey70]",
            title="[bold bright_red]ℹ ABOUT[/bold bright_red]",
            border_style="bright_red",
        )
    )

    pause()


# ============================================================
# MENU ROUTER
# ============================================================

def handle_choice(choice: str) -> bool:

    if choice in {"0", "00"}:
        return False

    if choice == "01":
        web_security_scan()

    elif choice == "02":
        module_screen(
            "🛡️ SECURITY HEADERS",
            "Analyze HTTP security headers.",
        )

    elif choice == "03":
        module_screen(
            "🍪 COOKIE CHECKER",
            "Inspect cookie security attributes.",
        )

    elif choice == "04":
        module_screen(
            "🌐 CORS CHECKER",
            "Analyze CORS response configuration.",
        )

    elif choice == "05":
        module_screen(
            "📜 CSP CHECKER",
            "Analyze Content-Security-Policy configuration.",
        )

    elif choice == "06":
        module_screen(
            "🔎 INFORMATION DISCLOSURE",
            "Inspect exposed HTTP metadata.",
        )

    elif choice == "07":
        module_screen(
            "🔀 REDIRECT ANALYZER",
            "Analyze HTTP redirect behavior.",
        )

    elif choice == "08":
        module_screen(
            "🕷️ URL DISCOVERY",
            "Discover same-origin URLs.",
        )

    elif choice == "09":
        module_screen(
            "🤖 ROBOTS.TXT",
            "Inspect robots.txt.",
        )

    elif choice == "10":
        module_screen(
            "🗺️ SITEMAP.XML",
            "Inspect sitemap.xml.",
        )

    elif choice == "11":
        module_screen(
            "🔐 TLS CHECKER",
            "Inspect HTTPS/TLS configuration.",
        )

    elif choice == "12":
        view_reports()

    elif choice == "13":
        configuration()

    elif choice == "14":
        about()

    else:
        console.print()
        console.print(
            Panel(
                "[bold bright_red]Invalid option.[/bold bright_red]\n"
                "Choose a number from [bright_white]00–14[/bright_white].",
                border_style="bright_red",
            )
        )

        pause()

    return True


# ============================================================
# INTERACTIVE MODE
# ============================================================

def interactive_mode() -> None:

    # Show disclaimer once at startup.
    clear_screen()
    banner()
    disclaimer()

    pause()

    while True:

        clear_screen()

        banner()
        main_menu()

        status_bar()

        console.print()

        choice = console.input(
            "[bold bright_red]  Select option » [/bold bright_white]"
        ).strip()

        if not handle_choice(choice):
            break

    clear_screen()

    console.print(
        Panel(
            Align.center(
                Text(
                    "🦅 M4ZK1PLAY NUSANTARA\n"
                    "Security console closed.\n\n"
                    "🇮🇩 Stay secure.",
                    style="bold bright_white",
                )
            ),
            border_style="bright_red",
            box=box.DOUBLE,
        )
    )


# ============================================================
# ENTRY POINT
# ============================================================

def main() -> None:
    try:
        interactive_mode()

    except KeyboardInterrupt:
        console.print(
            "\n\n[bold bright_red]CTRL+C detected — exiting.[/bold bright_red]"
        )

    except EOFError:
        console.print(
            "\n\n[bold bright_red]Input closed — exiting.[/bold bright_red]"
        )


if __name__ == "__main__":
    main()
