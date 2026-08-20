from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from app.config import APP_NAME, APP_VERSION, load_config
from app.models import Finding, ScanTarget
from app.reporting import (
    build_scan_result,
    save_json_report,
    summarize_findings,
)
from app.scanner import WebScanner

from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.csp import check_csp
from modules.crawler import crawl
from modules.disclosure import check_disclosure
from modules.headers import run_header_checks
from modules.redirects import check_redirect_chain
from modules.robots import check_robots
from modules.sitemap import check_sitemap
from modules.tls import check_tls


# ============================================================
# APPLICATION
# ============================================================

app = typer.Typer(
    name="mazkiplay-nusantara",
    help="M4ZK1PLAY Nusantara Web Security Assessment Toolkit",
    add_completion=False,
)

console = Console()


# ============================================================
# MENU
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


# ============================================================
# TERMINAL UI
# ============================================================

def clear_terminal() -> None:
    os.system(
        "cls" if os.name == "nt" else "clear"
    )


def banner() -> None:
    text = Text()
    text.append(
        "🦅 M4ZK1PLAY NUSANTARA 🇮🇩\n",
        style="bold bright_white",
    )
    text.append(
        "DARK CYBER SECURITY TOOLKIT\n",
        style="bold bright_red",
    )
    text.append(
        f"v{APP_VERSION}",
        style="bold bright_white",
    )

    console.print(
        Panel(
            Align.center(text),
            border_style="bright_red",
            box=box.DOUBLE,
            padding=(1, 5),
        )
    )


def disclaimer() -> None:
    console.print(
        Panel(
            "[bold bright_red]"
            "AUTHORIZED SECURITY TESTING ONLY"
            "[/]\n\n"
            "[bright_white]"
            "M4ZK1PLAY Nusantara is intended for authorized "
            "security assessment and defensive testing.\n\n"
            "Only scan systems that you own or have explicit "
            "permission to assess.\n\n"
            "Do not use this toolkit to disrupt, bypass, "
            "or gain unauthorized access to systems."
            "[/]",
            title="[bold bright_red]⚠ DISCLAIMER[/]",
            border_style="bright_red",
            padding=(1, 2),
        )
    )


def pause() -> None:
    console.input(
        "\n[bold bright_red]Press ENTER to continue...[/]"
    )


def show_menu() -> None:
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
    )

    table.add_column(
        "NO",
        justify="right",
        style="bold bright_red",
    )
    table.add_column(
        "ICON",
        justify="center",
    )
    table.add_column(
        "OPTION",
        style="bold white",
    )

    for number, icon, title in MENU_ITEMS:
        style = (
            "bold bright_red"
            if number == "00"
            else "bold white"
        )

        table.add_row(
            f"[{number}]",
            icon,
            f"[{style}]{title}[/]",
        )

    console.print(
        Panel(
            table,
            title="[bold bright_red]MAIN MENU[/]",
            border_style="bright_red",
            padding=(1, 2),
        )
    )

    console.print(
        Align.center(
            Text(
                "M4ZK1PLAY@NUSANTARA :: SECURITY CONSOLE",
                style="bold bright_white",
            )
        )
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target: str) -> ScanTarget:
    target = target.strip()

    if not target:
        raise typer.BadParameter(
            "Target tidak boleh kosong."
        )

    # Only add the default HTTPS scheme when the user supplied
    # a bare hostname. Never rewrite an explicitly supplied
    # unsupported scheme such as ftp://, ssh://, etc.
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise typer.BadParameter(
            "Gunakan target HTTP atau HTTPS."
        )

    if not parsed.hostname:
        raise typer.BadParameter(
            "Hostname tidak valid."
        )

    return ScanTarget(
        url=target,
        hostname=parsed.hostname,
        scheme=parsed.scheme,
        port=parsed.port,
    )


# ============================================================
# SCANNER ENGINE
# ============================================================

async def perform_scan(
    target: ScanTarget,
) -> tuple[list[Finding], int, int]:

    config = load_config()

    scanner = WebScanner(config)

    try:
        findings, requests_made, pages_scanned = (
            await scanner.scan(
                str(target.url)
            )
        )

        return findings, requests_made, pages_scanned

    finally:
        await scanner.close()


# ============================================================
# OUTPUT HELPERS
# ============================================================

def print_findings(
    findings: list[Finding],
) -> None:

    if not findings:
        console.print(
            Panel(
                "[bold green]"
                "No findings returned."
                "[/]",
                title="RESULT",
                border_style="green",
            )
        )
        return

    table = Table(
        title="[bold bright_red]FINDINGS[/]",
        border_style="bright_red",
    )

    table.add_column(
        "Severity",
        style="bold",
    )

    table.add_column(
        "Title",
    )

    table.add_column(
        "URL",
    )

    for finding in findings:

        severity = str(
            getattr(
                finding,
                "severity",
                "INFO",
            )
        )

        title = str(
            getattr(
                finding,
                "title",
                "Unnamed finding",
            )
        )

        url = str(
            getattr(
                finding,
                "url",
                "",
            )
        )

        table.add_row(
            severity,
            title,
            url,
        )

    console.print(table)


def print_summary(
    findings: list[Finding],
) -> None:

    summary = summarize_findings(
        findings
    )

    table = Table(
        title="[bold bright_red]SEVERITY SUMMARY[/]",
        border_style="bright_red",
    )

    table.add_column(
        "Severity"
    )

    table.add_column(
        "Count",
        justify="right",
    )

    for severity, count in summary.items():
        table.add_row(
            str(severity),
            str(count),
        )

    console.print(table)


# ============================================================
# SCAN COMMAND
# ============================================================

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="HTTP/HTTPS target authorized for assessment.",
    ),
    output: str = typer.Option(
        "reports",
        "--output",
        "-o",
        help="Directory for JSON reports.",
    ),
) -> None:

    banner()

    try:
        scan_target = validate_target(target)

    except typer.BadParameter as exc:
        console.print(
            f"[bold red]Invalid target:[/] {exc}"
        )
        raise typer.Exit(code=2)

    console.print(
        Panel(
            f"[bold]URL:[/] {scan_target.url}\n"
            f"[bold]Host:[/] {scan_target.hostname}\n"
            f"[bold]Scheme:[/] {scan_target.scheme}",
            title="TARGET",
            border_style="bright_red",
        )
    )

    try:
        (
            findings,
            requests_made,
            pages_scanned,
        ) = asyncio.run(
            perform_scan(scan_target)
        )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Scan interrupted.[/]"
        )
        raise typer.Exit(code=130)

    except Exception as exc:
        console.print(
            Panel(
                str(exc),
                title="SCAN ERROR",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    console.print(
        "\n[bold green]✓ Assessment complete.[/]\n"
    )

    print_findings(findings)
    print_summary(findings)

    try:
        result = build_scan_result(
            target=scan_target,
            findings=findings,
            pages_scanned=pages_scanned,
            requests_made=requests_made,
        )

        report_path = save_json_report(
            result,
            directory=output,
        )

        console.print(
            Panel(
                f"[bold green]JSON report created[/]\n\n"
                f"{report_path}",
                title="REPORT",
                border_style="green",
            )
        )

    except Exception as exc:
        console.print(
            Panel(
                str(exc),
                title="REPORT ERROR",
                border_style="yellow",
            )
        )


# ============================================================
# VERSION
# ============================================================

@app.command()
def version() -> None:

    console.print(
        Panel(
            f"[bold bright_red]{APP_NAME}[/]\n"
            f"Version: {APP_VERSION}\n\n"
            "Web Security Assessment Toolkit",
            border_style="bright_red",
        )
    )


# ============================================================
# INFO / CONFIGURATION
# ============================================================

@app.command()
def info() -> None:

    config = load_config()

    table = Table(
        title=APP_NAME,
        border_style="bright_red",
    )

    table.add_column("Setting")
    table.add_column("Value")

    rows = [
        ("Version", APP_VERSION),
        ("Timeout", f"{config.timeout}s"),
        (
            "Connect Timeout",
            f"{config.connect_timeout}s",
        ),
        (
            "Max Redirects",
            str(config.max_redirects),
        ),
        (
            "Max Pages",
            str(config.max_pages),
        ),
        (
            "Concurrency",
            str(config.concurrency),
        ),
        (
            "Request Delay",
            f"{config.request_delay}s",
        ),
        (
            "TLS Verification",
            str(config.verify_tls),
        ),
        (
            "Follow Redirects",
            str(config.follow_redirects),
        ),
        (
            "Reports",
            str(config.reports_dir),
        ),
    ]

    for key, value in rows:
        table.add_row(
            key,
            value,
        )

    console.print(table)


# ============================================================
# MENU: TARGET
# ============================================================

def ask_target() -> str | None:

    target = console.input(
        "\n[bold bright_red]"
        "Target URL » "
        "[/]"
    ).strip()

    if not target:
        console.print(
            "[bold red]Target cannot be empty.[/]"
        )
        return None

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    try:
        validate_target(target)
    except typer.BadParameter as exc:
        console.print(
            f"[bold red]Invalid target:[/] {exc}"
        )
        return None

    return target


# ============================================================
# MENU: WEB SCAN
# ============================================================

def menu_web_scan() -> None:

    clear_terminal()
    banner()

    console.print(
        Panel(
            "Passive HTTP/HTTPS security assessment "
            "using the project's WebScanner engine.",
            title="[bold bright_red]01 • WEB SECURITY SCAN[/]",
            border_style="bright_red",
        )
    )

    target = ask_target()

    if target is None:
        pause()
        return

    try:

        scan_target = validate_target(
            target
        )

        console.print(
            "\n[bold bright_red]"
            "Running assessment..."
            "[/]\n"
        )

        (
            findings,
            requests_made,
            pages_scanned,
        ) = asyncio.run(
            perform_scan(scan_target)
        )

        console.print(
            "[bold green]✓ Assessment complete.[/]\n"
        )

        print_findings(findings)

        console.print()

        print_summary(findings)

        result = build_scan_result(
            target=scan_target,
            findings=findings,
            pages_scanned=pages_scanned,
            requests_made=requests_made,
        )

        report_path = save_json_report(
            result,
            directory="reports",
        )

        console.print(
            Panel(
                f"[bold green]Report:[/] {report_path}\n"
                f"[bold]Requests:[/] {requests_made}",
                title="[bold bright_red]REPORT[/]",
                border_style="green",
            )
        )

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]Scan interrupted.[/]"
        )

    except Exception as exc:

        console.print(
            Panel(
                str(exc),
                title="[bold red]SCAN ERROR[/]",
                border_style="red",
            )
        )

    pause()


# ============================================================
# MENU: REPORTS
# ============================================================

def menu_reports() -> None:

    clear_terminal()
    banner()

    config = load_config()

    reports_dir = Path(
        config.reports_dir
    )

    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    reports = sorted(
        (
            item
            for item in reports_dir.iterdir()
            if item.is_file()
        ),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )

    if not reports:

        console.print(
            Panel(
                "[yellow]No reports found.[/]",
                title="[bold bright_red]12 • VIEW REPORTS[/]",
                border_style="yellow",
            )
        )

        pause()
        return

    table = Table(
        title="[bold bright_red]AVAILABLE REPORTS[/]",
        border_style="bright_red",
    )

    table.add_column("FILE")
    table.add_column(
        "SIZE",
        justify="right",
    )

    for report in reports:

        table.add_row(
            report.name,
            f"{report.stat().st_size:,} B",
        )

    console.print(table)

    pause()


# ============================================================
# MENU: CONFIGURATION
# ============================================================

def menu_configuration() -> None:

    clear_terminal()
    banner()

    config = load_config()

    table = Table(
        title="[bold bright_red]CONFIGURATION[/]",
        border_style="bright_red",
    )

    table.add_column("SETTING")
    table.add_column("VALUE")

    values = {
        "Version": APP_VERSION,
        "Timeout": f"{config.timeout}s",
        "Connect Timeout": f"{config.connect_timeout}s",
        "Max Redirects": str(config.max_redirects),
        "Max Pages": str(config.max_pages),
        "Concurrency": str(config.concurrency),
        "Request Delay": f"{config.request_delay}s",
        "TLS Verification": str(config.verify_tls),
        "Follow Redirects": str(config.follow_redirects),
        "Reports": str(config.reports_dir),
    }

    for key, value in values.items():
        table.add_row(
            key,
            value,
        )

    console.print(table)

    pause()


# ============================================================
# MENU: ABOUT
# ============================================================

def menu_about() -> None:

    clear_terminal()
    banner()

    console.print(
        Panel(
            "[bold bright_red]"
            "M4ZK1PLAY NUSANTARA"
            "[/]\n\n"
            "Dark Cyber Security Toolkit\n\n"
            f"Version : {APP_VERSION}\n"
            "Interface : Interactive CLI\n"
            "Engine : WebScanner\n"
            "Reports : JSON\n\n"
            "[grey70]"
            "🇮🇩 Built for authorized security assessment."
            "[/]",
            title="[bold bright_red]14 • ABOUT[/]",
            border_style="bright_red",
        )
    )

    pause()


# ============================================================
# MENU: INDIVIDUAL SECURITY MODULES
# ============================================================

async def perform_module_check(
    number: str,
    target: ScanTarget,
) -> tuple[list[Finding], int]:
    """
    Execute one individual security module.

    The modules are intentionally kept behind the same HTTP
    client/configuration used by the main WebScanner.
    """

    config = load_config()
    scanner = WebScanner(config)

    try:
        # --------------------------------------------------
        # Response-based modules
        # --------------------------------------------------

        if number in {
            "02",
            "03",
            "04",
            "05",
            "06",
            "07",
        }:
            response = await scanner.get(str(target.url))

            if number == "02":
                findings = run_header_checks(response)

            elif number == "03":
                findings = check_cookies(response)

            elif number == "04":
                findings = check_cors(response)

            elif number == "05":
                findings = check_csp(response)

            elif number == "06":
                findings = check_disclosure(response)

            else:
                findings = check_redirect_chain(
                    response,
                    str(target.url),
                )

            return scanner.deduplicate(findings), 1

        # --------------------------------------------------
        # URL discovery / crawler
        # --------------------------------------------------

        if number == "08":
            (
                pages,
                findings,
                requests_made,
            ) = await crawl(
                client=scanner.client,
                start_url=str(target.url),
                max_pages=config.max_pages,
                request_delay=config.request_delay,
            )

            console.print(
                Panel(
                    f"[bold]Pages discovered:[/] {len(pages)}\n"
                    f"[bold]Requests made:[/] {requests_made}",
                    title="[bold bright_red]08 • URL DISCOVERY[/]",
                    border_style="bright_red",
                )
            )

            return (
                scanner.deduplicate(findings),
                requests_made,
            )

        # --------------------------------------------------
        # robots.txt
        # --------------------------------------------------

        if number == "09":
            findings = await check_robots(
                scanner.client,
                str(target.url),
            )

            return scanner.deduplicate(findings), 1

        # --------------------------------------------------
        # sitemap.xml
        # --------------------------------------------------

        if number == "10":
            discovered, findings = await check_sitemap(
                scanner.client,
                str(target.url),
                max_urls=config.max_sitemap_urls,
            )

            console.print(
                Panel(
                    f"[bold]URLs discovered:[/] {len(discovered)}",
                    title="[bold bright_red]10 • SITEMAP.XML[/]",
                    border_style="bright_red",
                )
            )

            return (
                scanner.deduplicate(findings),
                1,
            )

        # --------------------------------------------------
        # TLS
        # --------------------------------------------------

        if number == "11":
            if target.scheme != "https":
                return [
                    Finding(
                        id="tls-not-applicable",
                        title="TLS Check Not Applicable",
                        severity="INFO",
                        description=(
                            "TLS certificate inspection requires "
                            "an HTTPS target."
                        ),
                        evidence=str(target.url),
                        recommendation=(
                            "Use an HTTPS target to perform TLS "
                            "certificate inspection."
                        ),
                        url=str(target.url),
                        category="tls",
                    )
                ], 0

            findings = await check_tls(
                hostname=target.hostname,
                port=target.port or 443,
                timeout=config.timeout,
            )

            return scanner.deduplicate(findings), 0

        return [
            Finding(
                id=f"unknown-module-{number}",
                title="Unknown Module",
                severity="INFO",
                description="The requested module is not registered.",
                evidence=number,
                recommendation="Select a valid module.",
                url=str(target.url),
                category="scanner",
            )
        ], 0

    except Exception as exc:
        return [
            scanner.checker_error(
                f"module-{number}",
                str(target.url),
                exc,
            )
        ], 0

    finally:
        await scanner.close()


def module_status(
    number: str,
    title: str,
    description: str,
) -> None:
    """
    Run an individual security module from the interactive menu.
    """

    clear_terminal()
    banner()

    console.print(
        Panel(
            f"[bold white]{description}[/]\n\n"
            "[bold green]STATUS:[/] ACTIVE",
            title=f"[bold bright_red]{number} • {title}[/]",
            border_style="bright_red",
        )
    )

    target_input = ask_target()

    if not target_input:
        return

    try:
        target = validate_target(target_input)

    except typer.BadParameter as exc:
        console.print(
            Panel(
                str(exc),
                title="[bold red]INVALID TARGET[/]",
                border_style="red",
            )
        )
        pause()
        return

    console.print(
        Panel(
            f"[bold]URL:[/] {target.url}\n"
            f"[bold]Host:[/] {target.hostname}\n"
            f"[bold]Scheme:[/] {target.scheme}",
            title="[bold bright_red]TARGET[/]",
            border_style="bright_red",
        )
    )

    console.print(
        "\n[bold yellow]Running module...[/]\n"
    )

    try:
        findings, requests_made = asyncio.run(
            perform_module_check(
                number,
                target,
            )
        )

    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Module interrupted.[/]"
        )
        return

    except Exception as exc:
        console.print(
            Panel(
                str(exc),
                title="[bold red]MODULE ERROR[/]",
                border_style="red",
            )
        )
        pause()
        return

    console.print(
        "\n[bold green]✓ Module completed.[/]\n"
    )

    console.print(
        Panel(
            f"[bold]Requests made:[/] {requests_made}",
            title="[bold bright_red]RESULT[/]",
            border_style="bright_red",
        )
    )

    print_findings(findings)
    print_summary(findings)

    pause()


# ============================================================
# INTERACTIVE MENU
# ============================================================

def interactive_menu() -> None:

    clear_terminal()
    banner()
    disclaimer()

    pause()

    while True:

        clear_terminal()
        banner()
        show_menu()

        choice = console.input(
            "\n[bold bright_red]"
            "Select option » "
            "[/]"
        ).strip()

        if choice in {"0", "00"}:
            break

        if choice == "01":
            menu_web_scan()

        elif choice == "02":
            module_status(
                "02",
                "SECURITY HEADERS",
                "HTTP security header inspection.",
            )

        elif choice == "03":
            module_status(
                "03",
                "COOKIE CHECKER",
                "Cookie security attribute inspection.",
            )

        elif choice == "04":
            module_status(
                "04",
                "CORS CHECKER",
                "CORS policy inspection.",
            )

        elif choice == "05":
            module_status(
                "05",
                "CSP CHECKER",
                "Content-Security-Policy inspection.",
            )

        elif choice == "06":
            module_status(
                "06",
                "INFORMATION DISCLOSURE",
                "HTTP metadata and disclosure inspection.",
            )

        elif choice == "07":
            module_status(
                "07",
                "REDIRECT ANALYZER",
                "HTTP redirect chain inspection.",
            )

        elif choice == "08":
            module_status(
                "08",
                "URL DISCOVERY",
                "Same-origin URL discovery.",
            )

        elif choice == "09":
            module_status(
                "09",
                "ROBOTS.TXT",
                "robots.txt inspection.",
            )

        elif choice == "10":
            module_status(
                "10",
                "SITEMAP.XML",
                "sitemap.xml inspection.",
            )

        elif choice == "11":
            module_status(
                "11",
                "TLS CHECKER",
                "HTTPS/TLS configuration inspection.",
            )

        elif choice == "12":
            menu_reports()

        elif choice == "13":
            menu_configuration()

        elif choice == "14":
            menu_about()

        else:

            console.print(
                "\n[bold red]"
                "Invalid option."
                "[/]"
            )

            pause()

    clear_terminal()

    console.print(
        Panel(
            Align.center(
                Text(
                    "🦅 M4ZK1PLAY NUSANTARA 🇮🇩\n\n"
                    "SECURITY CONSOLE CLOSED",
                    style="bold bright_white",
                )
            ),
            border_style="bright_red",
            box=box.DOUBLE,
        )
    )


# ============================================================
# DEFAULT CALLBACK
# ============================================================

@app.callback(
    invoke_without_command=True,
)
def cli_callback(
    ctx: typer.Context,
) -> None:
    """
    Launch interactive menu when no command is supplied.
    """

    if ctx.invoked_subcommand is None:
        interactive_menu()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app()
