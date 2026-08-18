from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.config import load_config
from app.models import Finding, ScanTarget, Severity
from app.reporting import (
    build_scan_result,
    save_json_report,
    summarize_findings,
)
from app.scanner import WebScanner

from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.csp import check_csp
from modules.disclosure import check_disclosure
from modules.headers import run_header_checks
from modules.redirects import check_redirect_chain


# ============================================================
# APP CONFIGURATION
# ============================================================

APP_NAME = "Mazkiplay Nusantara"
APP_VERSION = "0.1.0"

app = typer.Typer(
    name="mazkiplay-nusantara",
    help=(
        "Mazkiplay Nusantara — "
        "Web Security Assessment Toolkit"
    ),
    add_completion=False,
)

console = Console()


# ============================================================
# BANNER
# ============================================================

BANNER = r"""
███╗   ███╗ █████╗ ███████╗██╗  ██╗██╗██████╗ ██╗      █████╗ ██╗   ██╗
████╗ ████║██╔══██╗╚══███╔╝██║ ██╔╝██║██╔══██╗██║     ██╔══██╗╚██╗ ██╔╝
██╔████╔██║███████║  ███╔╝ █████╔╝ ██║██████╔╝██║     ███████║ ╚████╔╝
██║╚██╔╝██║██╔══██║ ███╔╝  ██╔═██╗ ██║██╔═══╝ ██║     ██╔══██║  ╚██╔╝
██║ ╚═╝ ██║██║  ██║███████╗██║  ██╗██║██║     ███████╗██║  ██║   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝

                 🇮🇩  N U S A N T A R A  🇮🇩
                    Web Security Toolkit
"""


def print_banner() -> None:
    console.print(
        Panel(
            BANNER,
            title=f"[bold cyan]{APP_NAME}[/]",
            subtitle=f"v{APP_VERSION}",
            border_style="cyan",
        )
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target: str) -> ScanTarget:
    """
    Validate and normalize an HTTP/HTTPS target.
    """

    target = target.strip()

    if not target:
        raise typer.BadParameter(
            "Target tidak boleh kosong."
        )

    if not target.startswith(
        ("http://", "https://")
    ):
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise typer.BadParameter(
            "Target harus menggunakan HTTP atau HTTPS."
        )

    if not parsed.hostname:
        raise typer.BadParameter(
            "Hostname target tidak valid."
        )

    return ScanTarget(
        url=target,
        hostname=parsed.hostname,
        scheme=parsed.scheme,
        port=parsed.port,
    )


# ============================================================
# SEVERITY DISPLAY
# ============================================================

def severity_style(
    severity: Severity,
) -> str:

    styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "white",
    }

    return styles.get(
        severity,
        "white",
    )


# ============================================================
# FINDINGS TABLE
# ============================================================

def print_findings(
    findings: list[Finding],
) -> None:

    if not findings:
        console.print(
            Panel(
                "[bold green]No findings detected.[/]",
                title="Security Result",
                border_style="green",
            )
        )
        return

    table = Table(
        title="Security Findings",
        show_header=True,
        show_lines=True,
        expand=True,
    )

    table.add_column(
        "Severity",
        no_wrap=True,
    )

    table.add_column(
        "ID",
        style="dim",
    )

    table.add_column(
        "Title",
    )

    table.add_column(
        "Category",
    )

    for finding in findings:

        style = severity_style(
            finding.severity
        )

        table.add_row(
            f"[{style}]"
            f"{finding.severity.value}"
            f"[/]",

            finding.id,

            finding.title,

            finding.category,
        )

    console.print(table)


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    findings: list[Finding],
) -> None:

    summary = summarize_findings(
        findings
    )

    table = Table(
        title="Severity Summary",
        show_header=True,
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
            severity,
            str(count),
        )

    console.print(table)


# ============================================================
# SCANNER ENGINE
# ============================================================

async def perform_scan(
    target: ScanTarget,
) -> tuple[list[Finding], int]:

    config = load_config()

    scanner = WebScanner(
        config
    )

    requests_made = 0

    try:

        response = await scanner.get(
            str(target.url)
        )

        requests_made += 1

        findings: list[Finding] = []

        # ----------------------------------------------------
        # HTTP SECURITY HEADERS
        # ----------------------------------------------------

        findings.extend(
            run_header_checks(
                response
            )
        )

        # ----------------------------------------------------
        # COOKIE SECURITY
        # ----------------------------------------------------

        findings.extend(
            check_cookies(
                response
            )
        )

        # ----------------------------------------------------
        # CORS
        # ----------------------------------------------------

        findings.extend(
            check_cors(
                response
            )
        )

        # ----------------------------------------------------
        # CONTENT SECURITY POLICY
        # ----------------------------------------------------

        findings.extend(
            check_csp(
                response
            )
        )

        # ----------------------------------------------------
        # INFORMATION DISCLOSURE
        # ----------------------------------------------------

        findings.extend(
            check_disclosure(
                response
            )
        )

        # ----------------------------------------------------
        # REDIRECT ANALYSIS
        # ----------------------------------------------------

        findings.extend(
            check_redirect_chain(
                response,
                str(target.url),
            )
        )

        return findings, requests_made

    finally:

        await scanner.close()


# ============================================================
# SCAN COMMAND
# ============================================================

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help=(
            "HTTP/HTTPS target yang ingin diperiksa."
        ),
    ),

    output: str = typer.Option(
        "reports",
        "--output",
        "-o",
        help=(
            "Directory untuk menyimpan JSON report."
        ),
    ),
) -> None:
    """
    Jalankan passive web security assessment.
    """

    print_banner()

    try:

        scan_target = validate_target(
            target
        )

    except typer.BadParameter as exc:

        console.print(
            f"[bold red]Invalid target:[/] "
            f"{exc}"
        )

        raise typer.Exit(
            code=2
        )

    console.print(
        Panel(
            f"[bold]Target:[/] "
            f"{scan_target.url}\n"
            f"[bold]Host:[/] "
            f"{scan_target.hostname}\n"
            f"[bold]Scheme:[/] "
            f"{scan_target.scheme}",
            title="Scan Target",
            border_style="cyan",
        )
    )

    console.print(
        "\n[bold cyan]"
        "Starting security assessment..."
        "[/]\n"
    )

    try:

        findings, requests_made = (
            asyncio.run(
                perform_scan(
                    scan_target
                )
            )
        )

    except KeyboardInterrupt:

        console.print(
            "\n[yellow]"
            "Scan interrupted."
            "[/]"
        )

        raise typer.Exit(
            code=130
        )

    except Exception as exc:

        console.print(
            Panel(
                str(exc),
                title="Scan Error",
                border_style="red",
            )
        )

        raise typer.Exit(
            code=1
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    console.print(
        "\n[bold cyan]"
        "Assessment complete."
        "[/]\n"
    )

    print_findings(
        findings
    )

    console.print()

    print_summary(
        findings
    )

    # --------------------------------------------------------
    # JSON REPORT
    # --------------------------------------------------------

    try:

        result = build_scan_result(
            target=scan_target,
            findings=findings,
            pages_scanned=1,
            requests_made=requests_made,
        )

        report_path = save_json_report(
            result,
            directory=output,
        )

    except Exception as exc:

        console.print(
            Panel(
                str(exc),
                title="Report Error",
                border_style="yellow",
            )
        )

        raise typer.Exit(
            code=1
        )

    console.print(
        Panel(
            f"[bold green]"
            f"Report successfully saved[/]\n\n"
            f"{report_path}",
            title="JSON Report",
            border_style="green",
        )
    )

    console.print(
        f"\n[bold]Total findings:[/] "
        f"{len(findings)}"
    )

    console.print(
        f"[bold]Requests made:[/] "
        f"{requests_made}\n"
    )


# ============================================================
# VERSION COMMAND
# ============================================================

@app.command()
def version() -> None:
    """
    Tampilkan versi Mazkiplay Nusantara.
    """

    console.print(
        Panel(
            f"[bold cyan]{APP_NAME}[/]\n"
            f"Version: {APP_VERSION}\n"
            "Web Security Assessment Toolkit",
            border_style="cyan",
        )
    )


# ============================================================
# INFO COMMAND
# ============================================================

@app.command()
def info() -> None:
    """
    Tampilkan informasi scanner.
    """

    table = Table(
        title=APP_NAME
    )

    table.add_column(
        "Component"
    )

    table.add_column(
        "Status"
    )

    components = [
        (
            "HTTP Security Headers",
            "ACTIVE",
        ),
        (
            "Cookie Security",
            "ACTIVE",
        ),
        (
            "CORS Analysis",
            "ACTIVE",
        ),
        (
            "CSP Analysis",
            "ACTIVE",
        ),
        (
            "Information Disclosure",
            "ACTIVE",
        ),
        (
            "Redirect Analysis",
            "ACTIVE",
        ),
        (
            "JSON Reporting",
            "ACTIVE",
        ),
    ]

    for name, status in components:

        table.add_row(
            name,
            f"[green]{status}[/]",
        )

    console.print(table)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app()
