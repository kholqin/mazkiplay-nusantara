from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from app.config import (
    APP_NAME,
    APP_VERSION,
    load_config,
)
from app.models import (
    Finding,
    ScanTarget,
    Severity,
)
from app.reporting import (
    build_scan_result,
    save_json_report,
    summarize_findings,
)
from app.scanner import WebScanner


app = typer.Typer(
    name="mazkiplay-nusantara",
    help=(
        "Mazkiplay Nusantara - "
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

                    🇮🇩  NUSANTARA  🇮🇩
              WEB SECURITY ASSESSMENT TOOLKIT
"""


# ============================================================
# UI
# ============================================================

def print_banner() -> None:
    console.print(
        Panel(
            BANNER,
            title=f"[bold cyan]{APP_NAME}[/]",
            subtitle=f"v{APP_VERSION}",
            border_style="cyan",
        )
    )


def severity_style(
    severity: Severity,
) -> str:

    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "white",
    }.get(
        severity,
        "white",
    )


def print_findings(
    findings: list[Finding],
) -> None:

    if not findings:
        console.print(
            Panel(
                "[bold green]"
                "No findings detected."
                "[/]",
                title="Security Result",
                border_style="green",
            )
        )
        return

    table = Table(
        title="Security Findings",
        show_lines=True,
        expand=True,
    )

    table.add_column(
        "Severity",
        no_wrap=True,
    )

    table.add_column(
        "ID",
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


def print_summary(
    findings: list[Finding],
) -> None:

    summary = summarize_findings(
        findings
    )

    table = Table(
        title="Severity Summary"
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
# TARGET
# ============================================================

def validate_target(
    target: str,
) -> ScanTarget:

    target = target.strip()

    if not target:
        raise typer.BadParameter(
            "Target tidak boleh kosong."
        )

    if not target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        target = (
            "https://"
            + target
        )

    parsed = urlparse(
        target
    )

    if parsed.scheme not in {
        "http",
        "https",
    }:
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
# SCANNER
# ============================================================

async def perform_scan(
    target: ScanTarget,
) -> tuple[list[Finding], int]:

    config = load_config()

    scanner = WebScanner(
        config
    )

    try:

        findings, requests_made = (
            await scanner.scan(
                str(target.url)
            )
        )

        return (
            findings,
            requests_made,
        )

    finally:

        await scanner.close()


# ============================================================
# SCAN
# ============================================================

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help=(
            "HTTP/HTTPS target yang "
            "diizinkan untuk assessment."
        ),
    ),

    output: str = typer.Option(
        "reports",
        "--output",
        "-o",
        help="Directory JSON report.",
    ),
) -> None:

    print_banner()

    try:

        scan_target = validate_target(
            target
        )

    except typer.BadParameter as exc:

        console.print(
            f"[bold red]"
            f"Invalid target:[/] {exc}"
        )

        raise typer.Exit(
            code=2
        )

    console.print(
        Panel(
            f"[bold]URL:[/] "
            f"{scan_target.url}\n"
            f"[bold]Host:[/] "
            f"{scan_target.hostname}\n"
            f"[bold]Scheme:[/] "
            f"{scan_target.scheme}",
            title="Target",
            border_style="cyan",
        )
    )

    console.print(
        "\n[cyan]"
        "Running passive security assessment..."
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
    # REPORT
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
            f"JSON report created[/]\n\n"
            f"{report_path}",
            title="Report",
            border_style="green",
        )
    )

    console.print(
        f"\n[bold]Findings:[/] "
        f"{len(findings)}"
    )

    console.print(
        f"[bold]Requests:[/] "
        f"{requests_made}\n"
    )


# ============================================================
# VERSION
# ============================================================

@app.command()
def version() -> None:

    console.print(
        Panel(
            f"[bold cyan]{APP_NAME}[/]\n"
            f"Version: {APP_VERSION}\n\n"
            "Web Security Assessment Toolkit",
            border_style="cyan",
        )
    )


# ============================================================
# INFO
# ============================================================

@app.command()
def info() -> None:

    config = load_config()

    table = Table(
        title=APP_NAME
    )

    table.add_column(
        "Setting"
    )

    table.add_column(
        "Value"
    )

    rows = [
        (
            "Version",
            APP_VERSION,
        ),
        (
            "Timeout",
            f"{config.timeout}s",
        ),
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
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app()
