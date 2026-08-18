from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from app.config import load_config
from app.models import Finding, ScanTarget, Severity
from app.scanner import WebScanner
from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.csp import check_csp
from modules.disclosure import check_disclosure
from modules.headers import run_header_checks
from modules.redirects import check_redirect_chain


app = typer.Typer(
    name="mazkiplay-nusantara",
    help="Mazkiplay Nusantara Web Security Assessment Toolkit",
)

console = Console()


def validate_target(target: str) -> ScanTarget:
    parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise typer.BadParameter(
            "Target must use http:// or https://"
        )

    if not parsed.hostname:
        raise typer.BadParameter(
            "Target must contain a valid hostname."
        )

    return ScanTarget(
        url=target,
        hostname=parsed.hostname,
        scheme=parsed.scheme,
        port=parsed.port,
    )


def print_banner() -> None:
    console.print(
        "\n[bold cyan]╔══════════════════════════════════════╗[/]"
    )
    console.print(
        "[bold cyan]║     MAZKIPLAY NUSANTARA             ║[/]"
    )
    console.print(
        "[bold cyan]║     Web Security Assessment          ║[/]"
    )
    console.print(
        "[bold cyan]╚══════════════════════════════════════╝[/]\n"
    )


def severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "white",
    }.get(severity, "white")


def print_findings(
    findings: list[Finding],
) -> None:
    if not findings:
        console.print(
            "[green]No findings generated.[/green]"
        )
        return

    table = Table(
        title="Security Findings",
        show_lines=True,
    )

    table.add_column(
        "Severity",
        style="bold",
        no_wrap=True,
    )
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Category")

    for finding in findings:
        table.add_row(
            f"[{severity_style(finding.severity)}]"
            f"{finding.severity.value}[/]",
            finding.id,
            finding.title,
            finding.category,
        )

    console.print(table)


async def perform_scan(
    target: ScanTarget,
) -> list[Finding]:
    config = load_config()

    scanner = WebScanner(config)

    try:
        response = await scanner.get(
            str(target.url)
        )

        findings: list[Finding] = []

        findings.extend(
            run_header_checks(response)
        )

        findings.extend(
            check_cookies(response)
        )

        findings.extend(
            check_cors(response)
        )

        findings.extend(
            check_csp(response)
        )

        findings.extend(
            check_disclosure(response)
        )

        findings.extend(
            check_redirect_chain(
                response,
                str(target.url),
            )
        )

        return findings

    finally:
        await scanner.close()


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Authorized HTTP/HTTPS target to assess.",
    ),
) -> None:
    """
    Run a passive baseline security scan.
    """

    print_banner()

    scan_target = validate_target(target)

    console.print(
        f"[bold]Target:[/] {scan_target.url}"
    )

    console.print(
        "[dim]Running passive security checks...[/]\n"
    )

    try:
        findings = asyncio.run(
            perform_scan(scan_target)
        )
    except Exception as exc:
        console.print(
            f"[bold red]Scan failed:[/] {exc}"
        )
        raise typer.Exit(code=1)

    print_findings(findings)

    console.print(
        f"\n[bold]Total findings:[/] "
        f"{len(findings)}\n"
    )


@app.command()
def version() -> None:
    """
    Show Mazkiplay Nusantara version.
    """

    console.print(
        "[bold cyan]Mazkiplay Nusantara[/] "
        "v0.1.0"
    )


if __name__ == "__main__":
    app()
