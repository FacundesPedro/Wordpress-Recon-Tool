#!/usr/bin/env python3
"""CLI entrypoint for WordPress reconnaissance tool using Typer."""

import asyncio
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console
from rich.table import Table

from base.runner import Runner
from config import ScanConfig
from core.logger import Logger
from core.target import Target
from modules import AVAILABLE_MODULES, MODULE_REGISTRY, PROFILES
from utils.report import (
    JsonFormatter,
    MarkdownFormatter,
    Report,
    generate_report_filename,
)

app = typer.Typer(rich_markup_mode="rich")
console = Console()

logger = Logger("Main")


@app.command()
def main(
    target: Annotated[
        str,
        typer.Option(
            "-t", "--target", help="Target WordPress URL (e.g., https://example.com)"
        ),
    ],
    output: Annotated[
        Path,
        typer.Option("-o", "--output", help="Output directory for reports"),
    ] = Path("./reports"),
    format: Annotated[
        str,
        typer.Option(
            "-f",
            "--format",
            help="Report format: json, markdown, both",
            case_sensitive=False,
        ),
    ] = "markdown",
    report_file: Annotated[
        Optional[str],
        typer.Option(
            "--report-file", help="Custom report filename (without extension)"
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option(
            "-q", "--quiet", help="Suppress console output, only write report"
        ),
    ] = False,
    profile: Annotated[
        str,
        typer.Option("-p", "--profile", help="Scan profile"),
    ] = "light",
    modules: Annotated[
        Optional[str],
        typer.Option("-m", "--modules", help="Comma-separated modules to run"),
    ] = None,
    threads: Annotated[
        int,
        typer.Option("--threads", help="Number of threads"),
    ] = 2,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Request timeout in seconds"),
    ] = 10,
    insecure: Annotated[
        bool,
        typer.Option("--insecure", help="Skip TLS certificate verification"),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option("-d", "--debug", help="Enable debug logging"),
    ] = False,
    wpscan: Annotated[
        bool,
        typer.Option("--wpscan", help="Enable WPScan vulnerability scanner"),
    ] = False,
    wpscan_api_token: Annotated[
        Optional[str],
        typer.Option("--wpscan-api-token", help="WPScan API token"),
    ] = None,
    wpscan_enumerate: Annotated[
        str,
        typer.Option("--wpscan-enumerate", help="WPScan enumeration options"),
    ] = "vp,vt,tt,cb,u",
    wpscan_timeout: Annotated[
        int,
        typer.Option("--wpscan-timeout", help="WPScan timeout in seconds"),
    ] = 600,
    nuclei: Annotated[
        bool,
        typer.Option("--nuclei", help="Enable Nuclei vulnerability scanner"),
    ] = False,
    nuclei_severity: Annotated[
        str,
        typer.Option("--nuclei.severity", help="Nuclei severity filter"),
    ] = "medium,high,critical",
    ffuf: Annotated[
        bool,
        typer.Option("--ffuf", help="Enable FFUF fuzzer"),
    ] = False,
    ffuf_wordlist: Annotated[
        Optional[str],
        typer.Option("--ffuf-wordlist", help="FFUF wordlist path"),
    ] = None,
    ffuf_timeout: Annotated[
        int,
        typer.Option("--ffuf-timeout", help="FFUF timeout in seconds"),
    ] = 300,
    ffuf_rate_limit: Annotated[
        int,
        typer.Option("--ffuf-rate-limit", help="FFUF rate limit (0 = unlimited)"),
    ] = 0,
    ffuf_filter_status: Annotated[
        str,
        typer.Option("--ffuf-filter-status", help="FFUF filter status codes"),
    ] = "404",
    opendoor: Annotated[
        bool,
        typer.Option("--opendoor", help="Enable OpenDoor scanner"),
    ] = False,
    opendoor_wordlist: Annotated[
        Optional[str],
        typer.Option("--opendoor-wordlist", help="OpenDoor wordlist path"),
    ] = None,
    opendoor_timeout: Annotated[
        int,
        typer.Option("--opendoor-timeout", help="OpenDoor timeout in seconds"),
    ] = 300,
    opendoor_rate_limit: Annotated[
        int,
        typer.Option("--opendoor-rate-limit", help="OpenDoor rate limit (0 = unlimited)"),
    ] = 0,
    opendoor_mode: Annotated[
        str,
        typer.Option("--opendoor-mode", help="OpenDoor mode (wp_paths, backup, config, sensitive)"),
    ] = "wp_paths",
    skip_version_check: Annotated[
        bool,
        typer.Option("--skip-version-check", help="Skip version checking for external tools"),
    ] = False,
    require_version: Annotated[
        bool,
        typer.Option("--require-version", help="Fail if tool version is incompatible"),
    ] = False,
    verbose_version_check: Annotated[
        bool,
        typer.Option("--verbose-version-check", help="Show detailed version information"),
    ] = False,
):
    """Run WordPress reconnaissance scan."""
    config = ScanConfig()
    config.threads = threads
    config.timeout = timeout
    config.output_dir = output
    config.output_format = format  # type: ignore
    config.insecure = insecure
    config.log_level = "DEBUG" if debug else "INFO"
    config.quiet = quiet

    config.enable_wpscan = wpscan
    if wpscan_api_token:
        config.wpscan_api_token = wpscan_api_token
    config.wpscan_enumerate = wpscan_enumerate
    config.wpscan_timeout = wpscan_timeout

    config.enable_nuclei = nuclei
    config.nuclei_severity = nuclei_severity

    config.enable_ffuf = ffuf
    if ffuf_wordlist:
        config.ffuf_wordlist = ffuf_wordlist
    config.ffuf_timeout = ffuf_timeout
    config.ffuf_rate_limit = ffuf_rate_limit
    config.ffuf_filter_status = ffuf_filter_status

    config.enable_opendoor = opendoor
    if opendoor_wordlist:
        config.opendoor_wordlist = opendoor_wordlist
    config.opendoor_timeout = opendoor_timeout
    config.opendoor_rate_limit = opendoor_rate_limit
    config.opendoor_mode = opendoor_mode

    config.skip_version_check = skip_version_check
    config.require_version = require_version
    config.verbose_version_check = verbose_version_check

    main_logger = Logger("Main", config.log_level)

    if not config.quiet:
        main_logger.info("Initializing scan configuration")

    if insecure:
        main_logger.warning("TLS verification disabled - this is less secure")

    domain = resolve_domain(target)
    target_obj = Target(url=target, domain=domain)

    if not config.quiet:
        main_logger.info(f"Target: {target_obj.url} (domain: {target_obj.domain})")

    module_names = get_module_names(profile, modules, wpscan, nuclei, ffuf, opendoor)

    if not config.quiet:
        main_logger.info(f"Selected modules: {', '.join(module_names)}")

    built_modules = build_modules(module_names, wpscan, nuclei, ffuf, opendoor, config)
    if not built_modules:
        main_logger.error("No valid modules selected")
        raise typer.Exit(code=1)

    if not config.quiet:
        main_logger.info(f"Initialized {len(built_modules)} module(s)")

    runner = Runner(built_modules, config, target_obj)

    if not config.quiet:
        main_logger.info(f"Starting scan against {target_obj.url}")

    report = asyncio.run(runner.run_all())

    if not config.quiet:
        summary = report.get_summary()
        main_logger.info("Scan complete")
        main_logger.info(
            f"Total: {summary['total']} | Info: {summary['info']} | Low: {summary['low']} | Medium: {summary['medium']} | High: {summary['high']} | Critical: {summary['critical']}"
        )

    config.mkdir_output()
    _save_report(report, config, report_file, output)


@app.command("list-profiles")
def list_profiles():
    """List available scan profiles."""
    table = Table(title="Available Profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Modules", style="green")

    for name, modules in PROFILES.items():
        table.add_row(name, ", ".join(modules))

    console.print(table)


@app.command("list-modules")
def list_modules():
    """List available modules."""
    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="green")

    for name in AVAILABLE_MODULES:
        cls = MODULE_REGISTRY[name]
        table.add_row(name, cls.description or "No description")

    console.print(table)


def resolve_domain(url: str) -> str:
    """Extract domain from URL."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.netloc or url


def get_module_names(
    profile: str,
    modules_arg: Optional[str] = None,
    enable_wpscan: bool = False,
    enable_nuclei: bool = False,
    enable_ffuf: bool = False,
    enable_opendoor: bool = False,
) -> List[str]:
    """Resolve module names from profile or --modules argument."""
    if modules_arg:
        return [m.strip() for m in modules_arg.split(",")]
    return PROFILES.get(profile, [])


def build_modules(
    module_names: List[str],
    enable_wpscan: bool = False,
    enable_nuclei: bool = False,
    enable_ffuf: bool = False,
    enable_opendoor: bool = False,
    config: ScanConfig = None,
):
    """Instantiate module classes."""
    modules = []
    config = config or ScanConfig()

    for name in module_names:
        if name not in MODULE_REGISTRY:
            logger.warning(f"Unknown module '{name}', skipping")
            continue

        if name == "tools" and not enable_wpscan and not enable_nuclei and not enable_ffuf and not enable_opendoor:
            logger.debug("Skipping tools module (--wpscan, --nuclei, --ffuf, --opendoor not specified)")
            continue

        module_cls = MODULE_REGISTRY[name]

        if name == "tools":
            module = module_cls(config)
        else:
            module = module_cls()

        modules.append(module)
    return modules


def _save_report(
    report: Report,
    config: ScanConfig,
    report_file: Optional[str],
    output: Path,
):
    """Save report in configured format(s)."""
    timestamp = report.completed_at
    filename_base = report_file or generate_report_filename(
        report.domain, timestamp
    )

    if config.output_format in ("json", "both"):
        json_path = output / f"{filename_base}.json"
        JsonFormatter.save(report, json_path)
        console.print(f"[green]JSON report: {json_path}[/green]")

    if config.output_format in ("markdown", "both"):
        md_path = output / f"{filename_base}.md"
        MarkdownFormatter.save(report, md_path)
        console.print(f"[green]Markdown report: {md_path}[/green]")


if __name__ == "__main__":
    app()
