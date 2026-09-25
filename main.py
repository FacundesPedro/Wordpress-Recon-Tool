#!/usr/bin/env python3
"""CLI entrypoint for WordPress reconnaissance tool using Typer."""

import asyncio
import re
from pathlib import Path
from typing import Annotated, Literal, Optional, cast

import typer
from rich.console import Console
from rich.table import Table

from base.runner import Runner
from config import ScanConfig
from core.exceptions import ValidationError
from core.logger import Logger
from core.target import Target
from modules import AVAILABLE_MODULES, MODULE_REGISTRY, PROFILES, RISK_TIERS
from utils.report import (
    HtmlFormatter,
    JsonFormatter,
    MarkdownFormatter,
    PdfFormatter,
    Report,
    SarifFormatter,
    generate_report_filename,
)

app = typer.Typer(rich_markup_mode="rich")
console = Console()

logger = Logger("Main")

REPORT_FORMATS = frozenset({"json", "markdown", "sarif", "html", "pdf"})

_UNSAFE_DIR_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _parse_targets(
    targets: Optional[list[str]],
    targets_file: Optional[str] = None,
) -> list[str]:
    """Resolve the target list from repeatable ``-t`` values and a file.

    Each ``-t`` value may itself be a comma-separated list. File entries are
    read one per line, with blank lines and ``#`` comments ignored. Duplicates
    are removed while preserving order.

    Raises:
        typer.BadParameter: If the targets file cannot be read or no target
            is supplied by either source.
    """
    parsed: list[str] = []

    def _add(value: str) -> None:
        value = value.strip()
        if value and value not in parsed:
            parsed.append(value)

    for value in targets or []:
        for part in str(value).split(","):
            _add(part)

    if targets_file:
        path = Path(targets_file)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise typer.BadParameter(
                f"Could not read targets file '{path}': {exc}"
            ) from exc
        for line in lines:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            _add(entry)

    if not parsed:
        raise typer.BadParameter(
            "No targets provided. Use -t/--target (repeatable or "
            "comma-separated) and/or --targets-file."
        )
    return parsed


def safe_target_dir(target: Target) -> str:
    """Return a filesystem-safe folder name for a target.

    Uses the target host (no port) and replaces any character outside
    ``[A-Za-z0-9._-]`` with an underscore.
    """
    name = _UNSAFE_DIR_CHARS.sub("_", target.domain or target.url)
    return name.strip(".-") or "target"


def _parse_formats(value: str) -> list[str]:
    """Parse a comma-separated report format list.

    Raises:
        typer.BadParameter: If empty or containing unknown formats.
    """
    raw = [part.strip().lower() for part in (value or "").split(",") if part.strip()]
    if not raw:
        raise typer.BadParameter(
            "No report format specified. Valid: json, markdown, sarif, html, pdf, all"
        )
    if "all" in raw:
        return sorted(REPORT_FORMATS)
    unknown = sorted({part for part in raw if part not in REPORT_FORMATS})
    if unknown:
        raise typer.BadParameter(
            f"Unknown report format(s): {', '.join(unknown)}. "
            f"Valid: json, markdown, sarif, html, pdf, all"
        )
    return sorted(set(raw))


@app.command()
def main(
    target: Annotated[
        Optional[list[str]],
        typer.Option(
            "-t",
            "--target",
            help=(
                "Target URL; repeat for multiple targets (-t a -t b) or pass a "
                "comma-separated list (e.g., https://example.com)"
            ),
        ),
    ] = None,
    targets_file: Annotated[
        Optional[str],
        typer.Option(
            "--targets-file",
            help="File with one target per line (blank lines and # comments ignored)",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("-o", "--output", help="Base output directory for reports"),
    ] = Path("./reports"),
    flat_output: Annotated[
        bool,
        typer.Option(
            "--flat-output",
            help="Write all reports directly into the output directory (no per-target folder)",
        ),
    ] = False,
    format: Annotated[
        str,
        typer.Option(
            "-f",
            "--format",
            help="Report format: json, markdown, sarif, html, pdf, all",
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
    nuclei_concurrency: Annotated[
        int,
        typer.Option("--nuclei-concurrency", help="Nuclei template concurrency"),
    ] = 25,
    nuclei_rate_limit: Annotated[
        int,
        typer.Option("--nuclei-rate-limit", help="Nuclei max requests per second"),
    ] = 150,
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
    ffuf_threads: Annotated[
        int,
        typer.Option("--ffuf-threads", help="FFUF concurrent threads (-t)"),
    ] = 40,
    ffuf_rate_limit: Annotated[
        int,
        typer.Option(
            "--ffuf-rate-limit", help="FFUF request rate per second (-rate, 0 = unlimited)"
        ),
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
    nmap: Annotated[
        bool,
        typer.Option("--nmap", help="Enable Nmap port scan with version detection"),
    ] = False,
    nmap_scripts: Annotated[
        bool,
        typer.Option("--nmap-scripts", help="Enable Nmap default NSE script scan (-sC)"),
    ] = False,
    nmap_top_ports: Annotated[
        int,
        typer.Option("--nmap-top-ports", help="Nmap top ports to scan"),
    ] = 100,
    nmap_ports: Annotated[
        str,
        typer.Option("--nmap-ports", help="Custom Nmap port list (overrides top ports)"),
    ] = "",
    nmap_timeout: Annotated[
        int,
        typer.Option("--nmap-timeout", help="Nmap timeout in seconds"),
    ] = 300,
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
    wp_user: Annotated[
        Optional[str],
        typer.Option("--wp-user", help="WordPress username for authenticated REST API scan"),
    ] = None,
    wp_app_password: Annotated[
        Optional[str],
        typer.Option("--wp-app-password", help="WordPress Application Password (WP >= 5.6)"),
    ] = None,
    wp_auth_method: Annotated[
        str,
        typer.Option("--wp-auth-method", help="Auth method: app_password or cookie"),
    ] = "app_password",
    save_raw: Annotated[
        bool,
        typer.Option(
            "--save-raw/--no-save-raw",
            help="Persist raw stdout/stderr/argv of external tool steps",
        ),
    ] = True,
    raw_output: Annotated[
        Optional[str],
        typer.Option("--raw-output", help="Directory for raw tool output (default <output>/raw)"),
    ] = None,
    raw_max_bytes: Annotated[
        int,
        typer.Option("--raw-max-bytes", help="Max bytes per raw artifact (0 = unlimited)"),
    ] = 5_000_000,
    raw_no_redact: Annotated[
        bool,
        typer.Option(
            "--raw-no-redact",
            help="Do not redact secrets from persisted raw output (debug only)",
        ),
    ] = False,
    skip_reachability_check: Annotated[
        bool,
        typer.Option(
            "--skip-reachability-check",
            help="Skip pre-flight DNS/TCP/TLS reachability probe",
        ),
    ] = False,
    active: Annotated[
        bool,
        typer.Option(
            "--active",
            help="Enable active/intrusive testing steps (requires --authorized)",
        ),
    ] = False,
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized",
            help="Confirm you have written authorization to actively test the target",
        ),
    ] = False,
):
    """Run WordPress reconnaissance scan."""
    try:
        parsed_formats = _parse_formats(format)
    except typer.BadParameter as exc:
        logger.error(str(exc))
        raise typer.Exit(code=1) from exc

    try:
        target_urls = _parse_targets(target, targets_file)
    except typer.BadParameter as exc:
        logger.error(str(exc))
        raise typer.Exit(code=1) from exc

    config = ScanConfig()
    config.threads = threads
    config.timeout = timeout
    config.output_dir = output
    config.organize_by_target = not flat_output
    config.output_format = ",".join(parsed_formats)
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
    config.nuclei_threads = nuclei_concurrency
    config.nuclei_rate_limit = nuclei_rate_limit

    config.enable_ffuf = ffuf
    if ffuf_wordlist:
        config.ffuf_wordlist = ffuf_wordlist
    config.ffuf_timeout = ffuf_timeout
    config.ffuf_threads = ffuf_threads
    config.ffuf_rate_limit = ffuf_rate_limit
    config.ffuf_filter_status = ffuf_filter_status

    config.enable_opendoor = opendoor
    if opendoor_wordlist:
        config.opendoor_wordlist = opendoor_wordlist
    config.opendoor_timeout = opendoor_timeout
    config.opendoor_rate_limit = opendoor_rate_limit
    config.opendoor_mode = opendoor_mode

    config.enable_nmap = nmap
    config.enable_nmap_scripts = nmap_scripts
    config.nmap_top_ports = nmap_top_ports
    config.nmap_ports = nmap_ports
    config.nmap_timeout = nmap_timeout

    if wp_user:
        config.wp_user = wp_user
    if wp_app_password:
        config.wp_application_password = wp_app_password
    config.wp_auth_method = cast(
        "Literal['app_password', 'cookie']", wp_auth_method
    )

    config.skip_version_check = skip_version_check
    config.require_version = require_version
    config.verbose_version_check = verbose_version_check
    config.skip_reachability_check = skip_reachability_check
    config.save_raw = save_raw
    if raw_output:
        config.raw_output_dir = raw_output
    config.raw_max_bytes = raw_max_bytes
    config.raw_no_redact = raw_no_redact

    main_logger = Logger("Main", config.log_level)

    module_names = get_module_names(
        profile, modules, wpscan, nuclei, ffuf, opendoor, nmap, nmap_scripts
    )

    # ── Active testing gate ─────────────────────────────────────────
    if "active" in module_names or active:
        if not authorized:
            main_logger.error(
                "Active/intrusive testing requested but not authorized. "
                "Pass --authorized to confirm you have permission to "
                "actively test this target."
            )
            raise typer.Exit(code=1)
        if "active" not in module_names:
            module_names.append("active")
        config.active_enabled = True
        main_logger.warning(
            "ACTIVE TESTING ENABLED — intrusive canary probes will be sent "
            "to the target. Detection-only payloads; still verify scope."
        )

    if not config.quiet:
        main_logger.info("Initializing scan configuration")

    if insecure:
        main_logger.warning("TLS verification disabled - this is less secure")

    if not config.quiet:
        main_logger.info(f"Selected modules: {', '.join(module_names)}")
        main_logger.info(f"Targets: {len(target_urls)}")

    # Validate module selection once, before iterating targets.
    if not build_modules(
        module_names, wpscan, nuclei, ffuf, opendoor, nmap, nmap_scripts, config
    ):
        main_logger.error("No valid modules selected")
        raise typer.Exit(code=1)

    base_output = Path(output)
    completed: list[tuple[str, Path, dict]] = []
    failed: list[str] = []

    for target_url in target_urls:
        try:
            target_obj = Target(url=target_url, domain=resolve_domain(target_url))
        except ValidationError as exc:
            main_logger.error(f"Skipping invalid target '{target_url}': {exc}")
            failed.append(target_url)
            continue

        # ── Per-target output folder ─────────────────────────────────
        if config.organize_by_target:
            target_output = base_output / safe_target_dir(target_obj)
        else:
            target_output = base_output
        target_output.mkdir(parents=True, exist_ok=True)
        config.output_dir = target_output
        if raw_output:
            config.raw_output_dir = (
                str(Path(raw_output) / safe_target_dir(target_obj))
                if config.organize_by_target
                else raw_output
            )
        else:
            config.raw_output_dir = ""

        if not config.quiet:
            main_logger.info(
                f"Target: {target_obj.url} (domain: {target_obj.domain}) "
                f"-> {target_output}"
            )

        # ── Pre-flight reachability probe ────────────────────────────
        if not config.skip_reachability_check:
            from core.reachability import check_reachability

            probe = asyncio.run(
                check_reachability(
                    target_obj.url, timeout=config.timeout, insecure=config.insecure
                )
            )
            if not probe.reachable:
                main_logger.error(
                    f"{target_obj.url}: {probe.error or 'Target is unreachable'}"
                )
                failed.append(target_url)
                continue
            if not config.quiet:
                main_logger.info(
                    f"Resolved {target_obj.domain} -> {probe.ip} "
                    f"(DNS {probe.dns_ms:.0f}ms, TCP {probe.tcp_ms:.0f}ms"
                    + (f", TLS {probe.tls_ms:.0f}ms" if probe.tls_ms else "")
                    + ")"
                )
                main_logger.debug(
                    "If this IP differs from the intended internal endpoint, run the "
                    "container with --add-host <host>:<ip> to pin the correct address."
                )

        # Rebuild modules per target so no state leaks between scans.
        built_modules = build_modules(
            module_names, wpscan, nuclei, ffuf, opendoor, nmap, nmap_scripts, config
        )
        runner = Runner(built_modules, config, target_obj)

        if not config.quiet:
            main_logger.info(f"Starting scan against {target_obj.url}")

        report = asyncio.run(runner.run_all())
        summary = report.get_summary()

        if not config.quiet:
            main_logger.info("Scan complete")
            main_logger.info(
                f"Total: {summary['total']} | Info: {summary['info']} | "
                f"Low: {summary['low']} | Medium: {summary['medium']} | "
                f"High: {summary['high']} | Critical: {summary['critical']}"
            )

        _save_report(report, config, report_file)
        completed.append((target_obj.url, target_output, summary))

    if failed:
        main_logger.warning(
            f"{len(failed)} target(s) skipped/failed: {', '.join(failed)}"
        )

    if not completed:
        main_logger.error("No targets were scanned successfully")
        raise typer.Exit(code=1)

    if len(target_urls) > 1 and not config.quiet:
        _print_batch_summary(completed, failed)


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
    """List available modules with step counts and descriptions."""
    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Steps", style="yellow", justify="right")
    table.add_column("Risk Tier", style="magenta")
    table.add_column("Description", style="green")

    for name in AVAILABLE_MODULES:
        cls = MODULE_REGISTRY[name]
        inst = cls()
        step_count = len(inst)
        tier = next(
            (str(t) for t, names in RISK_TIERS.items() if name in names),
            "?",
        )
        table.add_row(name, str(step_count), f"T{tier}", inst.description or "No description")

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
    enable_nmap: bool = False,
    enable_nmap_scripts: bool = False,
) -> list[str]:
    """Resolve module names from profile or --modules argument."""
    if modules_arg:
        return [m.strip() for m in modules_arg.split(",")]
    return PROFILES.get(profile, [])


def build_modules(
    module_names: list[str],
    enable_wpscan: bool = False,
    enable_nuclei: bool = False,
    enable_ffuf: bool = False,
    enable_opendoor: bool = False,
    enable_nmap: bool = False,
    enable_nmap_scripts: bool = False,
    config: Optional[ScanConfig] = None,
):
    """Instantiate module classes."""
    modules = []
    config = config or ScanConfig()

    for name in module_names:
        if name not in MODULE_REGISTRY:
            logger.warning(f"Unknown module '{name}', skipping")
            continue

        if name == "tools" and not (
            enable_wpscan
            or enable_nuclei
            or enable_ffuf
            or enable_opendoor
            or enable_nmap
            or enable_nmap_scripts
        ):
            logger.debug(
                "Skipping tools module "
                "(--wpscan, --nuclei, --ffuf, --opendoor, --nmap not specified)"
            )
            continue

        module_cls = MODULE_REGISTRY[name]

        module = module_cls(config) if name == "tools" else module_cls()

        modules.append(module)
    return modules


def _print_batch_summary(
    completed: list[tuple[str, Path, dict]],
    failed: list[str],
) -> None:
    """Render a compact per-target summary table after a multi-target run."""
    table = Table(title="Scan Summary")
    table.add_column("Target", style="cyan")
    table.add_column("Output", style="green")
    table.add_column("Findings", justify="right")
    table.add_column("Crit", justify="right", style="red")
    table.add_column("High", justify="right", style="red")

    for target_url, folder, summary in completed:
        table.add_row(
            target_url,
            str(folder),
            str(summary["total"]),
            str(summary["critical"]),
            str(summary["high"]),
        )

    console.print(table)

    if failed:
        console.print(f"[yellow]Failed/skipped targets: {', '.join(failed)}[/yellow]")


def _save_report(
    report: Report,
    config: ScanConfig,
    report_file: Optional[str],
):
    """Save report in the configured format(s).

    Writes into ``config.output_dir`` (the per-target folder). Accepts a single
    format or a comma-separated list (also ``all``). Formatter failures degrade
    gracefully with a warning; an empty/unknown format selection raises
    ``typer.Exit`` so a requested artifact is never silently dropped.
    """
    try:
        formats = set(_parse_formats(config.output_format))
    except typer.BadParameter as exc:
        console.print(f"[red]Error: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    output = Path(config.output_dir)
    timestamp = report.completed_at
    filename_base = report_file or generate_report_filename(
        report.domain, timestamp
    )

    if "json" in formats:
        try:
            json_path = output / f"{filename_base}.json"
            JsonFormatter.save(report, json_path)
            console.print(f"[green]JSON report: {json_path}[/green]")
        except Exception as exc:
            console.print(f"[yellow]Warning: JSON report failed ({exc})[/yellow]")

    if "markdown" in formats:
        try:
            md_path = output / f"{filename_base}.md"
            MarkdownFormatter.save(report, md_path)
            console.print(f"[green]Markdown report: {md_path}[/green]")
        except Exception as exc:
            console.print(f"[yellow]Warning: Markdown report failed ({exc})[/yellow]")

    if "sarif" in formats:
        try:
            sarif_path = output / f"{filename_base}.sarif"
            SarifFormatter.save(report, sarif_path)
            console.print(f"[green]SARIF report: {sarif_path}[/green]")
        except Exception as exc:
            console.print(f"[yellow]Warning: SARIF report failed ({exc})[/yellow]")

    if "html" in formats:
        try:
            html_path = output / f"{filename_base}.html"
            HtmlFormatter.save(report, html_path)
            console.print(f"[green]HTML report: {html_path}[/green]")
        except Exception as exc:
            console.print(f"[yellow]Warning: HTML report failed ({exc})[/yellow]")

    if "pdf" in formats:
        try:
            pdf_path = output / f"{filename_base}.pdf"
            PdfFormatter.save(report, pdf_path)
            console.print(f"[green]PDF report: {pdf_path}[/green]")
        except ImportError:
            console.print(
                "[yellow]Warning: PDF report skipped — install xhtml2pdf "
                "(pip install xhtml2pdf)[/yellow]"
            )
        except Exception as exc:
            console.print(f"[yellow]Warning: PDF report failed ({exc})[/yellow]")


if __name__ == "__main__":
    app()
