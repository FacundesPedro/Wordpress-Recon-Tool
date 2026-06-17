# recon_wp/base/runner.py
"""Runner - async orchestrator for modules and steps with risk tier parallelism."""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from config import ScanConfig
from core.finding import Finding
from core.http_client import HttpClient
from core.logger import Logger
from core.target import Target
from modules.module import Module
from utils.report import Report

RISK_TIERS = {
    1: ["passive"],
    2: ["infrastructure", "discovery", "fingerprint", "access"],
    3: ["users", "api", "xmlrpc", "secrets", "ssrf"],
    4: ["tools"],
}


class Runner:
    """Orchestrates module execution and aggregates findings.

    SECURITY:
    - Passes insecure flag to HttpClient for TLS verification control
    - Uses async context manager for proper resource cleanup
    - Validates modules before execution

    CONCURRENCY:
    - Modules are grouped by risk tier
    - Tiers execute sequentially (Tier 1 completes before Tier 2 starts)
    - Within each tier, modules run in parallel via asyncio.TaskGroup
    - Semaphore limits concurrent HTTP/tool operations
    """

    def __init__(self, modules: list[Module], config: ScanConfig, target: Target):
        self.modules = modules
        self.config = config
        self.target = target
        self.all_findings: list[Finding] = []
        self.errors: list[str] = []
        self.modules_run: list[str] = []
        self.started_at: Optional[datetime] = None
        self.logger = Logger("Runner", config.log_level)
        self._http: Optional[HttpClient] = None

    def _get_modules_by_tier(self) -> dict[int, list[Module]]:
        """Group modules by risk tier."""
        tier_modules: dict[int, list[Module]] = {1: [], 2: [], 3: [], 4: []}

        for module in self.modules:
            module_name = module.name or module.__class__.__name__
            for tier, tier_names in RISK_TIERS.items():
                if module_name in tier_names:
                    tier_modules[tier].append(module)
                    break

        return tier_modules

    async def _run_and_collect(
        self,
        module: Module,
        semaphore: asyncio.Semaphore,
        findings_list: list[Finding],
    ) -> None:
        """Run module and collect findings into shared list."""
        findings = await self.run_module(module, semaphore)
        findings_list.extend(findings)

    async def run_module(
        self,
        module: Module,
        semaphore: asyncio.Semaphore,
    ) -> list[Finding]:
        """Run all steps in a single module with semaphore control."""
        findings = []
        module_name = module.name or module.__class__.__name__
        self.logger.info(f"Starting module: {module_name}")

        issues = module.validate()
        for issue in issues:
            self.logger.warning(issue)

        if not module.steps:
            self.logger.info(f"Module '{module_name}' has no steps - skipping")
            return findings

        async with semaphore:
            for step_class in module.steps:
                try:
                    step = step_class(
                        target=self.target,
                        config=self.config,
                        http=self._http,
                    )
                    self.logger.debug(f"Running step: {step.name}")
                    step_findings = await step.run()
                    findings.extend(step_findings)
                    self.logger.debug(
                        f"Step {step.name} completed with {len(step_findings)} findings"
                    )
                except Exception as e:
                    err_msg = f"Error running step {step_class.__name__}: {e}"
                    self.logger.error(err_msg)
                    self.errors.append(err_msg)

        self.logger.info(f"Module {module_name} completed: {len(findings)} findings")
        return findings

    async def run_all(self) -> Report:
        """Run all modules in risk tier parallel order and aggregate findings."""
        self.started_at = datetime.now(timezone.utc)
        self.logger.info(f"Starting scan with {len(self.modules)} modules")

        for module in self.modules:
            issues = module.validate()
            for issue in issues:
                self.logger.warning(issue)

        tier_modules = self._get_modules_by_tier()
        semaphore = asyncio.Semaphore(self.config.threads)

        all_findings = []

        async with HttpClient(
            timeout=self.config.timeout,
            insecure=self.config.insecure,
        ) as self._http:
            for tier in sorted(RISK_TIERS.keys()):
                modules_in_tier = tier_modules.get(tier, [])
                if not modules_in_tier:
                    continue

                self.logger.info(
                    f"[Tier {tier}] Running {len(modules_in_tier)} module(s) in parallel"
                )

                async with asyncio.TaskGroup() as tg:
                    for module in modules_in_tier:
                        module_name = module.name or module.__class__.__name__
                        self.modules_run.append(module_name)
                        self.logger.info(f"  -> {module_name}")
                        tg.create_task(
                            self._run_and_collect(module, semaphore, all_findings)
                        )

                self.logger.info(f"[Tier {tier}] completed")

        self.all_findings = all_findings
        self.logger.info(f"Scan complete: {len(all_findings)} total findings")

        return Report(
            target=self.target.url,
            domain=self.target.domain,
            started_at=self.started_at,
            completed_at=datetime.now(timezone.utc),
            findings=all_findings,
            modules_run=self.modules_run,
            errors=self.errors,
        )

    def get_findings_by_severity(self, severity: str) -> list[Finding]:
        """Filter findings by severity."""
        return [f for f in self.all_findings if f.severity == severity]

    def get_findings_by_module(self, module: str) -> list[Finding]:
        """Filter findings by module name."""
        return [f for f in self.all_findings if f.module == module]

    def get_summary(self) -> dict:
        """Get a summary count of findings."""
        summary = {"total": len(self.all_findings)}
        severities = ["info", "low", "medium", "high", "critical"]
        for sev in severities:
            summary[sev] = len(self.get_findings_by_severity(sev))
        return summary
