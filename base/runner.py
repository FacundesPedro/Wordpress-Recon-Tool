# recon_wp/base/runner.py
"""Runner - async orchestrator for modules and steps with risk tier parallelism."""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from base.scheduler import build_graph, run_graph
from config import ScanConfig
from core.finding import Finding
from core.http_client import HttpClient
from core.logger import Logger
from core.scan_context import ScanContext
from core.target import Target
from modules import RISK_TIERS
from modules.module import Module
from utils.report import Report


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
    - With ``config.parallel_steps`` enabled, steps within a tier run as a
      dependency-aware graph (see base/scheduler.py) and share data through
      a per-target ScanContext.
    """

    # Modules whose steps must stay serialized (they intentionally pace
    # requests or mutate shared session state).
    SERIAL_MODULES = frozenset({"active"})

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
        self._ctx: Optional[ScanContext] = None

    def _parallel_enabled(self) -> bool:
        """Explicit identity check so MagicMock configs do not enable it."""
        return getattr(self.config, "parallel_steps", False) is True

    def _step_concurrency(self) -> int:
        value = getattr(self.config, "step_concurrency", 0)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
        threads = getattr(self.config, "threads", 2)
        return threads if isinstance(threads, int) and threads > 0 else 2

    def _get_modules_by_tier(self) -> dict[int, list[Module]]:
        """Group modules by risk tier."""
        tier_modules: dict[int, list[Module]] = {tier: [] for tier in RISK_TIERS}

        for module in self.modules:
            module_name = module.name or module.__class__.__name__
            matched = False
            for tier, tier_names in RISK_TIERS.items():
                if module_name in tier_names:
                    tier_modules[tier].append(module)
                    matched = True
                    break
            if not matched:
                self.logger.warning(
                    f"Module '{module_name}' does not match any risk tier — will not run"
                )

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
                if self._http is not None and self._http.unreachable is True:
                    self.logger.warning(
                        f"Target unreachable — skipping step {step_class.__name__}"
                    )
                    continue
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

    async def _run_step_node(
        self,
        node,
        semaphore: asyncio.Semaphore,
        findings_list: list[Finding],
    ) -> None:
        """Instantiate and run one step node, collecting findings.

        Never raises: failures are recorded in ``self.errors`` so the
        dependency graph keeps making progress.
        """
        try:
            async with semaphore:
                if self._http is not None and self._http.unreachable is True:
                    return
                step = node.step_class(
                    target=self.target,
                    config=self.config,
                    http=self._http,
                )
                if self._ctx is not None:
                    step._ctx = self._ctx
                self.logger.debug(f"Running step: {step.name}")
                step_findings = await step.run()
                findings_list.extend(step_findings)
                self.logger.debug(
                    f"Step {step.name} completed with {len(step_findings)} findings"
                )
        except Exception as e:
            err_msg = f"Error running step {node.step_class.__name__}: {e}"
            self.logger.error(err_msg)
            self.errors.append(err_msg)

    async def _run_tier_parallel(
        self,
        tier: int,
        modules_in_tier: list[Module],
        findings_list: list[Finding],
    ) -> None:
        """Run a tier's steps as a dependency-aware DAG."""
        entries: list[tuple[type, str]] = []
        module_names: list[str] = []
        for module in modules_in_tier:
            module_name = module.name or module.__class__.__name__
            module_names.append(module_name)
            for step_class in module.steps:
                entries.append((step_class, module_name))

        for name in module_names:
            if name not in self.modules_run:
                self.modules_run.append(name)

        graph = build_graph(entries)
        for warning in graph.warnings:
            self.logger.warning(warning)
        for error in graph.errors:
            self.logger.error(error)

        step_semaphore = asyncio.Semaphore(self._step_concurrency())
        serial_semaphore = asyncio.Semaphore(1)

        def semaphore_for(node) -> asyncio.Semaphore:
            if node.module_name in self.SERIAL_MODULES:
                return serial_semaphore
            return step_semaphore

        async def run_node(node) -> None:
            await self._run_step_node(node, semaphore_for(node), findings_list)

        def should_skip(node) -> bool:
            return self._http is not None and self._http.unreachable is True

        def on_skip(node) -> None:
            if self._ctx is not None and node.provides:
                self._ctx.mark_missing(*node.provides)

        self.logger.info(
            f"[Tier {tier}] Running {len(graph.nodes)} step(s) as a dependency graph "
            f"(concurrency={self._step_concurrency()})"
        )
        await run_graph(
            graph.nodes,
            run_node=run_node,
            should_skip=should_skip,
            on_skip=on_skip,
        )

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
            config=self.config,
        ) as self._http:
            # Per-target shared context (blackboard + memoized web artifacts).
            self._ctx = ScanContext(
                http=self._http,
                target_url=self.target.url,
                config=self.config,
                logger=self.logger,
            )
            try:
                self._http.scan_context = self._ctx
            except Exception:
                self.logger.debug("Could not attach ScanContext to HttpClient")

            parallel = self._parallel_enabled()

            for tier in sorted(RISK_TIERS.keys()):
                modules_in_tier = tier_modules.get(tier, [])
                if not modules_in_tier:
                    continue

                if self._http is not None and self._http.unreachable is True:
                    self.logger.warning(
                        f"Target unreachable — skipping tier {tier} and all remaining tiers"
                    )
                    break

                if parallel:
                    await self._run_tier_parallel(tier, modules_in_tier, all_findings)
                    self.logger.info(f"[Tier {tier}] completed")
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

            stats = self._ctx.stats if self._ctx is not None else {}
            if stats.get("requests_made") or stats.get("requests_saved"):
                self.logger.info(
                    "Shared web context: "
                    f"{stats.get('requests_made', 0)} request(s) made, "
                    f"{stats.get('requests_saved', 0)} duplicate request(s) avoided"
                )

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
