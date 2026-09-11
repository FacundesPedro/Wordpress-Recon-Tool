# recon_wp/steps/active/race_condition_step.py
"""
Race condition detection - concurrent identical request burst.

Covers WSTG 4.10.x (business logic / limits): sends a burst of concurrent
identical requests to an operator-supplied endpoint and reports the status
distribution. Mixed 2xx/4xx outcomes on a single-use endpoint suggest a race
window; uniform 2xx on a limited endpoint suggests no limiting.

Requires `WP_ACTIVE_RACE_ENDPOINT` to be set (app-specific surface).
"""

# WHAT: Probes for race windows via concurrent identical requests
# HOW: Fires N concurrent requests at a configured endpoint; analyzes the
#      status distribution for mixed outcomes
# WHY: Concurrent processing of limited/single-use actions is a classic
#      financial/business-logic bug

import asyncio
from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

BURST = 10
MAX_FINDINGS = 1


class RaceConditionStep(ActiveHttpStep):
    """Send a concurrent burst at a configured endpoint and analyze outcomes."""

    name = "race_condition"
    description = "Detect race windows via concurrent request burst (endpoint required)"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        endpoint = (getattr(self.config, "active_race_endpoint", "") or "").strip()
        if not endpoint:
            self.logger.info(
                "Race probe skipped: WP_ACTIVE_RACE_ENDPOINT not set"
            )
            return self.findings

        self.logger.info(f"Probing race conditions at {endpoint} ({BURST} concurrent)...")

        baseline = await self.probe(endpoint)
        if baseline is None:
            self.logger.info("Race probe: baseline request failed")
            return self.findings

        semaphore = asyncio.Semaphore(BURST)

        async def single() -> int | None:
            async with semaphore:
                response = await self.probe(endpoint)
                return response.status_code if response else None

        results = await asyncio.gather(*(single() for _ in range(BURST)))
        statuses = [s for s in results if s is not None]
        if not statuses:
            self.logger.info("Race probe: no responses")
            return self.findings

        successes = sum(1 for s in statuses if 200 <= s < 300)
        failures = len(statuses) - successes
        distribution = {s: statuses.count(s) for s in sorted(set(statuses))}

        if successes and failures:
            self.add_finding(
                "medium",
                f"Mixed outcomes under concurrency at {endpoint}",
                (
                    f"{BURST} concurrent identical requests produced both "
                    f"successes ({successes}) and failures ({failures}) "
                    f"({distribution}). If the action is limited or single-use, "
                    f"this mixed outcome suggests a race window - verify "
                    f"manually with a state-changing action."
                ),
                f"{BURST} concurrent requests to {endpoint} -> {distribution}",
                "Serialize state-changing operations (row locks, idempotency "
                "keys, atomic counters)",
                raw={"endpoint": endpoint, "statuses": statuses,
                     "distribution": distribution},
            )
        elif successes == len(statuses) and getattr(
            self.config, "active_race_endpoint", ""
        ):
            self.add_finding(
                "info",
                f"All concurrent requests succeeded at {endpoint}",
                (
                    f"{BURST} concurrent identical requests all returned 2xx "
                    f"({distribution}). If this endpoint is supposed to be "
                    f"limited or single-use, no limiting is enforced."
                ),
                f"{BURST} concurrent requests to {endpoint} -> {distribution}",
                "Enforce per-identity limits and idempotency for limited actions",
                raw={"endpoint": endpoint, "distribution": distribution},
            )

        self.logger.info(
            f"Race probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} sequential requests"
        )
        return self.findings
