# recon_wp/steps/tools/service_inventory_step.py
"""Consolidated network-service inventory.

WHAT: Merges the banner/version data published by the nmap tool steps into a
      single normalized "services" view (port, protocol, product, version).
HOW:  Reads the ``services`` artifact from the shared ScanContext (populated by
      NmapPortScanStep / NmapScriptScanStep) and emits one aggregated finding.
WHY:  The report's host/service table (and the future infra-CVE correlation
      step) should be generated from structured data instead of assembled by
      hand from raw tool output.
"""

from base.step import BaseStep
from core.finding import Finding


class ServiceInventoryStep(BaseStep):
    """Emit a deduplicated service inventory from the shared context."""

    name = "service_inventory"
    description = "Consolidated network-service inventory (from nmap/TLS)"
    severity = "info"
    MODULE = "tools"
    requires = ("services",)
    provides = ("service_inventory",)

    def __init__(self, target=None, config=None, name=None, description=None):
        super().__init__(
            target=target,
            config=config,
            name=name or self.name,
            description=description or self.description,
        )

    async def run(self) -> list[Finding]:
        ctx = self.ctx
        services = ctx.get("services") if ctx is not None else None
        if not services:
            self.logger.info("No service data available for inventory")
            return self.findings

        unique: dict[tuple, dict] = {}
        for service in services:
            if not isinstance(service, dict):
                continue
            key = (
                service.get("host"),
                service.get("port"),
                service.get("protocol"),
                service.get("service"),
                service.get("product"),
            )
            # Prefer an entry that carries a product/version over a bare one.
            existing = unique.get(key)
            if existing is None or (
                not existing.get("version") and service.get("version")
            ):
                unique[key] = service

        records = sorted(
            unique.values(),
            key=lambda s: (
                str(s.get("host") or ""),
                int(s.get("port") or 0),
            ),
        )
        if not records:
            return self.findings

        lines = []
        for s in records:
            label = f"{s.get('port')}/{s.get('protocol', 'tcp')} {s.get('service')}"
            if s.get("product"):
                label += f" ({s['product']}"
                label += f" {s['version']})" if s.get("version") else ")"
            lines.append(label)

        self._add_finding(
            module=self.MODULE,
            severity="info",
            title=f"Network service inventory: {len(records)} service(s)",
            description="Normalized services discovered during the scan",
            evidence="\n".join(lines),
            recommendation=(
                "Review each exposed service, confirm it is required, and track "
                "its version against vendor advisories"
            ),
            raw={"services": records},
        )
        self.logger.info(f"Service inventory: {len(records)} service(s)")
        return self.findings
