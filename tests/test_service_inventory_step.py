"""Tests for the consolidated ServiceInventoryStep."""

from core.scan_context import ScanContext
from steps.tools.service_inventory_step import ServiceInventoryStep


def _step_with_context(services):
    step = ServiceInventoryStep()
    ctx = ScanContext()
    ctx.set("services", services)
    step._ctx = ctx
    return step


class TestServiceInventoryStep:
    def test_metadata(self):
        step = ServiceInventoryStep()
        assert step.name == "service_inventory"
        assert step.requires == ("services",)

    def test_accepts_http_kwarg(self):
        """The Runner passes http= to every step class; it must be accepted."""
        from unittest.mock import MagicMock

        step = ServiceInventoryStep(
            target=MagicMock(), config=MagicMock(), http=MagicMock()
        )
        assert step.name == "service_inventory"

    async def test_emits_deduplicated_inventory(self):
        step = _step_with_context(
            [
                {
                    "host": "app.example",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.30.5",
                },
                {
                    # Same service with no version -> folded into the above.
                    "host": "app.example",
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "",
                },
                {
                    "host": "app.example",
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.6p1",
                },
            ]
        )
        findings = await step.run()
        assert len(findings) == 1
        services = findings[0].raw["services"]
        assert [s["port"] for s in services] == [22, 80]
        assert services[1]["version"] == "1.30.5"

    async def test_no_context_data_is_clean(self):
        step = ServiceInventoryStep()
        assert await step.run() == []

    async def test_empty_context_services_is_clean(self):
        step = _step_with_context([])
        assert await step.run() == []
