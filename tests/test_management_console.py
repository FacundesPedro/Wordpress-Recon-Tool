"""Tests for ManagementConsoleStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.management_console_step import ManagementConsoleStep

NPM_CONSOLE = {
    "name": "Nginx Proxy Manager",
    "kind": "management",
    "probe_paths": ["/api/", "/"],
    "signature": r"(?i)nginx\s*proxy\s*manager|nginx-proxy-manager|nginxproxy",
    "version_paths": ["/api/"],
    "version_pattern": r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
    "advisories": [
        {
            "cve": "CVE-2026-40519",
            "title": "Authenticated RCE",
            "fixed_in": "2.15.2",
            "severity": "high",
        },
    ],
}


def make_step(mock_http, mock_target, mock_config, consoles=None):
    step = ManagementConsoleStep(
        target=mock_target, config=mock_config, http=mock_http
    )
    step._load_consoles = MagicMock(return_value=consoles or [NPM_CONSOLE])
    return step


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return MagicMock(status_code=404, text="not found", headers={})

    return _respond


class TestDetection:
    async def test_vulnerable_version_high(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/api/": MagicMock(
                        status_code=200,
                        text='{"version": "2.15.1"}',
                        headers={"server": "nginx-proxy-manager"},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "CVE-2026-40519" in findings[0].title
        assert findings[0].raw["version"] == "2.15.1"

    async def test_patched_version_is_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/api/": MagicMock(
                        status_code=200,
                        text='{"version": "2.16.0"}',
                        headers={"server": "nginx-proxy-manager"},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "detected" in findings[0].title.lower()

    async def test_unknown_version_is_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/api/": MagicMock(
                        status_code=200,
                        text="nginx-proxy-manager login",
                        headers={},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert findings[0].raw["version"] is None

    async def test_no_console_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=MagicMock(status_code=404, text=""))
        step = make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_disabled_config(self, mock_http, mock_target, mock_config):
        mock_config.webapp_mgmt_console_probe = False
        mock_http.request = AsyncMock(return_value=MagicMock(status_code=404))
        step = make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
        mock_http.request.assert_not_called()


class TestCandidateBases:
    def test_primary_only_by_default(self, mock_http, mock_target, mock_config):
        step = make_step(mock_http, mock_target, mock_config)
        bases = step._candidate_bases()
        assert bases == [("https://example.com", {})]

    def test_includes_nmap_http_ports(self, mock_http, mock_target, mock_config):
        from core.scan_context import ScanContext

        step = make_step(mock_http, mock_target, mock_config)
        ctx = ScanContext()
        ctx.set("services", [{"service": "http", "port": 81, "state": "open"}])
        step._ctx = ctx

        bases = step._candidate_bases()
        urls = [b for b, _ in bases]
        assert "http://example.com:81" in urls

    def test_pinned_adds_host_header_for_extra_ports(
        self, mock_http, mock_config
    ):
        from core.scan_context import ScanContext
        from core.target import Target

        target = Target(
            url="https://app.example.com",
            domain="app.example.com",
            connect_ip="10.0.0.5",
        )
        step = ManagementConsoleStep(target=target, config=mock_config, http=mock_http)
        ctx = ScanContext()
        ctx.set("services", [{"service": "http", "port": 81, "state": "open"}])
        step._ctx = ctx

        bases = step._candidate_bases()
        assert ("http://10.0.0.5:81", {"Host": "app.example.com:81"}) in bases
