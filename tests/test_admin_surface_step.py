"""Tests for AdminSurfaceStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.admin_surface_step import AdminSurfaceStep, extract_title

DEFAULT_PATHS = ["grafana", "actuator/heapdump", "status", "admin"]


def make_step(mock_http, mock_target, mock_config, paths=None):
    mock_config.webapp_max_admin_paths = 40
    step = AdminSurfaceStep(target=mock_target, config=mock_config, http=mock_http)
    step.resolve_wordlist_or_fallback = MagicMock(
        return_value=paths if paths is not None else DEFAULT_PATHS
    )
    return step


def response(status, text=""):
    return MagicMock(status_code=status, text=text)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return response(404, "Not Found")

    return _respond


class TestExtractTitle:
    def test_title(self):
        assert extract_title("<html><head><title>  Grafana </title></head>") == "Grafana"

    def test_no_title(self):
        assert extract_title("<html></html>") == ""


class TestAdminSurfaceStep:
    async def test_exposed_console_medium(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {"grafana": response(200, "<html><title>Grafana</title></html>")}
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "/grafana" in f.title][0]
        assert finding.severity == "medium"
        assert "Grafana" in finding.evidence

    async def test_actuator_heapdump_high(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder({"actuator/heapdump": response(200, "binary-ish")})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "heapdump" in f.title][0]
        assert finding.severity == "high"

    async def test_status_info(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder({"status": response(200, "OK")})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "/status" in f.title][0]
        assert finding.severity == "info"

    async def test_protected_aggregated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "grafana": response(403, "Forbidden"),
                    "admin": response(401, "Unauthorized"),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        finding = [f for f in findings if "behind authentication" in f.title][0]
        assert finding.severity == "info"
        assert "grafana" in finding.raw["paths"]
        assert "admin" in finding.raw["paths"]

    async def test_security_txt_info(self, mock_http, mock_target, mock_config):
        step = make_step(
            mock_http, mock_target, mock_config, paths=[".well-known/security.txt"]
        )
        mock_http.request = AsyncMock(
            side_effect=responder(
                {"security.txt": response(200, "Contact: security@example.com")}
            )
        )
        findings = await step.run()

        finding = [f for f in findings if "security.txt" in f.title][0]
        assert finding.severity == "info"

    async def test_404_ignored(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=response(404, "Not Found"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_wordlist_none_disables(self, mock_http, mock_target, mock_config):
        step = make_step(mock_http, mock_target, mock_config)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=None)
        findings = await step.run()
        assert findings == []
        mock_http.request.assert_not_called()

    async def test_exceptions_tolerated(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
