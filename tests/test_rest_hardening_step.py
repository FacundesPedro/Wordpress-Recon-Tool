"""Tests for RestHardeningStep."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


class TestCheckCors:
    """Tests for _check_cors method."""

    async def test_wildcard_cors_creates_high_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=200, headers={"Access-Control-Allow-Origin": "*"})
        mock_http.get.return_value = mock_resp

        await step._check_cors()

        assert len(step.findings) == 1
        f = step.findings[0]
        assert f.severity == "high"
        assert f.module == "access"
        assert "CORS" in f.title
        assert "*" in f.evidence

    async def test_restricted_cors_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "https://trusted.com"},
        )
        mock_http.get.return_value = mock_resp

        await step._check_cors()

        assert len(step.findings) == 0

    async def test_exception_during_cors_check_handled(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.side_effect = Exception("Timeout")

        await step._check_cors()

        assert len(step.findings) == 0


class TestCheckRouteLeakage:
    """Tests for _check_route_leakage method."""

    async def test_non_wp_namespaces_creates_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        routes = {
            "routes": {
                "wp/v2/posts": {},
                "wp/v2/pages": {},
                "contact-form-7/v1/forms": {},
                "woocommerce/v3/products": {},
            }
        }
        mock_resp = MagicMock(
            status_code=200,
            headers={"content-type": "application/json"},
            text=json.dumps(routes),
            json=MagicMock(return_value=routes),
        )
        mock_http.get.return_value = mock_resp

        await step._check_route_leakage()

        assert len(step.findings) == 1
        f = step.findings[0]
        assert f.severity == "info"
        assert "route leakage" in f.title.lower()
        assert "contact-form-7" in f.evidence
        assert "woocommerce" in f.evidence

    async def test_only_wp_namespace_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        routes = {"routes": {"wp/v2/posts": {}, "wp/v2/pages": {}}}
        mock_resp = MagicMock(
            status_code=200,
            headers={"content-type": "application/json"},
            text=json.dumps(routes),
            json=MagicMock(return_value=routes),
        )
        mock_http.get.return_value = mock_resp

        await step._check_route_leakage()

        assert len(step.findings) == 0

    async def test_non_200_returns_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=403)
        mock_http.get.return_value = mock_resp

        await step._check_route_leakage()

        assert len(step.findings) == 0

    async def test_non_json_response_returns_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=200, json=MagicMock(side_effect=ValueError("Not JSON")))
        mock_http.get.return_value = mock_resp

        await step._check_route_leakage()

        assert len(step.findings) == 0

    async def test_routes_not_a_dict_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"routes": "not_a_dict"}),
        )
        mock_http.get.return_value = mock_resp

        await step._check_route_leakage()

        assert len(step.findings) == 0


class TestCheckUserEndpoint:
    """Tests for _check_user_endpoint method."""

    async def test_200_with_user_list_creates_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        users = [{"id": 1, "name": "admin"}, {"id": 2, "name": "editor"}]
        mock_resp = MagicMock(
            status_code=200,
            headers={"content-type": "application/json"},
            text=json.dumps(users),
            json=MagicMock(return_value=users),
        )
        mock_http.get.return_value = mock_resp

        await step._check_user_endpoint()

        assert len(step.findings) == 1
        f = step.findings[0]
        assert f.severity == "medium"
        assert "User list" in f.title
        assert f.raw["user_count"] == 2

    async def test_200_with_non_list_json_uses_count_one(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        user = {"id": 1, "name": "admin"}
        mock_resp = MagicMock(
            status_code=200,
            headers={"content-type": "application/json"},
            text=json.dumps(user),
            json=MagicMock(return_value=user),
        )
        mock_http.get.return_value = mock_resp

        await step._check_user_endpoint()

        assert len(step.findings) == 1
        assert step.findings[0].raw["user_count"] == 1

    async def test_html_200_not_a_user_list(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.return_value = MagicMock(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<!doctype html><html><body>homepage</body></html>",
        )

        await step._check_user_endpoint()

        assert len(step.findings) == 0

    async def test_plain_permalink_fallback(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        users = [{"id": 1, "name": "admin"}]

        async def requestor(url, **kwargs):
            if "rest_route=" in url:
                return MagicMock(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text=json.dumps(users),
                    json=MagicMock(return_value=users),
                )
            return MagicMock(status_code=200, text="<html>homepage</html>")

        mock_http.get = AsyncMock(side_effect=requestor)

        await step._check_user_endpoint()

        assert len(step.findings) == 1

    async def test_non_200_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=403)
        mock_http.get.return_value = mock_resp

        await step._check_user_endpoint()

        assert len(step.findings) == 0

    async def test_exception_handled(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.side_effect = Exception("Timeout")

        await step._check_user_endpoint()

        assert len(step.findings) == 0


class TestCheckPluginEndpoints:
    """Tests for _check_plugin_endpoints method."""

    async def test_some_endpoints_accessible_creates_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        async def requestor(url, **kwargs):
            if "elementor" in url or "contact-form-7" in url:
                return MagicMock(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    text="[]",
                )
            return MagicMock(
                status_code=404,
                headers={"content-type": "application/json"},
                text='{"code": "rest_no_route"}',
            )

        mock_http.get = AsyncMock(side_effect=requestor)

        await step._check_plugin_endpoints()

        assert len(step.findings) == 1
        f = step.findings[0]
        assert f.severity == "medium"
        assert "Plugin REST API" in f.title
        assert len(f.raw["accessible_endpoints"]) == 2

    async def test_html_shell_not_accessible(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.return_value = MagicMock(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<!doctype html><html><body>homepage</body></html>",
        )

        await step._check_plugin_endpoints()

        assert len(step.findings) == 0

    async def test_no_accessible_endpoints_no_finding(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_resp = MagicMock(status_code=403)
        mock_http.get.return_value = mock_resp

        await step._check_plugin_endpoints()

        assert len(step.findings) == 0

    async def test_exception_on_endpoint_skipped_gracefully(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        mock_http.get.side_effect = Exception("Timeout")

        await step._check_plugin_endpoints()

        assert len(step.findings) == 0


class TestRun:
    """Tests for the full run method."""

    async def test_run_runs_all_four_checks(self, mock_http, mock_target, mock_config):
        from steps.access.rest_hardening_step import RestHardeningStep
        step = RestHardeningStep(target=mock_target, config=mock_config, http=mock_http)

        step._check_cors = AsyncMock()
        step._check_route_leakage = AsyncMock()
        step._check_user_endpoint = AsyncMock()
        step._check_plugin_endpoints = AsyncMock()

        await step.run()

        step._check_cors.assert_called_once()
        step._check_route_leakage.assert_called_once()
        step._check_user_endpoint.assert_called_once()
        step._check_plugin_endpoints.assert_called_once()
