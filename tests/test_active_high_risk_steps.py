"""Tests for RequestSmugglingStep, MassAssignmentStep, RaceConditionStep,
FileUploadStep."""

import json
from unittest.mock import AsyncMock, MagicMock

from steps.active.request_smuggling_step import (
    RequestSmugglingStep,
    build_baseline_payload,
    build_clte_payload,
    build_tecl_payload,
)
from steps.active.mass_assignment_step import MassAssignmentStep
from steps.active.race_condition_step import RaceConditionStep
from steps.active.file_upload_step import FileUploadStep


class TestSmugglingPayloads:
    def test_clte_has_both_headers(self):
        payload = build_clte_payload("example.com").decode()
        assert "Content-Length: 4" in payload
        assert "Transfer-Encoding: chunked" in payload

    def test_tecl_conflict(self):
        payload = build_tecl_payload("example.com").decode()
        assert "Content-Length: 100" in payload

    def test_baseline_get(self):
        assert b"GET /" in build_baseline_payload("example.com")


class TestRequestSmugglingStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True,
                  smuggling=False):
        mock_config.active_enabled = enabled
        mock_config.active_smuggling = smuggling
        mock_config.active_max_requests = 10
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 5
        return RequestSmugglingStep(
            target=mock_target, config=mock_config, http=mock_http
        )

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_disabled_by_smuggling_flag(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config,
                              enabled=True, smuggling=False)
        assert await step.run() == []


class TestMassAssignmentStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True,
                  endpoint=""):
        mock_config.active_enabled = enabled
        mock_config.active_mass_assign_endpoint = endpoint
        mock_config.active_max_requests = 20
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 5
        return MassAssignmentStep(
            target=mock_target, config=mock_config, http=mock_http
        )

    async def test_skips_without_endpoint(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, endpoint="")
        assert await step.run() == []

    async def test_accepted_fields_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            body = json.loads(kwargs.get("content") or "{}")
            if "role" in body or "is_admin" in body or "admin" in body:
                return MagicMock(status_code=201,
                                 text=json.dumps({"role": "administrator"}))
            return MagicMock(status_code=201, text='{"ok": true}')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config,
                              endpoint="/api/register")
        findings = await step.run()
        assert any("mass assignment" in f.title.lower() for f in findings)


class TestRaceConditionStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True,
                  endpoint=""):
        mock_config.active_enabled = enabled
        mock_config.active_race_endpoint = endpoint
        mock_config.active_max_requests = 30
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 5
        return RaceConditionStep(
            target=mock_target, config=mock_config, http=mock_http
        )

    async def test_skips_without_endpoint(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, endpoint="")
        assert await step.run() == []

    async def test_mixed_outcomes_reported(self, mock_http, mock_target, mock_config):
        outcomes = [200, 200, 200, 200, 200, 409, 409, 409, 409, 409]
        idx = {"n": 0}

        async def requestor(method, url, **kwargs):
            status = outcomes[idx["n"] % len(outcomes)]
            idx["n"] += 1
            return MagicMock(status_code=status, text="x")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config,
                              endpoint="/api/coupon")
        findings = await step.run()
        assert any("Mixed outcomes" in f.title for f in findings)


class TestFileUploadStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True,
                  upload=False):
        mock_config.active_enabled = enabled
        mock_config.active_file_upload = upload
        mock_config.active_max_requests = 10
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 5
        return FileUploadStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_disabled_by_upload_flag(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config,
                              enabled=True, upload=False)
        assert await step.run() == []

    async def test_no_upload_forms(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>no forms</p>")
        )
        step = self.make_step(mock_http, mock_target, mock_config,
                              enabled=True, upload=True)
        assert await step.run() == []

    async def test_upload_accepted_reported(self, mock_http, mock_target, mock_config):
        html = ('<form action="/upload" method="POST">'
                '<input type="file" name="file"></form>')

        async def requestor(method, url, **kwargs):
            if method == "POST" and "/upload" in url:
                return MagicMock(status_code=201,
                                 text="https://example.com/uploads/canary.txt")
            if "uploads/" in url and method == "GET":
                return MagicMock(status_code=200, text="recon-canary-marker-7q4")
            return MagicMock(status_code=200, text=html)

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config,
                              enabled=True, upload=True)
        findings = await step.run()
        assert any("publicly accessible" in f.title for f in findings)
