"""Tests for HeadersStep multi-backend variance reporting (hml A5)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from config import ScanConfig
from steps.infrastructure.headers_step import HeadersStep


def make_step(tmp_path, node_headers, security_headers=None):
    config = ScanConfig(output_dir=tmp_path, headers_multi_node=True)
    if security_headers is not None:
        config.security_headers = security_headers
    step = HeadersStep(target=MagicMock(), config=config, http=MagicMock())
    ctx = MagicMock()
    ctx.web.homepage = AsyncMock(
        return_value=MagicMock(
            status_code=200,
            headers=MagicMock(items=lambda: [("x-frame-options", "DENY")]),
        )
    )
    step._ctx = ctx
    step._resolve_ips = AsyncMock(return_value=list(node_headers))
    step._fetch_node_headers = AsyncMock(side_effect=node_headers.get)
    return step


class TestSingleNode:
    @pytest.mark.asyncio
    async def test_missing_headers_reported(self, tmp_path):
        config = ScanConfig(output_dir=tmp_path)
        step = HeadersStep(
            target=MagicMock(), config=config, http=MagicMock()
        )
        ctx = MagicMock()
        ctx.web.homepage = AsyncMock(
            return_value=MagicMock(
                status_code=200,
                headers=MagicMock(
                    items=lambda: [("x-frame-options", "DENY")]
                ),
            )
        )
        step._ctx = ctx
        step._resolve_ips = AsyncMock(return_value=["10.0.0.1"])
        findings = await step.run()
        assert len(findings) == 1
        assert findings[0].title == "Missing security headers"
        assert "Content-Security-Policy" in findings[0].raw["missing"]


class TestMultiNode:
    @pytest.mark.asyncio
    async def test_variance_reported_not_global_missing(self, tmp_path):
        node_headers = {
            "10.0.0.1": {"x-frame-options": "DENY"},
            "10.0.0.2": {
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
            },
        }
        step = make_step(tmp_path, node_headers)
        findings = await step.run()

        titles = [f.title for f in findings]
        assert "Security headers differ between backend nodes" in titles
        # Global-missing findings must not include headers that node .2 sends.
        global_findings = [
            f for f in findings if "all backend nodes" in f.title
        ]
        for finding in global_findings:
            assert "Content-Security-Policy" not in finding.raw["missing"]
            assert "Strict-Transport-Security" not in finding.raw["missing"]

        variance = next(
            f for f in findings if "differ" in f.title
        )
        assert variance.severity == "info"
        assert "10.0.0.1" in variance.evidence
        assert "Content-Security-Policy" in variance.evidence
        assert variance.raw["nodes"] == ["10.0.0.1", "10.0.0.2"]

    @pytest.mark.asyncio
    async def test_all_nodes_missing_reported_once(self, tmp_path):
        node_headers = {
            "10.0.0.1": {"x-frame-options": "DENY"},
            "10.0.0.2": {"x-frame-options": "DENY"},
        }
        step = make_step(tmp_path, node_headers)
        findings = await step.run()
        global_findings = [
            f for f in findings if "all backend nodes" in f.title
        ]
        assert len(global_findings) == 1
        assert "Content-Security-Policy" in global_findings[0].raw["missing"]
        assert not [f for f in findings if "differ" in f.title]

    @pytest.mark.asyncio
    async def test_unreachable_nodes_fall_back_to_single(self, tmp_path):
        step = make_step(
            tmp_path,
            {
                "10.0.0.1": None,
                "10.0.0.2": None,
            },
        )
        findings = await step.run()
        assert [f.title for f in findings] == ["Missing security headers"]
