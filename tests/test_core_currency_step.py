"""Tests for CoreCurrencyStep and utils.core_version."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from steps.passive.core_currency_step import (
    CoreCurrencyStep,
    clear_cache,
    parse_version_check,
)
from utils.core_version import detect_core_version


@pytest.fixture(autouse=True)
def _clear():
    clear_cache()
    yield
    clear_cache()


class TestDetectCoreVersion:
    def test_meta_generator(self):
        html = '<meta name="generator" content="WordPress 6.4.2" />'
        assert detect_core_version(html) == ("6.4.2", "meta generator")

    def test_emoji_asset_when_generator_removed(self):
        html = (
            '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.1.2">'
            "</script>"
        )
        version, source = detect_core_version(html)
        assert version == "7.1.2"
        assert "core asset" in source

    def test_block_library_css(self):
        html = (
            '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=6.5" '
            'rel="stylesheet">'
        )
        assert detect_core_version(html)[0] == "6.5"

    def test_theme_asset_is_not_core(self):
        html = '<link href="/wp-content/themes/t/style.css?ver=1.2">'
        assert detect_core_version(html) == (None, None)


class TestParseVersionCheck:
    def test_upgrade_offer(self):
        data = {
            "offers": [
                {
                    "response": "upgrade",
                    "current": "7.1.3",
                    "php_version": "7.4",
                    "download": "https://example/wordpress-7.1.3.zip",
                }
            ]
        }
        offer = parse_version_check(data, "7.1.2")
        assert offer["current"] == "7.1.3"
        assert offer["response"] == "upgrade"

    def test_missing_offers(self):
        assert parse_version_check({}, "7.1.2") is None
        assert parse_version_check({"offers": []}, "7.1.2") is None
        assert parse_version_check({"offers": [{}]}, "7.1.2") is None


def make_step(homepage_text: str, is_wp: bool = True) -> CoreCurrencyStep:
    step = CoreCurrencyStep(
        target=MagicMock(), config=MagicMock(), http=MagicMock()
    )
    ctx = MagicMock()
    ctx.web.wordpress = AsyncMock(return_value=is_wp)
    ctx.web.homepage = AsyncMock(
        return_value=MagicMock(status_code=200, text=homepage_text)
    )
    step._ctx = ctx
    return step


@pytest.mark.asyncio
class TestCoreCurrencyStep:
    async def test_outdated_core_is_medium(self):
        step = make_step(
            '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=7.1.2">'
            "</script>"
        )
        step._fetch_api = AsyncMock(
            return_value={
                "offers": [
                    {
                        "response": "upgrade",
                        "current": "7.1.3",
                        "php_version": "7.4",
                    }
                ]
            }
        )
        findings = await step.run()
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "7.1.2" in findings[0].title and "7.1.3" in findings[0].title
        assert findings[0].raw["installed"] == "7.1.2"
        assert findings[0].raw["latest"] == "7.1.3"

    async def test_current_core_has_no_finding(self):
        step = make_step(
            '<meta name="generator" content="WordPress 7.1.3" />'
        )
        step._fetch_api = AsyncMock(
            return_value={"offers": [{"response": "latest", "current": "7.1.3"}]}
        )
        assert await step.run() == []

    async def test_api_failure_is_operational_info(self):
        step = make_step(
            '<meta name="generator" content="WordPress 7.1.2" />'
        )
        step._fetch_api = AsyncMock(return_value=None)
        findings = await step.run()
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert findings[0].raw["operational"] is True

    async def test_non_wordpress_target_skips(self):
        step = make_step("", is_wp=False)
        step._fetch_api = AsyncMock()
        assert await step.run() == []
        step._fetch_api.assert_not_awaited()

    async def test_version_not_detected_skips(self):
        step = make_step("<html>no version here</html>")
        step._fetch_api = AsyncMock()
        assert await step.run() == []
        step._fetch_api.assert_not_awaited()
