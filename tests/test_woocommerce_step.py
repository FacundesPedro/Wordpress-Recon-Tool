"""Tests for WooCommerceStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.discovery.woocommerce_step import (
    WooCommerceStep,
    extract_version,
    is_json_body,
)


class TestExtractVersion:
    def test_stable_tag(self):
        assert extract_version("Stable tag: 8.2.1") == "8.2.1"

    def test_missing(self):
        assert extract_version("no version here") is None


class TestIsJsonBody:
    def test_json_list(self):
        assert is_json_body(MagicMock(text="[]")) is True

    def test_json_object(self):
        assert is_json_body(MagicMock(text='{"products": []}')) is True

    def test_html_rejected(self):
        assert is_json_body(MagicMock(text="<html>shell</html>")) is False

    def test_empty_rejected(self):
        assert is_json_body(MagicMock(text="")) is False


class TestWooCommerceStep:
    def make_step(self, mock_http, mock_target, mock_config):
        return WooCommerceStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_not_detected(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=404, text="")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_detected_via_store_api(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "wc/store/v1/products" in url:
                return MagicMock(status_code=200, text="[]")
            if "readme.txt" in url:
                return MagicMock(status_code=200, text="Stable tag: 8.2.1")
            if "wc-ajax" in url:
                return MagicMock(status_code=200, text="{}")
            return MagicMock(status_code=200, text="<html>shop</html>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("WooCommerce detected" in f.title for f in findings)
        assert any("version disclosed" in f.title.lower() for f in findings)

    async def test_store_paths_enumerated(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "wc/store" in url:
                return MagicMock(status_code=200, text="[]")
            if any(p in url for p in ("cart/", "checkout/", "my-account/")):
                return MagicMock(status_code=200, text="<html>page</html>")
            return MagicMock(status_code=404, text="nope")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("Store endpoint" in f.title for f in findings)

    async def test_store_api_html_200_not_detected(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "wc/store/v1/products" in url:
                return MagicMock(status_code=200, text="<html>spa shell</html>")
            return MagicMock(status_code=404, text="")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_wc_ajax_html_response_ignored(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            return MagicMock(status_code=200, text="<html>woocommerce shop</html>")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("WooCommerce detected" in f.title for f in findings)
        assert not any("AJAX" in f.title for f in findings)
        assert not any("Store endpoint" in f.title for f in findings)

    async def test_store_paths_soft404_skipped(self, mock_http, mock_target, mock_config):
        shell = "<html><title>Shop</title>homepage shell</html>"

        async def requestor(method, url, **kwargs):
            if "wc/store/v1/products" in url:
                return MagicMock(status_code=200, text="[]")
            return MagicMock(status_code=200, text=shell)

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("WooCommerce detected" in f.title for f in findings)
        assert not any("Store endpoint" in f.title for f in findings)
