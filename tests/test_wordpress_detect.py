"""Tests for the WordPress detection gate (utils/wordpress_detect.py).

is_wordpress is imported by value (not through the module attribute) so
these tests exercise the real detector: tests/conftest.py autouse-patches
utils.wordpress_detect.is_wordpress to True for the WP-step suite.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from utils.wordpress_detect import _detected, is_wordpress


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)


def resp(status, text="", headers=None, json_data=None):
    response = MagicMock(
        status_code=status, text=text, headers=HeaderDict(headers or {})
    )
    if json_data is not None:
        response.json = MagicMock(return_value=json_data)
    return response


@pytest.fixture(autouse=True)
def clear_detection_cache():
    _detected.clear()
    yield
    _detected.clear()


class TestIsWordpress:
    async def test_rest_root_with_namespaces(self):
        http = MagicMock()
        http.request = AsyncMock(
            return_value=resp(
                200,
                "",
                {"Content-Type": "application/json"},
                json_data={"namespaces": ["wp/v2"]},
            )
        )
        assert await is_wordpress(http, "https://wp.example") is True
        assert http.request.await_count == 1

    async def test_wp_content_marker_on_homepage(self):
        async def requestor(method, url, **kwargs):
            if url.endswith("/wp-json/"):
                return resp(200, "Not Found")
            return resp(
                200, '<link href="/wp-content/themes/twentytwenty/style.css">'
            )

        http = MagicMock()
        http.request = AsyncMock(side_effect=requestor)
        assert await is_wordpress(http, "https://wp.example") is True

    async def test_generator_meta_marker(self):
        async def requestor(method, url, **kwargs):
            if url.endswith("/wp-json/"):
                return resp(404, "Not Found")
            return resp(
                200, '<meta name="generator" content="WordPress 6.5.2" />'
            )

        http = MagicMock()
        http.request = AsyncMock(side_effect=requestor)
        assert await is_wordpress(http, "https://wp.example") is True

    async def test_non_wordpress_json_without_namespaces(self):
        async def requestor(method, url, **kwargs):
            if url.endswith("/wp-json/"):
                return resp(
                    200,
                    "",
                    {"Content-Type": "application/json"},
                    json_data={"routes": {}},
                )
            return resp(200, "<html><body>App</body></html>")

        http = MagicMock()
        http.request = AsyncMock(side_effect=requestor)
        assert await is_wordpress(http, "https://app.example") is False

    async def test_spa_shell_is_not_wordpress(self):
        http = MagicMock()
        http.request = AsyncMock(
            return_value=resp(
                200,
                "<!doctype html><html><body>SPA shell</body></html>",
                {"Content-Type": "text/html"},
            )
        )
        assert await is_wordpress(http, "https://spa.example") is False

    async def test_fail_closed_on_network_error(self):
        http = MagicMock()
        http.request = AsyncMock(side_effect=ConnectionError("boom"))
        assert await is_wordpress(http, "https://down.example") is False

    async def test_result_is_cached_per_url(self):
        http = MagicMock()
        http.request = AsyncMock(
            return_value=resp(
                200,
                "",
                {"Content-Type": "application/json"},
                json_data={"namespaces": ["wp/v2"]},
            )
        )
        assert await is_wordpress(http, "https://wp.example") is True
        calls = http.request.await_count
        assert await is_wordpress(http, "https://wp.example") is True
        assert http.request.await_count == calls

    async def test_cache_key_ignores_trailing_slash(self):
        http = MagicMock()
        http.request = AsyncMock(
            return_value=resp(
                200,
                "",
                {"Content-Type": "application/json"},
                json_data={"namespaces": ["wp/v2"]},
            )
        )
        assert await is_wordpress(http, "https://wp.example/") is True
        calls = http.request.await_count
        assert await is_wordpress(http, "https://wp.example") is True
        assert http.request.await_count == calls
