"""Tests for CookieFlagsStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.cookie_flags_step import CookieFlagsStep, parse_set_cookie


class HeaderDict:
    """Minimal httpx-like headers supporting get_list/get/items."""

    def __init__(self, data: dict):
        self._data = {}
        for key, value in data.items():
            self._data.setdefault(key.lower(), []).extend(
                value if isinstance(value, list) else [value]
            )

    def get_list(self, key: str):
        return self._data.get(key.lower(), [])

    def get(self, key: str, default=None):
        values = self._data.get(key.lower())
        return values[0] if values else default

    def items(self):
        for key, values in self._data.items():
            for value in values:
                yield key, value


def response(status, headers: dict, text=""):
    return MagicMock(status_code=status, headers=HeaderDict(headers), text=text)


def make_step(mock_http, mock_target, mock_config):
    return CookieFlagsStep(target=mock_target, config=mock_config, http=mock_http)


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return response(404, {})

    return _respond


class TestParseSetCookie:
    def test_full_attributes(self):
        cookie = parse_set_cookie(
            "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"
        )
        assert cookie["name"] == "session"
        assert cookie["secure"] is True
        assert cookie["httponly"] is True
        assert cookie["samesite"] is True

    def test_no_attributes(self):
        cookie = parse_set_cookie("id=xyz")
        assert cookie["name"] == "id"
        assert cookie["secure"] is False
        assert cookie["httponly"] is False
        assert cookie["samesite"] is False

    def test_samesite_strict(self):
        cookie = parse_set_cookie("id=xyz; SameSite=Strict")
        assert cookie["samesite"] is True


class TestCookieFlagsStep:
    async def test_insecure_cookie_flagged(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200, {"set-cookie": "session=abc123; Path=/"}
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        titles = {f.title for f in findings}
        assert "Cookies without HttpOnly flag" in titles
        assert "Cookies without Secure flag" in titles
        assert "Cookies without SameSite attribute" in titles
        assert all(f.severity in ("low", "medium") for f in findings)

    async def test_secure_cookie_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200,
                        {"set-cookie": "session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_multiple_cookies_deduped(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200, {"set-cookie": ["session=abc; Path=/", "pref=dark"]}
                    ),
                    "/login": response(
                        200, {"set-cookie": "session=abc; Path=/"}
                    ),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        httponly = [f for f in findings if "HttpOnly" in f.title]
        assert len(httponly) == 1
        assert "session (/)" in httponly[0].evidence
        assert "pref (/)" in httponly[0].evidence

    async def test_no_cookies_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            side_effect=responder({"/": response(200, {})})
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_http_target_skips_secure_check(self, mock_http, mock_target, mock_config):
        mock_target.url = "http://example.com"
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": response(
                        200,
                        {"set-cookie": "session=abc; Path=/; HttpOnly; SameSite=Lax"},
                    )
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert not any("Secure" in f.title for f in findings)
