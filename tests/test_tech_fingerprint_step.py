"""Tests for TechFingerprintStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.tech_fingerprint_step import TechFingerprintStep


class HeaderDict:
    def __init__(self, data: dict):
        self._data = {k.lower(): v for k, v in data.items()}

    def get(self, key, default=None):
        return self._data.get(key.lower(), default)


def resp(headers=None, text=""):
    return MagicMock(status_code=200, headers=HeaderDict(headers or {}), text=text)


class TestTechFingerprintStep:
    async def test_nextjs_detected(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({"X-Powered-By": "Next.js 14"}, "<div>ok</div>")
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Next.js" in f.title for f in findings)

    async def test_django_body_pattern(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({}, '<input name="csrfmiddlewaretoken">')
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Django" in f.title for f in findings)

    async def test_cookie_signature(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({"Set-Cookie": "PHPSESSID=abc"}, "<p>hi</p>")
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("PHP" in f.title for f in findings)

    async def test_wordpress_detected(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({}, '<link href="/wp-content/themes/x/style.css">')
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("WordPress" in f.title for f in findings)

    async def test_unknown_stack_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(return_value=resp({}, "<p>plain</p>"))
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_fetch_failure_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        assert await step.run() == []

    async def test_angular_spa_detected(self, mock_http, mock_target, mock_config):
        html = (
            '<app-root data-beasties-container>'
            '<script src="main.4f3a1b2c.js"></script>'
            '<script src="chunk-AB12CD34.js"></script></app-root>'
        )
        mock_http.request = AsyncMock(return_value=resp({}, html))
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Angular" in f.title for f in findings)

    async def test_tailwind_detected(self, mock_http, mock_target, mock_config):
        html = "<style>@layer theme,base,components,utilities;.x{--tw-ring-color:red}</style>"
        mock_http.request = AsyncMock(return_value=resp({}, html))
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Tailwind" in f.title for f in findings)

    async def test_server_banner_detected(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({"Server": "nginx/1.30.5"}, "<p>x</p>")
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("nginx" in f.title for f in findings)

    async def test_summary_inventory_raw(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=resp({"Server": "nginx/1.30.5"}, "<p>x</p>")
        )
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        summary = [f for f in findings if "component(s)" in f.title]
        assert summary, "expected a machine-readable inventory finding"
        names = [t["name"] for t in summary[0].raw["technologies"]]
        assert "nginx" in names


class TestKeycloakDetection:
    async def test_keycloak_realm_detected(self, mock_http, mock_target, mock_config):
        realm = MagicMock(status_code=200, headers=HeaderDict({}), text="")
        realm.json = MagicMock(
            return_value={
                "realm": "master",
                "public_key": "MIIBIjANBgkq...",
                "token-service": "https://x/auth/realms/master/protocol/openid-connect",
            }
        )

        async def handler(method, url, **kwargs):
            if url.endswith("/auth/realms/master") or url.endswith("/realms/master"):
                return realm
            return resp({}, "<p>plain</p>")

        mock_http.request = AsyncMock(side_effect=handler)
        step = TechFingerprintStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert any("Keycloak" in f.title for f in findings)
