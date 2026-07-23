# tests/test_auth.py
"""Tests for WordPress authentication helpers — App Passwords and AdminSession."""

import base64
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from core.auth import AdminSession, get_wp_auth_header, has_wp_auth


class TestGetWpAuthHeader:
    """Tests for Application Password Authorization header builder."""

    def test_returns_basic_header(self):
        result = get_wp_auth_header("admin", "secret123")
        expected_token = base64.b64encode(b"admin:secret123").decode()
        assert result == {"Authorization": f"Basic {expected_token}"}

    def test_returns_none_when_user_empty(self):
        assert get_wp_auth_header("", "secret123") is None

    def test_returns_none_when_password_empty(self):
        assert get_wp_auth_header("admin", "") is None

    def test_returns_none_when_both_empty(self):
        assert get_wp_auth_header("", "") is None

    def test_returns_none_when_defaults_used(self):
        assert get_wp_auth_header() is None

    def test_strips_whitespace_from_user(self):
        result = get_wp_auth_header("  admin  ", "secret123")
        expected_token = base64.b64encode(b"admin:secret123").decode()
        assert result == {"Authorization": f"Basic {expected_token}"}

    def test_strips_whitespace_from_password(self):
        result = get_wp_auth_header("admin", "  secret123  ")
        expected_token = base64.b64encode(b"admin:secret123").decode()
        assert result == {"Authorization": f"Basic {expected_token}"}

    def test_strips_whitespace_from_both(self):
        result = get_wp_auth_header("  admin  ", "  secret123  ")
        expected_token = base64.b64encode(b"admin:secret123").decode()
        assert result == {"Authorization": f"Basic {expected_token}"}

    def test_special_characters_in_password(self):
        result = get_wp_auth_header("admin", "p@ss/word+123")
        expected_token = base64.b64encode(b"admin:p@ss/word+123").decode()
        assert result == {"Authorization": f"Basic {expected_token}"}

    def test_whitespace_only_user_still_encodes(self):
        result = get_wp_auth_header("   ", "secret123")
        assert result is not None
        assert "Authorization" in result

    def test_whitespace_only_password_still_encodes(self):
        result = get_wp_auth_header("admin", "   ")
        assert result is not None
        assert "Authorization" in result


class TestHasWpAuth:
    """Tests for credential presence check."""

    def test_returns_true_when_both_set(self):
        assert has_wp_auth("admin", "secret") is True

    def test_returns_false_when_user_empty(self):
        assert has_wp_auth("", "secret") is False

    def test_returns_false_when_password_empty(self):
        assert has_wp_auth("admin", "") is False

    def test_returns_false_when_both_empty(self):
        assert has_wp_auth("", "") is False

    def test_returns_false_when_defaults_used(self):
        assert has_wp_auth() is False

    def test_returns_true_with_whitespace(self):
        assert has_wp_auth(" ", " ") is True


class TestAdminSessionInit:
    """Tests for AdminSession initialization."""

    def test_strips_trailing_slash_from_base_url(self):
        mock_http = AsyncMock()
        session = AdminSession(mock_http, "https://example.com/")
        assert session.base_url == "https://example.com"

    def test_preserves_base_url_without_slash(self):
        mock_http = AsyncMock()
        session = AdminSession(mock_http, "https://example.com")
        assert session.base_url == "https://example.com"

    def test_starts_unauthenticated(self):
        mock_http = AsyncMock()
        session = AdminSession(mock_http, "https://example.com")
        assert session.is_authenticated is False

    def test_stores_http_reference(self):
        mock_http = AsyncMock()
        session = AdminSession(mock_http, "https://example.com")
        assert session.http is mock_http


class TestAdminSessionLogin:
    """Tests for AdminSession.login() flow."""

    @pytest.mark.asyncio
    async def test_login_success_via_redirect(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://example.com/wp-admin/"}
        resp.cookies = {}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        result = await session.login("admin", "password123")

        assert result is True
        assert session.is_authenticated is True

    @pytest.mark.asyncio
    async def test_login_success_via_session_cookie(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.cookies = {"wordpress_logged_in_abc123": "token_value"}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        result = await session.login("admin", "password123")

        assert result is True
        assert session.is_authenticated is True

    @pytest.mark.asyncio
    async def test_login_failure_wrong_credentials(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.cookies = {}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        result = await session.login("admin", "wrongpassword")

        assert result is False
        assert session.is_authenticated is False

    @pytest.mark.asyncio
    async def test_login_failure_redirect_not_wp_admin(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://example.com/wp-login.php?error=1"}
        resp.cookies = {}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        result = await session.login("admin", "wrongpassword")

        assert result is False
        assert session.is_authenticated is False

    @pytest.mark.asyncio
    async def test_login_http_error(self):
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        session = AdminSession(mock_http, "https://example.com")
        result = await session.login("admin", "password123")

        assert result is False
        assert session.is_authenticated is False

    @pytest.mark.asyncio
    async def test_login_sends_correct_form_data(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://example.com/wp-admin/"}
        resp.cookies = {}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        await session.login("testuser", "testpass")

        call_kwargs = mock_http.post.call_args
        assert call_kwargs[0][0] == "https://example.com/wp-login.php"
        form_data = call_kwargs[1]["data"]
        assert form_data["log"] == "testuser"
        assert form_data["pwd"] == "testpass"
        assert form_data["wp-submit"] == "Log In"
        assert form_data["redirect_to"] == "https://example.com/wp-admin/"

    @pytest.mark.asyncio
    async def test_login_follow_redirects_disabled(self):
        mock_http = AsyncMock()
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {"location": "https://example.com/wp-admin/"}
        resp.cookies = {}
        mock_http.post = AsyncMock(return_value=resp)

        session = AdminSession(mock_http, "https://example.com")
        await session.login("admin", "password123")

        call_kwargs = mock_http.post.call_args
        assert call_kwargs[1]["follow_redirects"] is False


class TestAdminSessionRequests:
    """Tests for AdminSession.get() and AdminSession.post()."""

    @pytest.mark.asyncio
    async def test_get_builds_correct_url(self):
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.get("wp-admin/site-health-info.php")

        call_args = mock_http.get.call_args
        assert call_args[0][0] == "https://example.com/wp-admin/site-health-info.php"

    @pytest.mark.asyncio
    async def test_get_strips_leading_slash(self):
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.get("/wp-admin/plugins.php")

        call_args = mock_http.get.call_args
        assert call_args[0][0] == "https://example.com/wp-admin/plugins.php"

    @pytest.mark.asyncio
    async def test_get_passes_kwargs(self):
        mock_http = AsyncMock()
        mock_http.get = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.get("wp-admin/", timeout=30)

        call_kwargs = mock_http.get.call_args
        assert call_kwargs[1]["timeout"] == 30

    @pytest.mark.asyncio
    async def test_post_builds_correct_url(self):
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.post("wp-admin/admin-ajax.php", data={"action": "test"})

        call_args = mock_http.post.call_args
        assert call_args[0][0] == "https://example.com/wp-admin/admin-ajax.php"

    @pytest.mark.asyncio
    async def test_post_strips_leading_slash(self):
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.post("/wp-admin/edit.php", data={"title": "test"})

        call_args = mock_http.post.call_args
        assert call_args[0][0] == "https://example.com/wp-admin/edit.php"

    @pytest.mark.asyncio
    async def test_post_passes_data(self):
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.post("wp-admin/", data={"key": "value"})

        call_kwargs = mock_http.post.call_args
        assert call_kwargs[1]["data"] == {"key": "value"}

    @pytest.mark.asyncio
    async def test_post_with_none_data(self):
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=MagicMock())
        session = AdminSession(mock_http, "https://example.com")

        await session.post("wp-admin/")

        call_kwargs = mock_http.post.call_args
        assert call_kwargs[1]["data"] is None
