"""Tests for users module steps."""

from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


class TestAuthorIdStep:
    """Tests for AuthorIdStep — 20 GETs to ?author=N."""

    _AUTHOR_RESP = MagicMock(status_code=200, text="Welcome to my blog")
    _LOGIN_RESP = MagicMock(status_code=200, text="wp-login")
    _404_RESP = MagicMock(status_code=404, text="")

    async def test_author_found(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [self._404_RESP] * 3 + [
            self._AUTHOR_RESP
        ] + [self._404_RESP] * 16

        from steps.users.author_id_step import AuthorIdStep
        step = AuthorIdStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "users"
        assert f.severity == "info"
        assert "Author IDs enumerated" in f.title
        assert "4" in f.evidence

    async def test_redirect_to_login_not_counted(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [self._LOGIN_RESP] + [self._404_RESP] * 19

        from steps.users.author_id_step import AuthorIdStep
        step = AuthorIdStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_multiple_authors_found(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [self._AUTHOR_RESP] * 5 + [self._404_RESP] * 15

        from steps.users.author_id_step import AuthorIdStep
        step = AuthorIdStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "1" in findings[0].evidence
        assert "5" in findings[0].evidence

    async def test_no_authors_found(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [self._404_RESP] * 20

        from steps.users.author_id_step import AuthorIdStep
        step = AuthorIdStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_exception_skips_iteration(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [
            self._AUTHOR_RESP,
            Exception("Connection error"),
        ] + [self._404_RESP] * 18

        from steps.users.author_id_step import AuthorIdStep
        step = AuthorIdStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "1" in findings[0].evidence


class TestLoginVerbosityStep:
    """Tests for LoginVerbosityStep — single GET to wp-login.php."""

    async def test_verbose_incorrect_username(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="ERROR: Incorrect username or password"
        )

        from steps.users.login_verbosity_step import LoginVerbosityStep
        step = LoginVerbosityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "users"
        assert f.severity == "info"
        assert "Login page reveals username validity" in f.title

    async def test_verbose_invalid_username(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="ERROR: Invalid username"
        )

        from steps.users.login_verbosity_step import LoginVerbosityStep
        step = LoginVerbosityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1

    async def test_generic_error_message(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200, text="ERROR: Login failed"
        )

        from steps.users.login_verbosity_step import LoginVerbosityStep
        step = LoginVerbosityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_non_200_status(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(status_code=404, text="")

        from steps.users.login_verbosity_step import LoginVerbosityStep
        step = LoginVerbosityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = Exception("Connection error")

        from steps.users.login_verbosity_step import LoginVerbosityStep
        step = LoginVerbosityStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []


class TestOembedUsersStep:
    """Tests for OembedUsersStep — 10 GETs to oembed/1.0/embed."""

    @staticmethod
    def _oembed_resp(author_name, author_url=""):
        return MagicMock(
            status_code=200,
            json=MagicMock(
                return_value={
                    "author_name": author_name,
                    "author_url": author_url,
                }
            ),
        )

    async def test_author_found(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [self._oembed_resp("admin")] + [
            MagicMock(status_code=404, text="")
        ] * 9

        from steps.users.oembed_users_step import OembedUsersStep
        step = OembedUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "users"
        assert f.severity == "info"
        assert "Users enumerated via oEmbed" in f.title
        assert "admin" in f.evidence

    async def test_multiple_authors_dedup(self, mock_http, mock_target, mock_config):
        resp = self._oembed_resp("admin")
        mock_http.get.side_effect = [resp, resp] + [
            MagicMock(status_code=404, text="")
        ] * 8

        from steps.users.oembed_users_step import OembedUsersStep
        step = OembedUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        assert "admin" in findings[0].evidence

    async def test_no_users_found(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [
            MagicMock(status_code=404, text="")
        ] * 10

        from steps.users.oembed_users_step import OembedUsersStep
        step = OembedUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_json_decode_error_skipped(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.side_effect = ValueError("bad json")
        mock_http.get.side_effect = [mock_resp] + [
            MagicMock(status_code=404, text="")
        ] * 9

        from steps.users.oembed_users_step import OembedUsersStep
        step = OembedUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_exception_skips_iteration(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = [
            self._oembed_resp("admin"),
            Exception("Connection error"),
        ] + [MagicMock(status_code=404, text="")] * 8

        from steps.users.oembed_users_step import OembedUsersStep
        step = OembedUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1


class TestRestApiUsersStep:
    """Tests for RestApiUsersStep — single GET to /wp/v2/users."""

    def _user_list_resp(self, users):
        return MagicMock(status_code=200, json=MagicMock(return_value=users))

    async def test_users_found(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = self._user_list_resp(
            [{"id": 1, "name": "admin", "slug": "admin"}]
        )

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "users"
        assert f.severity == "info"
        assert "Users enumerated via REST API" in f.title
        assert "admin (admin)" in f.evidence

    async def test_empty_user_list(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = self._user_list_resp([])

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_non_list_json(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={"message": "not a list"}),
        )

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_requires_auth(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(status_code=401, text="")

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_endpoint_not_found(self, mock_http, mock_target, mock_config):
        mock_http.get.return_value = MagicMock(status_code=404, text="")

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_json_decode_error(self, mock_http, mock_target, mock_config):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.side_effect = ValueError("bad json")

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        mock_http.get.return_value = mock_resp
        findings = await step.run()

        assert findings == []

    async def test_exception_returns_empty(self, mock_http, mock_target, mock_config):
        mock_http.get.side_effect = Exception("Connection error")

        from steps.users.rest_api_users_step import RestApiUsersStep
        step = RestApiUsersStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []
