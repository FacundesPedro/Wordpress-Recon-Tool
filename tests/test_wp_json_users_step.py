"""Tests for WpJsonUsersStep."""

from unittest.mock import AsyncMock, MagicMock

import pytest


pytestmark = pytest.mark.asyncio


MOCK_USERS = [
    {
        "id": 1,
        "name": "Admin User",
        "slug": "admin",
        "email": "admin@example.com",
        "roles": ["administrator"],
        "registered_date": "2024-01-01T00:00:00",
    },
    {
        "id": 2,
        "name": "Editor User",
        "slug": "editor",
        "email": "",
        "roles": ["editor"],
        "registered_date": "2024-01-02T00:00:00",
    },
]


class TestRunSkip:
    """Tests that run() returns early when auth is not configured."""

    async def test_returns_empty_when_no_auth(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = ""
        mock_config.wp_application_password = ""

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_returns_error_finding_on_http_error(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_http.request = AsyncMock(side_effect=Exception("Connection error"))

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.module == "access"
        assert f.severity == "low"
        assert "unavailable" in f.title.lower()


class TestSuccessfulResponse:
    """Tests for 200 response with user data."""

    async def test_user_enumeration_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_USERS))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert len(findings) >= 1
        info = [f for f in findings if f.severity == "info"][0]
        assert info.module == "access"
        assert "User Enumeration" in info.title
        assert info.raw["total"] == 2

    async def test_admin_email_exposure_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=MOCK_USERS))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        email_findings = [f for f in findings if f.severity == "medium"]
        assert len(email_findings) == 1
        assert "Email" in email_findings[0].title
        assert "admin@example.com" in email_findings[0].evidence

    async def test_empty_user_list_returns_no_extra_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=[]))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_non_list_response_no_finding(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value={}))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_parse_error_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(
            status_code=200,
            json=MagicMock(side_effect=ValueError("Invalid JSON")),
        )
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []


class TestAdminEmailExposure:
    """Tests for the admin email exposure edge cases."""

    async def test_no_admin_emails_when_users_have_no_email(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        users_no_email = [
            {
                "id": 1,
                "name": "Admin",
                "slug": "admin",
                "email": "",
                "roles": ["administrator"],
                "registered_date": "2024-01-01T00:00:00",
            },
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=users_no_email))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        medium = [f for f in findings if f.severity == "medium"]
        assert len(medium) == 0

    async def test_no_admin_email_when_no_administrator_role(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        users_no_admin_role = [
            {
                "id": 1,
                "name": "Editor",
                "slug": "editor",
                "email": "editor@example.com",
                "roles": ["editor"],
                "registered_date": "2024-01-01T00:00:00",
            },
        ]
        mock_resp = MagicMock(status_code=200, json=MagicMock(return_value=users_no_admin_role))
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        medium = [f for f in findings if f.severity == "medium"]
        assert len(medium) == 0


class TestFormatUserEvidence:
    """Tests for _format_user_evidence helper."""

    async def test_sorts_by_id(self, mock_http, mock_target, mock_config):
        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        users = [
            {"id": 2, "name": "Beta", "slug": "beta", "roles": ["editor"], "email": ""},
            {"id": 1, "name": "Alpha", "slug": "alpha", "roles": ["administrator"], "email": ""},
        ]
        result = step._format_user_evidence(users)

        lines = result.strip().split("\n")
        assert "#1" in lines[0]
        assert "#2" in lines[1]

    async def test_email_appended_when_present(self, mock_http, mock_target, mock_config):
        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        users = [
            {"id": 1, "name": "Admin", "slug": "admin", "roles": ["administrator"], "email": "admin@test.com"},
        ]
        result = step._format_user_evidence(users)

        assert "admin@test.com" in result

    async def test_roles_formatted(self, mock_http, mock_target, mock_config):
        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        users = [
            {"id": 1, "name": "Admin", "slug": "admin", "roles": ["administrator", "editor"], "email": ""},
        ]
        result = step._format_user_evidence(users)

        assert "administrator, editor" in result


class TestStatusCodeHandling:
    """Tests for non-200 status code responses."""

    async def test_401_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=401)
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []

    async def test_404_returns_empty(self, mock_http, mock_target):
        mock_config = MagicMock()
        mock_config.wp_user = "admin"
        mock_config.wp_application_password = "secret"
        mock_resp = MagicMock(status_code=404)
        mock_http.request = AsyncMock(return_value=mock_resp)

        from steps.access.users_step import WpJsonUsersStep
        step = WpJsonUsersStep(target=mock_target, config=mock_config, http=mock_http)

        findings = await step.run()

        assert findings == []
