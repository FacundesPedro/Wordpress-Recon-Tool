"""Tests for SourceReviewStep and its scanning rules."""

from unittest.mock import AsyncMock, MagicMock

from steps.webapp.source_review_step import (
    SourceReviewStep,
    _is_skip_value,
    _mask_secret,
    scan_for_secrets,
)

# Fake AWS key built by concatenation so the literal never appears in
# source (GitHub push protection flags pattern-matching AWS key literals).
_FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def make_step(mock_http, mock_target, mock_config, fuzz=False):
    mock_config.source_scan_fuzz = fuzz
    mock_config.source_scan_max_js = 10
    mock_config.source_scan_max_bytes = 100000
    step = SourceReviewStep(target=mock_target, config=mock_config, http=mock_http)
    step.resolve_wordlist_or_fallback = MagicMock(return_value=[])
    return step


def responder(routes: dict):
    async def _respond(method, url, **kwargs):
        for suffix, response in routes.items():
            if url.endswith(suffix) or url == suffix:
                return response
        return MagicMock(status_code=404, text="Not Found")

    return _respond


class TestScanForSecrets:
    def test_aws_key_detected(self):
        hits = scan_for_secrets(f'var key = "{_FAKE_AWS_KEY}";', "/app.js")
        rule_ids = {h["rule"]["id"] for h in hits}
        assert "aws-access-key-id" in rule_ids

    def test_github_token_detected(self):
        hits = scan_for_secrets("token: ghp_" + "a" * 36, "/app.js")
        assert any(h["rule"]["id"] == "github-token" for h in hits)

    def test_private_key_detected(self):
        hits = scan_for_secrets(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
            "/leak.txt",
        )
        assert any(h["rule"]["id"] == "private-key" for h in hits)

    def test_jwt_detected(self):
        jwt = "eyJ" + "a" * 20 + "." + "eyJ" + "b" * 20 + "." + "c" * 20
        hits = scan_for_secrets(f"authorization: Bearer {jwt}", "/app.js")
        assert any(h["rule"]["id"] == "jwt" for h in hits)

    def test_db_connection_string(self):
        hits = scan_for_secrets(
            "url: 'postgres://admin:hunter2secret@db.internal:5432/prod'", "/app.js"
        )
        assert any(h["rule"]["id"] == "db-connection-string" for h in hits)

    def test_basic_auth_url(self):
        hits = scan_for_secrets("api: https://user:passw0rd123@api.example.com/v1", "/app.js")
        assert any(h["rule"]["id"] == "basic-auth-url" for h in hits)

    def test_internal_ip(self):
        hits = scan_for_secrets("proxy at 10.0.0.5:8080", "/app.js")
        assert any(h["rule"]["id"] == "internal-ip" for h in hits)

    def test_email_with_image_tld_skipped(self):
        hits = scan_for_secrets("logo@2x.png", "/index.html")
        assert not any(h["rule"]["id"] == "email-address" for h in hits)

    def test_email_detected(self):
        hits = scan_for_secrets("contact admin@example.com for info", "/index.html")
        assert any(h["rule"]["id"] == "email-address" for h in hits)

    def test_openai_key_detected(self):
        key = (
            "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0" * 3 + "a1B2"
            + "T3BlbkFJ" + "Z9" * 37
        )
        hits = scan_for_secrets(f"OPENAI_API_KEY = \"{key}\"", "/app.js")
        assert any(h["rule"]["id"] == "openai-api-key" for h in hits)

    def test_openai_legacy_key_detected(self):
        key = "sk-" + "a1" * 10 + "T3BlbkFJ" + "b2" * 10
        hits = scan_for_secrets(f"key: '{key}'", "/app.js")
        assert any(h["rule"]["id"] == "openai-api-key" for h in hits)

    def test_anthropic_key_detected(self):
        key = "sk-ant-api03-" + "aB3" * 33 + "AA"
        hits = scan_for_secrets(f"ANTHROPIC_KEY=\"{key}\"", "/app.js")
        assert any(h["rule"]["id"] == "anthropic-api-key" for h in hits)

    def test_gitlab_pat_detected(self):
        hits = scan_for_secrets("glpat-" + "x" * 20, "/app.js")
        assert any(h["rule"]["id"] == "gitlab-pat" for h in hits)

    def test_notion_token_detected(self):
        token = "ntn_" + "1" * 11 + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"
        hits = scan_for_secrets(f"notion: '{token}'", "/app.js")
        assert any(h["rule"]["id"] == "notion-api-token" for h in hits)

    def test_telegram_bot_token_detected(self):
        token = "123456789:AA" + "H1b2" * 8 + "H"
        hits = scan_for_secrets(f"bot: {token}", "/app.js")
        assert any(h["rule"]["id"] == "telegram-bot-token" for h in hits)

    def test_discord_webhook_detected(self):
        hits = scan_for_secrets(
            "webhook: https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOp",
            "/app.js",
        )
        assert any(h["rule"]["id"] == "discord-webhook" for h in hits)

    def test_heroku_key_detected(self):
        hits = scan_for_secrets(
            "HEROKU_API_KEY=\"" + "HRKU-AA" + "a1B2c3D4" * 7 + "xy" + "\"", "/app.js"
        )
        assert any(h["rule"]["id"] == "heroku-api-key" for h in hits)

    def test_terraform_token_detected(self):
        token = "abcd1234efgh56.atlasv1." + "Xy9_" * 15 + "ab"
        hits = scan_for_secrets(f"TF_TOKEN = \"{token}\"", "/app.js")
        assert any(h["rule"]["id"] == "terraform-api-token" for h in hits)

    def test_azure_storage_key_detected(self):
        key = "AccountKey=" + "aB3/" * 28 + "=="
        hits = scan_for_secrets(f"connection: '{key}'", "/app.js")
        assert any(h["rule"]["id"] == "azure-storage-account-key" for h in hits)

    def test_aws_secret_requires_secret_context(self):
        hits = scan_for_secrets('var x = aws"ABCdef1234567890ABCdef1234567890ABCdef12"', "/app.js")
        assert not any(h["rule"]["id"] == "aws-secret-access-key" for h in hits)
        hits = scan_for_secrets(
            'AWS_SECRET_ACCESS_KEY: "' + "K7" * 20 + '"', "/app.js"
        )
        assert any(h["rule"]["id"] == "aws-secret-access-key" for h in hits)

    def test_skip_page_rules_for_html(self):
        content = "contact admin@example.com and 10.0.0.5"
        hits = scan_for_secrets(content, "/", skip_page_rules=True)
        ids = {h["rule"]["id"] for h in hits}
        assert "email-address" not in ids
        assert "internal-ip" not in ids
        hits = scan_for_secrets(content, "/app.js", skip_page_rules=False)
        ids = {h["rule"]["id"] for h in hits}
        assert "email-address" in ids
        assert "internal-ip" in ids

    def test_hardcoded_password(self):
        hits = scan_for_secrets('DB_PASSWORD = "Sup3rS3cret!x"', "/config.js")
        assert any(h["rule"]["id"] == "hardcoded-password" for h in hits)

    def test_hardcoded_password_placeholder_skipped(self):
        hits = scan_for_secrets('password = "changeme"', "/config.js")
        assert not any(h["rule"]["id"] == "hardcoded-password" for h in hits)

    def test_empty_content(self):
        assert scan_for_secrets("", "/app.js") == []

    def test_line_numbers(self):
        content = f"line one\nline two\nkey = '{_FAKE_AWS_KEY}'\n"
        hits = scan_for_secrets(content, "/app.js")
        aws = [h for h in hits if h["rule"]["id"] == "aws-access-key-id"]
        assert aws and aws[0]["line"] == 3


class TestMaskingHelpers:
    def test_mask_long(self):
        masked = _mask_secret(_FAKE_AWS_KEY)
        assert masked.startswith("AKIA")
        assert masked.endswith("MNOP")
        assert _FAKE_AWS_KEY not in masked

    def test_mask_short(self):
        assert _mask_secret("short") == "****"

    def test_skip_values(self):
        assert _is_skip_value("changeme")
        assert _is_skip_value("xxxx")
        assert not _is_skip_value("Sup3rS3cret!")


class TestSourceReviewStep:
    async def test_secrets_in_homepage_and_js(self, mock_http, mock_target, mock_config):
        html = (
            "<html><head><script src=\"/static/app.js\"></script></head>"
            "<body><p>contact admin@example.com</p>"
            "<!-- internal: 10.0.0.5 --></body></html>"
        )
        js = (
            f'var awsKey = "{_FAKE_AWS_KEY}";\n'
            "var contact = 'dev@example.com';\n"
            "var proxy = 'http://10.1.2.3:8080';\n"
        )
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/static/app.js": MagicMock(status_code=200, text=js),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()

        rule_ids = {f.raw.get("rule_id") for f in findings}
        assert "aws-access-key-id" in rule_ids
        # email/IP rules still apply to JS, but the homepage copies of them
        # are skipped (owned by ContentLeakStep)
        assert "email-address" in rule_ids
        assert "internal-ip" in rule_ids
        assert not any(f.raw.get("source") == "/" for f in findings)
        aws = [f for f in findings if f.raw.get("rule_id") == "aws-access-key-id"][0]
        assert aws.severity == "critical"
        assert "/static/app.js" in aws.evidence
        assert _FAKE_AWS_KEY not in aws.evidence

    async def test_no_secrets_no_findings(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html><body>clean</body></html>")
        )
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []

    async def test_fuzz_pass_discovered_asset(self, mock_http, mock_target, mock_config):
        html = "<html><body>no scripts</body></html>"
        js = 'apiKey = "sk_live_abcd1234efgh5678";\n'
        mock_http.request = AsyncMock(
            side_effect=responder(
                {
                    "/": MagicMock(status_code=200, text=html),
                    "/bundle.js": MagicMock(status_code=200, text=js),
                }
            )
        )
        step = make_step(mock_http, mock_target, mock_config, fuzz=True)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=["bundle.js"])
        findings = await step.run()
        assert any(f.raw.get("rule_id") == "stripe-key" for f in findings)

    async def test_fuzz_disabled(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<html></html>")
        )
        step = make_step(mock_http, mock_target, mock_config, fuzz=False)
        step.resolve_wordlist_or_fallback = MagicMock(return_value=["bundle.js"])
        await step.run()
        step.resolve_wordlist_or_fallback.assert_not_called()

    async def test_homepage_fetch_failure(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert findings == []
