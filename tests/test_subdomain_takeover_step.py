"""Tests for SubdomainTakeoverStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.passive.subdomain_takeover_step import (
    SubdomainTakeoverStep,
    match_fingerprint,
    match_nxdomain,
    parse_dig_cname,
)

FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": r"\.github\.io$",
     "fingerprint": "There isn't a GitHub Pages site here.", "status": "vulnerable"},
    {"service": "AWS S3", "cname": r"\.s3\.amazonaws\.com$",
     "fingerprint": "NoSuchBucket", "status": "vulnerable"},
    {"service": "Azure", "cname": r"\.azurewebsites\.net$",
     "fingerprint": "NXDOMAIN", "status": "vulnerable"},
]


class TestParseDigCname:
    def test_short_output(self):
        assert parse_dig_cname("foo.github.io.\n") == "foo.github.io"

    def test_full_row(self):
        assert parse_dig_cname("sub.example.com. 300 IN CNAME target.github.io.") \
            == "target.github.io"

    def test_no_cname(self):
        assert parse_dig_cname("93.184.216.34") is None
        assert parse_dig_cname("") is None


class TestMatchFingerprint:
    def test_cname_and_body_match(self):
        entry = match_fingerprint(
            "lost.github.io", "There isn't a GitHub Pages site here.", FINGERPRINTS
        )
        assert entry and entry["service"] == "GitHub Pages"

    def test_no_match_wrong_body(self):
        assert match_fingerprint("lost.github.io", "<html>fine</html>", FINGERPRINTS) is None

    def test_no_match_wrong_cname(self):
        assert match_fingerprint(
            "lost.other.com", "There isn't a GitHub Pages site here.", FINGERPRINTS
        ) is None

    def test_not_vulnerable_skipped(self):
        fps = FINGERPRINTS + [{"service": "Safe", "cname": r"\.safe\.com$",
                               "fingerprint": "x", "status": "not-vulnerable"}]
        assert match_fingerprint("a.safe.com", "x here", fps) is None


class TestMatchNxdomain:
    def test_nxdomain_match(self):
        entry = match_nxdomain("lost.azurewebsites.net", FINGERPRINTS)
        assert entry and entry["service"] == "Azure"

    def test_no_match(self):
        assert match_nxdomain("lost.other.com", FINGERPRINTS) is None


class TestSubdomainTakeoverStep:
    def make_step(self, mock_http, mock_target, mock_config):
        mock_config.takeover_max_subdomains = 5
        mock_target.domain = "example.com"
        return SubdomainTakeoverStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_no_subdomains(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="[]")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_crtsh_failure_clean(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(side_effect=ConnectionError("down"))
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_dangling_reported(self, mock_http, mock_target, mock_config):
        crt = [{"name_value": "lost.example.com\nexample.com"}]

        async def requestor(method, url, **kwargs):
            if "crt.sh" in url:
                import json
                return MagicMock(status_code=200, text=json.dumps(crt))
            return MagicMock(status_code=404, text="There isn't a GitHub Pages site here.")

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        # patch dig to return a github.io CNAME
        async def fake_dig(sub):
            return "lost.github.io" if "lost" in sub else None
        step._dig_cname = fake_dig
        findings = await step.run()
        assert any("takeover" in f.title.lower() for f in findings)
