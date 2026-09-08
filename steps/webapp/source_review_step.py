# recon_wp/steps/webapp/source_review_step.py
"""
Source code review - scans HTML, JS, and sourcemap content for embedded
credentials and leaked information.

Patterns are derived from gitleaks community rules (adapted to Python re).
"""

# WHAT: Reviews client-side source (HTML/JS/sourcemaps) for secrets and info leaks
# HOW: Fetches homepage, extracts+fuzzes asset URLs, scans content with regex rules
# WHY: Developers frequently hardcode API keys, tokens, and internal addresses in
#      frontend code; exposed sourcemaps leak original (unminified) source

import re

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import (
    extract_asset_urls,
    fetch_assets,
    fuzz_common_assets,
)

MAX_HITS_PER_RULE = 5
MAX_TOTAL_HITS = 60

DEFAULT_ASSET_PATHS = [
    "app.js",
    "bundle.js",
    "main.js",
    "main.min.js",
    "app.min.js",
    "static/js/main.js",
    "static/js/app.js",
    "assets/js/app.js",
    "assets/js/main.js",
    "js/app.js",
    "js/main.js",
    "js/bundle.js",
    "scripts/app.js",
    "build/app.js",
    "dist/app.js",
    "dist/bundle.js",
    "static/app.js",
    "manifest.json",
    "wp-content/themes/twentytwentyfour/style.css",
    "wp-content/themes/twentytwentythree/style.css",
    "wp-includes/js/wp-emoji-release.min.js",
]

SECRET_RULES: list[dict] = [
    {
        "id": "aws-access-key-id",
        "severity": "critical",
        "description": "AWS access key ID",
        "recommendation": "Rotate the exposed key in IAM and remove it from source code",
        "pattern": re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),
    },
    {
        "id": "aws-secret-access-key",
        "severity": "critical",
        "description": "AWS secret access key",
        "recommendation": "Rotate the exposed key in IAM and remove it from source code",
        "pattern": re.compile(
            r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key['\"]?\s*[:=]\s*['\"]?"
            r"[0-9a-zA-Z/]{40}['\"]?"
        ),
    },
    {
        "id": "openai-api-key",
        "severity": "critical",
        "description": "OpenAI API key",
        "recommendation": "Revoke the key in the OpenAI dashboard and remove it from source",
        "pattern": re.compile(
            r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{58,74}T3BlbkFJ[A-Za-z0-9_-]{58,74}\b"
            r"|\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"
        ),
    },
    {
        "id": "anthropic-api-key",
        "severity": "high",
        "description": "Anthropic API key",
        "recommendation": "Revoke the key in the Anthropic console and remove it from source",
        "pattern": re.compile(r"\bsk-ant-(?:api|admin)0[13]-[a-zA-Z0-9_-]{50,110}AA\b"),
    },
    {
        "id": "github-token",
        "severity": "critical",
        "description": "GitHub token",
        "recommendation": "Revoke the token in GitHub settings and purge it from history",
        "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b"),
    },
    {
        "id": "github-fine-grained-pat",
        "severity": "critical",
        "description": "GitHub fine-grained PAT",
        "recommendation": "Revoke the token in GitHub settings and purge it from history",
        "pattern": re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b"),
    },
    {
        "id": "private-key",
        "severity": "critical",
        "description": "Private key block (PEM)",
        "recommendation": "Remove the private key from public source and rotate the certificate",
        "pattern": re.compile(r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
    },
    {
        "id": "db-connection-string",
        "severity": "critical",
        "description": "Database connection string with credentials",
        "recommendation": (
            "Remove the connection string from client-side code "
            "and rotate the credentials"
        ),
        "pattern": re.compile(
            r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)"
            r"://[^\s/:@]{3,64}:[^\s/:@]{3,64}@"
        ),
    },
    {
        "id": "slack-token",
        "severity": "high",
        "description": "Slack token",
        "recommendation": "Revoke the token in the Slack app settings and remove it from source",
        "pattern": re.compile(r"\bxox[abepst]-[0-9A-Za-z-]{10,}\b"),
    },
    {
        "id": "slack-webhook",
        "severity": "high",
        "description": "Slack webhook URL",
        "recommendation": "Disable the webhook in Slack and remove the URL from source",
        "pattern": re.compile(
            r"hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{10,}"
        ),
    },
    {
        "id": "gcp-api-key",
        "severity": "high",
        "description": "Google API key",
        "recommendation": "Restrict or rotate the key in Google Cloud Console",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    },
    {
        "id": "stripe-key",
        "severity": "high",
        "description": "Stripe API key",
        "recommendation": "Roll the key in the Stripe dashboard and remove it from source",
        "pattern": re.compile(r"\b(?:sk|rk)_(?:test|live|prod)_[0-9a-zA-Z]{10,}\b"),
    },
    {
        "id": "twilio-api-key",
        "severity": "high",
        "description": "Twilio API key",
        "recommendation": "Rotate the key in the Twilio console and remove it from source",
        "pattern": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    },
    {
        "id": "sendgrid-api-key",
        "severity": "high",
        "description": "SendGrid API key",
        "recommendation": "Recreate the key in SendGrid and remove it from source",
        "pattern": re.compile(r"\bSG\.[0-9A-Za-z=_\-]{16,64}\.[0-9A-Za-z=_\-]{16,64}\b"),
    },
    {
        "id": "npm-token",
        "severity": "high",
        "description": "npm access token",
        "recommendation": "Revoke the token (npm token revoke) and remove it from source",
        "pattern": re.compile(r"\bnpm_[0-9a-zA-Z]{36}\b"),
    },
    {
        "id": "huggingface-token",
        "severity": "high",
        "description": "Hugging Face token",
        "recommendation": "Revoke the token in Hugging Face settings",
        "pattern": re.compile(r"\bhf_[0-9a-zA-Z]{34}\b"),
    },
    {
        "id": "mailgun-key",
        "severity": "high",
        "description": "Mailgun API key",
        "recommendation": "Regenerate the key in the Mailgun control panel",
        "pattern": re.compile(r"\b(?:key|pubkey)-[0-9a-f]{32}\b"),
    },
    {
        "id": "gitlab-pat",
        "severity": "high",
        "description": "GitLab personal access token",
        "recommendation": "Revoke the token in GitLab user settings and remove it from source",
        "pattern": re.compile(r"\bglpat-[0-9A-Za-z_-]{20}\b"),
    },
    {
        "id": "notion-api-token",
        "severity": "high",
        "description": "Notion API token",
        "recommendation": "Revoke the token in Notion integrations and remove it from source",
        "pattern": re.compile(r"\bntn_[0-9]{11}[0-9A-Za-z]{35}\b"),
    },
    {
        "id": "telegram-bot-token",
        "severity": "high",
        "description": "Telegram bot API token",
        "recommendation": "Revoke the token via the BotFather and remove it from source",
        "pattern": re.compile(r"\b[0-9]{8,10}:AA[0-9a-zA-Z_-]{33}\b"),
    },
    {
        "id": "discord-webhook",
        "severity": "high",
        "description": "Discord webhook URL",
        "recommendation": "Delete the webhook in Discord and remove the URL from source",
        "pattern": re.compile(r"discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
    },
    {
        "id": "heroku-api-key",
        "severity": "high",
        "description": "Heroku API key",
        "recommendation": "Rotate the API key in the Heroku dashboard and remove it from source",
        "pattern": re.compile(r"\bHRKU-AA[0-9A-Za-z_-]{58}\b"),
    },
    {
        "id": "terraform-api-token",
        "severity": "high",
        "description": "HashiCorp Terraform API token",
        "recommendation": "Rotate the token in HashiCorp and remove it from source",
        "pattern": re.compile(r"\b[0-9a-z]{14}\.atlasv1\.[0-9A-Za-z_\-]{60,70}\b"),
    },
    {
        "id": "azure-storage-account-key",
        "severity": "high",
        "description": "Azure storage account key",
        "recommendation": (
            "Rotate the storage account keys in the Azure portal "
            "and remove them from source"
        ),
        "pattern": re.compile(r"(?i)\baccountkey\s*[:=]\s*[0-9a-zA-Z+/]{80,90}={0,2}\b"),
    },
    {
        "id": "basic-auth-url",
        "severity": "high",
        "description": "Credentials embedded in a URL",
        "recommendation": (
            "Remove embedded credentials from the URL "
            "and rotate the account password"
        ),
        "pattern": re.compile(r"\b[a-z][a-z0-9+.-]{1,9}://[^\s/:@]{3,32}:[^\s/:@]{3,32}@"),
    },
    {
        "id": "jwt",
        "severity": "medium",
        "description": "JSON Web Token",
        "recommendation": (
            "Review the embedded JWT; short-lived or static tokens "
            "in client code are a risk"
        ),
        "pattern": re.compile(r"\beyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{5,}"),
    },
    {
        "id": "hardcoded-password",
        "severity": "medium",
        "description": "Hardcoded password in source",
        "recommendation": "Move credentials to server-side configuration and rotate the password",
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|pwd|db_password|client_secret|api_secret)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9!@#$%^&*._-]{8,})"
        ),
    },
    {
        "id": "cloud-metadata-ip",
        "severity": "medium",
        "description": "Cloud metadata endpoint reference",
        "recommendation": "Remove references to cloud metadata endpoints from client code",
        "pattern": re.compile(r"\b169\.254\.169\.254\b"),
    },
    {
        "id": "internal-ip",
        "severity": "low",
        "description": "Internal IP address in source",
        "recommendation": "Avoid exposing internal network addresses in client-side code",
        "pattern": re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
    },
    {
        "id": "email-address",
        "severity": "info",
        "description": "Email address in source",
        "recommendation": "Review whether staff email addresses should be public",
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    },
]

# Rules that only apply to code sources (JS/CSS/maps) — page-level rules for
# HTML are owned by ContentLeakStep to avoid duplicate findings.
_PAGE_ONLY_RULES = {"email-address", "internal-ip"}

_SKIP_PASSWORD_VALUES = {
    "yourpassword", "your_password", "password", "passwd", "changeme", "change_me",
    "xxx", "xxxx", "example", "placeholder", "123456", "12345678", "123456789",
    "1234567890", "admin", "test", "secret", "none", "null", "true", "false",
    "undefined", "redacted", "abc123", "qwerty", "letmein", "passw0rd",
}

_EMAIL_SKIP_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff",
    "woff2", "ttf", "eot", "mp4", "webm", "json", "html", "xml", "txt", "map",
}


def _mask_secret(value: str) -> str:
    """Partially mask a secret for safe display in evidence."""
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def _is_skip_value(value: str) -> bool:
    """Filter placeholder-like values for the hardcoded-password rule."""
    lowered = value.lower()
    if lowered in _SKIP_PASSWORD_VALUES:
        return True
    return len(set(value)) <= 1


def scan_for_secrets(content: str, source: str, skip_page_rules: bool = False) -> list[dict]:
    """Scan content with all secret/info-leak rules.

    Args:
        content: Text content to scan
        source: Human-readable source identifier (URL or path)
        skip_page_rules: When True, skip HTML-page-level rules (email, internal
            IP) that are owned by ContentLeakStep

    Returns:
        List of hit dicts: rule, value, masked, line
    """
    if not content:
        return []

    hits: list[dict] = []
    for rule in SECRET_RULES:
        if skip_page_rules and rule["id"] in _PAGE_ONLY_RULES:
            continue
        found = 0
        for match in rule["pattern"].finditer(content):
            if found >= MAX_HITS_PER_RULE:
                break
            if rule["id"] == "hardcoded-password":
                value = match.group(1)
                if _is_skip_value(value):
                    continue
            elif rule["id"] == "email-address":
                value = match.group(0)
                tld = value.rsplit(".", 1)[-1].lower()
                if tld in _EMAIL_SKIP_TLDS:
                    continue
            else:
                value = match.group(0)
            hits.append(
                {
                    "rule": rule,
                    "value": value,
                    "masked": _mask_secret(value),
                    "line": content.count("\n", 0, match.start()) + 1,
                }
            )
            found += 1
    return hits


class SourceReviewStep(BaseHttpStep, WordlistDependencyMixin):
    """Review HTML/JS/sourcemap source for embedded credentials and leaks."""

    name = "source_review"
    description = "Review HTML/JS source for embedded credentials and leaked information"
    severity = "critical"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Reviewing HTML/JS source for credentials and leaks...")

        base_url = self.target.url
        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Failed to fetch homepage: {e}")
            return self.findings

        html = getattr(response, "text", "") or ""
        sources: list[tuple[str, str]] = [("/", html)]

        asset_urls = extract_asset_urls(html, base_url)
        if asset_urls:
            self.logger.debug(f"Extracted {len(asset_urls)} asset URL(s) from HTML")

        if getattr(self.config, "source_scan_fuzz", True):
            fuzz_paths = self.resolve_wordlist_or_fallback(
                config_key="source_assets",
                defaults=DEFAULT_ASSET_PATHS,
                name="asset path wordlist",
                wordlist_file="webapp/assets.txt",
            )
            if fuzz_paths:
                found = await fuzz_common_assets(
                    self.http, base_url, fuzz_paths, max_probes=60
                )
                self.logger.debug(f"Fuzz pass found {len(found)} extra asset(s)")
                asset_urls.extend(found)

        max_js = getattr(self.config, "source_scan_max_js", 20)
        max_bytes = getattr(self.config, "source_scan_max_bytes", 1000000)
        assets = await fetch_assets(
            self.http, base_url, asset_urls, max_files=max_js, max_bytes=max_bytes
        )
        for url, text in assets:
            from urllib.parse import urlsplit

            sources.append((urlsplit(url).path or url, text))

        hits = 0
        for source_name, content in sources:
            # HTML pages are covered by ContentLeakStep for email/IP rules
            skip_page_rules = source_name == "/"
            for hit in scan_for_secrets(content, source_name, skip_page_rules):
                if hits >= MAX_TOTAL_HITS:
                    break
                self._add_finding(
                    module=self.MODULE,
                    severity=hit["rule"]["severity"],
                    title=f"{hit['rule']['description']} in {source_name}",
                    description=(
                        f"{hit['rule']['description']} detected at line {hit['line']} "
                        f"of {source_name}"
                    ),
                    evidence=f"{source_name}:{hit['line']}: {hit['masked']}",
                    recommendation=hit["rule"]["recommendation"],
                    raw={
                        "rule_id": hit["rule"]["id"],
                        "source": source_name,
                        "line": hit["line"],
                        "masked": hit["masked"],
                        "value": hit["value"],
                    },
                )
                hits += 1
            if hits >= MAX_TOTAL_HITS:
                break

        if hits:
            self.logger.info(f"Source review: {hits} potential secret/leak hit(s)")
        else:
            self.logger.info("Source review: no secrets detected")

        return self.findings
