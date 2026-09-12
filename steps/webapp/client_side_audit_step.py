# recon_wp/steps/webapp/client_side_audit_step.py
"""
Client-side security audit - static HTML/JS analysis.

Covers WSTG 4.11.1 (DOM-based XSS), 4.11.11 (Web Messaging), 4.11.12 (Browser
Storage), and 4.11.14 (Reverse Tabnabbing): scans fetched HTML/JS for
postMessage wildcard targetOrigins, DOM sinks fed by location sources,
sensitive data written to localStorage, and target="_blank" links without
rel=noopener.
"""

# WHAT: Static client-side audit of HTML/JS for DOM XSS, postMessage,
#       localStorage secrets, and reverse tabnabbing
# HOW: Regex analysis over homepage + bounded JS assets
# WHY: These client-side issues don't require active probing to detect

import re

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.source_discovery import extract_asset_urls, fetch_assets

# postMessage with wildcard targetOrigin
_POSTMESSAGE_WILDCARD_RE = re.compile(
    r"postMessage\s*\([^;]{0,200},\s*[\"']\*[\"']\s*\)"
)
# message listeners
_MESSAGE_LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*[\"']message[\"']"
)
# DOM sinks
_SINK_RE = re.compile(
    r"\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\(|"
    r"insertAdjacentHTML\s*\(|eval\s*\("
)
# location sources feeding sinks
_SOURCE_RE = re.compile(
    r"location\.(?:hash|search|href)|document\.URL|document\.referrer|"
    r"window\.name"
)
# localStorage writes with sensitive-looking keys
_LOCALSTORAGE_RE = re.compile(
    r"localStorage\.setItem\s*\(\s*[\"']([^\"']+)[\"']"
)
_SENSITIVE_KEY_RE = re.compile(
    r"token|password|secret|auth|jwt|session|key|card|ssn", re.I
)
# target=_blank without rel=noopener
_ANCHOR_RE = re.compile(r"<a\b[^>]*>", re.I)

MAX_FINDINGS = 10


def audit_html(html: str) -> list[dict]:
    """Audit raw HTML; return issue dicts."""
    issues: list[dict] = []

    for match in _ANCHOR_RE.findall(html):
        if 'target="_blank"' in match or "target='_blank'" in match \
                or re.search(r"target\s*=\s*[\"']_blank[\"']", match, re.I):
            if not re.search(r"rel\s*=\s*[\"'][^\"']*noopener", match, re.I):
                href = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", match)
                issues.append({
                    "severity": "low",
                    "title": "target=\"_blank\" link without rel=noopener",
                    "description": (
                        "Links opening in a new tab without rel=noopener "
                        "allow the opened page to access window.opener "
                        "(reverse tabnabbing)."
                    ),
                    "evidence": match[:200],
                    "recommendation": "Add rel=\"noopener noreferrer\" to target=\"_blank\" links",
                    "raw": {"href": href.group(1) if href else ""},
                })

    for match in _POSTMESSAGE_WILDCARD_RE.findall(html):
        issues.append({
            "severity": "medium",
            "title": "postMessage with wildcard targetOrigin (*)",
            "description": (
                "Messages are posted with targetOrigin '*', so any window "
                "can receive them - including attacker-controlled frames."
            ),
            "evidence": match[:200],
            "recommendation": "Set an explicit targetOrigin for postMessage",
            "raw": {},
        })

    for match in _LOCALSTORAGE_RE.findall(html):
        if _SENSITIVE_KEY_RE.search(match):
            issues.append({
                "severity": "medium",
                "title": f"Sensitive-looking data written to localStorage ('{match}')",
                "description": (
                    "localStorage is accessible to any script on the page; "
                    "storing tokens/secrets there exposes them to XSS."
                ),
                "evidence": f"localStorage.setItem('{match}', ...)",
                "recommendation": "Keep session tokens in HttpOnly cookies, not web storage",
                "raw": {"key": match},
            })

    return issues


def audit_js(content: str) -> list[dict]:
    """Audit JS content; return issue dicts."""
    issues: list[dict] = []

    for match in _POSTMESSAGE_WILDCARD_RE.findall(content):
        issues.append({
            "severity": "medium",
            "title": "postMessage with wildcard targetOrigin (*)",
            "description": (
                "Messages are posted with targetOrigin '*', so any window "
                "can receive them - including attacker-controlled frames."
            ),
            "evidence": match[:200],
            "recommendation": "Set an explicit targetOrigin for postMessage",
            "raw": {},
        })

    sinks = _SINK_RE.findall(content)
    sources = _SOURCE_RE.findall(content)
    if sinks and sources:
        issues.append({
            "severity": "medium",
            "title": "DOM sink reachable from location-based source",
            "description": (
                "The same script contains DOM sinks (innerHTML/eval/"
                "document.write) and location-derived sources (hash/search/"
                "referrer). This is a DOM-XSS pattern - verify data flow "
                "manually."
            ),
            "evidence": f"sinks: {sorted(set(sinks))[:3]}; "
                        f"sources: {sorted(set(sources))[:3]}",
            "recommendation": (
                "Never assign location-derived data to DOM sinks without "
                "sanitization; prefer textContent"
            ),
            "raw": {"sinks": sorted(set(sinks)), "sources": sorted(set(sources))},
        })

    for match in _LOCALSTORAGE_RE.findall(content):
        if _SENSITIVE_KEY_RE.search(match):
            issues.append({
                "severity": "medium",
                "title": f"Sensitive-looking data written to localStorage ('{match}')",
                "description": (
                    "localStorage is accessible to any script on the page; "
                    "storing tokens/secrets there exposes them to XSS."
                ),
                "evidence": f"localStorage.setItem('{match}', ...)",
                "recommendation": "Keep session tokens in HttpOnly cookies, not web storage",
                "raw": {"key": match},
            })

    if _MESSAGE_LISTENER_RE.search(content) and "origin" not in content:
        issues.append({
            "severity": "low",
            "title": "message listener without origin validation",
            "description": (
                "The script listens for postMessage events but never checks "
                "event.origin - any origin can deliver messages."
            ),
            "evidence": "addEventListener('message', ...) with no origin check",
            "recommendation": "Validate event.origin against an allowlist before acting on messages",
            "raw": {},
        })

    return issues


class ClientSideAuditStep(BaseHttpStep):
    """Static client-side audit (DOM XSS, postMessage, storage, tabnabbing)."""

    name = "client_side_audit"
    description = "Static HTML/JS audit: DOM sinks, postMessage, storage, tabnabbing"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing client-side security (static)...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        html = response.text or ""
        home_url = self.target.url
        issues = []
        for issue in audit_html(html):
            issue = dict(issue)
            issue["source_url"] = home_url
            issues.append(issue)

        try:
            asset_urls = extract_asset_urls(html, self.target.url)
            assets = await fetch_assets(
                self.http, self.target.url, asset_urls,
                max_files=int(getattr(self.config, "source_scan_max_js", 20)),
                max_bytes=int(getattr(self.config, "source_scan_max_bytes", 1000000)),
            )
            for asset_url, content in assets:
                for issue in audit_js(content):
                    issue = dict(issue)
                    issue["source_url"] = asset_url
                    issues.append(issue)
        except Exception as e:
            self.logger.debug(f"JS asset fetch failed: {e}")

        for issue in issues[:MAX_FINDINGS]:
            source_url = issue.get("source_url", self.target.url)
            self._add_finding(
                module=self.MODULE,
                severity=issue["severity"],
                title=issue["title"],
                description=issue["description"],
                evidence=f"{source_url}: {issue['evidence']}",
                recommendation=issue["recommendation"],
                raw={**issue.get("raw", {}), "source_url": source_url},
            )

        if len(issues) > MAX_FINDINGS:
            self.logger.info(
                f"Client-side audit: {len(issues)} issue(s) "
                f"(reporting capped at {MAX_FINDINGS})"
            )
        else:
            self.logger.info(f"Client-side audit: {len(issues)} issue(s)")
        return self.findings
