# recon_wp/steps/infrastructure/waf_step.py
"""
WAF detection - checks for Web Application Firewall.

Identifies WAF products protecting the site.
"""

# WHAT: Detects Web Application Firewall in use
# HOW: Checks response headers and cookies for WAF signatures
# WHY: WAF presence affects testing strategy and may block attacks

import json
from pathlib import Path

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding


class WafStep(BaseHttpStep, WordlistDependencyMixin):
    """Detect if a WAF is protecting the WordPress site."""

    name = "waf"
    description = "Detect WAF protection"
    severity = "info"
    MODULE = "infrastructure"

    DEFAULT_WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "akamai": ["akamai", "akamai-ghost", "akamai-x-cache"],
        "incapsula": ["incap", "incapsula"],
        "sucuri": ["sucuri", "cloudproxy"],
        "wordfence": ["wordfence", "wordfence_tag"],
        "siteground": ["siteground", "sg-cache"],
        "aws": ["aws.elb", "aws-waf"],
        "imperva": ["imperva", "incapsula"],
        "modsecurity": ["mod_security", "modsecurity"],
        "f5": ["f5/", "bigip"],
        "fortinet": ["fortiweb", "fortigate", "x-request-id", "fweb"],
        "paloalto": ["x-palo-alto", "x-request-uid", "globalprotect", "pan_"],
        "cisco": ["x-cisco-waas", "x-ace", "x-via: cisco", "cisco"],
        "cloudarmor": ["x-cloud-trace-context", "x-goog-", "google cloud armor"],
        "azure": ["x-azure-ref", "x-waf-action", "x-ms-waf", "azure_applicationgateway"],
    }

    @staticmethod
    def load_waf_signatures_from_file(path: Path) -> dict:
        """Load WAF signatures from a JSON wordlist file."""
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except (OSError, FileNotFoundError, json.JSONDecodeError):
            return {}

    async def run(self) -> list[Finding]:
        self.logger.info("Checking for WAF...")

        waf_signatures = self.resolve_wordlist_or_fallback(
            config_key="waf_signatures",
            defaults=self.DEFAULT_WAF_SIGNATURES,
            name="WAF signatures wordlist",
            loader=self.load_waf_signatures_from_file,
            wordlist_file="infrastructure/waf_signatures.json",
        )
        if not waf_signatures:
            return self.findings

        try:
            response = await self.http.get(self.target.url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            header_str = " ".join(str(v) for v in headers.values()).lower()
            cookies_str = headers.get("set-cookie", "").lower()
            content_str = response.text.lower()

            detected_wafs = []

            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in header_str or sig in cookies_str or sig in content_str:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            self.logger.info(f"Detected WAF: {waf_name}")

            if detected_wafs:
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="WAF detected",
                    description=f"Detected {len(detected_wafs)} WAF(s): {', '.join(detected_wafs)}",
                    evidence=", ".join(detected_wafs),
                    recommendation="WAF is active - ensure legitimate traffic is not blocked",
                    raw={"wafs": detected_wafs},
                )
            else:
                self.logger.debug("No WAF detected")

        except Exception as e:
            self.logger.error(f"Error checking for WAF: {e}")

        return self.findings
