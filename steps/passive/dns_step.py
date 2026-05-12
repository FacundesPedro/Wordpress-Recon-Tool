# recon_wp/steps/passive/dns_step.py
"""
DNS enumeration - queries A, AAAA, MX, TXT, NS, CNAME records.

Analyzes SPF, hosting provider, and email infrastructure.
"""

# WHAT: Queries DNS records and analyzes for intelligence
# HOW: Runs 'dig' for each record type, analyzes TXT for SPF
# WHY: DNS reveals infrastructure, hosting, and email security config

import re
from typing import Literal, Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import Config
from core.finding import Finding
from core.target import Target

HOSTING_PROVIDER_PATTERNS = {
    "Locaweb": ["locaweb.com.br", "locaweb.com"],
    "AWS": ["amazonaws.com", "aws"],
    "Azure": ["azure", "cloudapp.net"],
    "GCP": ["googleusercontent.com", "appspot.com", "cloud.google"],
    "Cloudflare": ["cloudflare", "cdn.cloudflare"],
    "DigitalOcean": ["digitalocean", "dio"],
    "Linode": ["linode", "linodes"],
    "Vultr": ["vultr"],
    "OVH": ["ovh.net", "ovh.com"],
    "GoDaddy": ["godaddy", "secureserver"],
    "Namecheap": ["namecheap", "nstld"],
    "Hostgator": ["hostgator"],
    "Bluehost": ["bluehost"],
    "SiteGround": ["siteground", "sg"],
}

EMAIL_PROVIDER_PATTERNS = {
    "Google Workspace": ["google", "gmail"],
    "Microsoft 365": ["microsoft", "outlook", "office365"],
    "Amazon SES": ["amazonaws.com"],
    "Mailgun": ["mailgun"],
    "SendGrid": ["sendgrid"],
    "Zoho": ["zoho", "zohocrm"],
    "ProtonMail": ["protonmail"],
    "Mailchimp": ["mailchimp"],
}


class DnsStep(BaseToolStep):
    """Enumerate DNS records for the target domain.

    Uses the system 'dig' binary to query various record types.
    Provides intelligence analysis on SPF, hosting providers, and email infrastructure.
    """

    name = "dns"
    description = "DNS record enumeration with intelligence analysis"
    severity = "info"
    MODULE = "passive"
    _tool_binary = "dig"

    DNS_TIMEOUT = 15
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    def __init__(
        self,
        target: Optional[Target] = None,
        config: Optional[Config] = None,
        http=None,
    ):
        super().__init__(
            target=target,
            config=config,
            http=http,
            name=self.name,
            description=self.description,
        )
        self._dns_records: dict = {rt: [] for rt in self.RECORD_TYPES}

    @property
    def getBinary(self) -> str:
        return self._tool_binary

    def build_command(self, record_type: str = "A") -> list[str]:
        if not self.target or not self.target.domain:
            return [self._tool_binary]
        return [
            self._tool_binary,
            self.target.domain,
            record_type,
            "+short",
            "+time=5",
            "+tries=2",
        ]

    async def run(self) -> list[Finding]:
        self.logger.debug("Starting DNS enumeration...")

        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.warning(f"'{self._tool_binary}' binary not found")
            self.logger.warning(
                "Install dig: 'brew install bind' (macOS) or 'apt install dnsutils' (Linux)"
            )
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="DNS check skipped",
                description="The 'dig' binary is not installed on this system",
                evidence=error or "Binary not found in PATH",
                recommendation="Install dig to enable DNS enumeration",
                raw={"binary": self._tool_binary, "error": error},
            )
            return self.findings

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        domain = self.target.domain
        all_findings: list[Finding] = []

        for record_type in self.RECORD_TYPES:
            self.logger.debug(f"Querying {record_type} records for {domain}")
            try:
                result = self._tool_runner.run(
                    self.build_command(record_type), timeout=self.DNS_TIMEOUT
                )
                findings = self.parse_output(result, record_type)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.debug(f"Error querying {record_type}: {e}")

        self._analyze_intelligence(domain, all_findings)

        if not all_findings:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="No DNS records found",
                description="Could not enumerate DNS records for the target domain",
                evidence=f"Domain: {domain}",
                recommendation="Verify the domain exists and DNS is accessible",
                raw={"domain": domain, "record_types_queried": self.RECORD_TYPES},
            )

        self.findings.extend(all_findings)
        return self.findings

    def parse_output(self, result: ToolResult, record_type: str) -> list[Finding]:
        findings = []

        if not result or not result.success:
            return findings

        output = result.stdout.strip()
        if not output:
            return findings

        lines = [line.strip() for line in output.split("\n") if line.strip()]
        if not lines:
            return findings

        valid_results = []
        for line in lines:
            if self._is_valid_result(line):
                valid_results.append(line)

        if valid_results:
            unique_results = list(dict.fromkeys(valid_results))
            self._dns_records[record_type] = unique_results

            evidence = f"Type: {record_type}\n" + "\n".join(unique_results[:10])
            if len(unique_results) > 10:
                evidence += f"\n... and {len(unique_results) - 10} more"

            findings.append(
                Finding(
                    step=self.name,
                    module=self.MODULE,
                    severity="info",
                    title=f"DNS {record_type} Records Found",
                    description=f"Found {len(unique_results)} {record_type} record(s)",
                    evidence=evidence,
                    recommendation=f"Review {record_type} records for infrastructure insights",
                    raw={
                        "record_type": record_type,
                        "records": unique_results,
                        "count": len(unique_results),
                    },
                )
            )
            self.logger.debug(f"Found {len(unique_results)} {record_type} record(s)")

        return findings

    def _analyze_intelligence(self, domain: str, findings: list[Finding]) -> None:
        """Analyze DNS records for intelligence."""
        self._analyze_spf(domain)
        self._analyze_google_verification(domain)
        self._analyze_hosting_provider(domain)
        self._analyze_email_provider(domain)

    def _analyze_spf(self, domain: str) -> None:
        """Analyze SPF records for email security configuration."""
        txt_records = self._dns_records.get("TXT", [])
        spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]

        if not spf_records:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="No SPF Record Found",
                description="Domain lacks SPF record, making it vulnerable to email spoofing",
                evidence=f"Domain: {domain}",
                recommendation="Add an SPF record to prevent email spoofing attacks",
                raw={"domain": domain},
            )
            return

        spf_text = " ".join(spf_records)
        all_records = " ".join(txt_records)

        severity: Literal["info", "low", "medium", "high", "critical"] = "low"

        if "~all" in spf_text.lower():
            severity = "low"
            severity_note = "Softfail (~all) - emails may be rejected"
        elif "-all" in spf_text.lower():
            severity = "info"
            severity_note = "Hard fail (-all) - strict SPF policy"
        else:
            severity = "medium"
            severity_note = "No fail mechanism configured"

        include_count = len(re.findall(r"include:", spf_text, re.IGNORECASE))
        if include_count > 5:
            severity = "medium"

        self._add_finding(
            module=self.MODULE,
            severity=severity,
            title="SPF Configuration Detected",
            description=f"SPF record found. {severity_note}",
            evidence=spf_text[:500],
            recommendation="Ensure SPF policy is correctly configured to prevent spoofing",
            raw={
                "domain": domain,
                "spf_record": spf_records[0] if spf_records else None,
                "include_count": include_count,
                "has_hard_fail": "-all" in spf_text.lower(),
                "has_soft_fail": "~all" in spf_text.lower(),
            },
        )

    def _analyze_google_verification(self, domain: str) -> None:
        """Detect Google site verification records."""
        txt_records = self._dns_records.get("TXT", [])

        google_verification = []
        for txt in txt_records:
            if "google-site-verification" in txt.lower():
                match = re.search(
                    r'google-site-verification=([^\s"]+)', txt, re.IGNORECASE
                )
                if match:
                    google_verification.append(match.group(1))

        if google_verification:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Google Site Verification Detected",
                description="Domain is verified with Google Search Console",
                evidence=f"Verification token(s): {', '.join(google_verification[:3])}",
                recommendation="This indicates the domain is indexed/verified with Google",
                raw={
                    "domain": domain,
                    "verification_tokens": google_verification,
                },
            )

    def _analyze_hosting_provider(self, domain: str) -> None:
        """Detect hosting provider from DNS records."""
        all_records = []
        for records in self._dns_records.values():
            all_records.extend(records)

        all_text = " ".join(all_records).lower()

        detected_providers = []
        for provider, patterns in HOSTING_PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in all_text:
                    if provider not in detected_providers:
                        detected_providers.append(provider)
                    break

        if detected_providers:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Hosting Provider Detected",
                description=f"Infrastructure appears to use: {', '.join(detected_providers)}",
                evidence="Detected from DNS records (A, MX, NS, CNAME)",
                recommendation="Research provider-specific vulnerabilities and configurations",
                raw={
                    "domain": domain,
                    "providers": detected_providers,
                },
            )

    def _analyze_email_provider(self, domain: str) -> None:
        """Detect email service provider from MX records."""
        mx_records = self._dns_records.get("MX", [])

        if not mx_records:
            return

        mx_text = " ".join(mx_records).lower()

        detected_providers = []
        for provider, patterns in EMAIL_PROVIDER_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in mx_text:
                    if provider not in detected_providers:
                        detected_providers.append(provider)
                    break

        if detected_providers:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Email Provider Detected",
                description=f"Email is handled by: {', '.join(detected_providers)}",
                evidence="MX records: " + ", ".join(mx_records[:3]),
                recommendation="Review email security settings (SPF, DKIM, DMARC) for the provider",
                raw={
                    "domain": domain,
                    "email_providers": detected_providers,
                    "mx_records": mx_records,
                },
            )

    def _is_valid_result(self, line: str) -> bool:
        """Filter out error messages and invalid responses."""
        invalid_patterns = [
            "connection timed out",
            "no servers could be reached",
            "connection refused",
            "network unreachable",
            "operation timed out",
            "SERVFAIL",
            "NXDOMAIN",
            "REFUSED",
            "; <<>>",
            "DiG",
        ]
        line_lower = line.lower()
        for pattern in invalid_patterns:
            if pattern.lower() in line_lower:
                return False
        return bool(line)
