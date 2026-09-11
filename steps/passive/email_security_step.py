# recon_wp/steps/passive/email_security_step.py
"""
Email security DNS audit - SPF strictness, DMARC policy, DKIM, CAA.

Complements the DNS step by evaluating the *quality* of email-related DNS
records: `_dmarc` policy strength (p=none is weak), SPF existence and
strictness (~all vs -all vs +all), common DKIM selectors, and CAA records
restricting certificate issuance. Uses the system `dig` binary.
"""

# WHAT: Audits email-security DNS records (SPF/DMARC/DKIM) and CAA
# HOW: dig TXT/CNAME queries; policy-strength analysis
# WHY: Weak SPF/DMARC enables direct domain spoofing (phishing)

import re
from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import Config
from core.finding import Finding
from core.target import Target

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "s1", "s2",
    "dkim", "k1", "mail", "smtp", "mandrill", "zoho", "protonmail",
]

CAA_TAGS = ("issue", "issuewild", "iodef")


def analyze_spf(records: list[str]) -> Optional[dict]:
    """Analyze SPF records; return issue dict or None when healthy/absent."""
    spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
    if spf is None:
        return {
            "severity": "medium",
            "title": "No SPF record found",
            "description": (
                "The domain publishes no SPF record. Any host can send "
                "email claiming to be from this domain."
            ),
            "recommendation": "Publish an SPF record listing authorized senders",
            "raw": {},
        }
    lowered = spf.lower()
    if "+all" in lowered or "all" == lowered.split()[-1]:
        return {
            "severity": "high",
            "title": "SPF allows any sender (+all)",
            "description": f"SPF record ends with a permissive all: {spf[:120]}",
            "recommendation": "End SPF with -all (hard fail)",
            "raw": {"spf": spf},
        }
    if "~all" in lowered:
        return {
            "severity": "low",
            "title": "SPF uses soft fail (~all)",
            "description": (
                "SPF ends with ~all (soft fail). Prefer -all (hard fail) "
                "once sender inventory is stable."
            ),
            "recommendation": "Move to -all when no legitimate soft-fail senders remain",
            "raw": {"spf": spf},
        }
    return None


def analyze_dmarc(records: list[str]) -> Optional[dict]:
    """Analyze DMARC record; return issue dict or None when strong/absent."""
    dmarc = next(
        (r for r in records if r.lower().startswith("v=dmarc1")), None
    )
    if dmarc is None:
        return {
            "severity": "medium",
            "title": "No DMARC record found",
            "description": (
                "The domain publishes no DMARC policy. Receivers get no "
                "instruction on handling spoofed mail."
            ),
            "recommendation": "Publish a DMARC record (start at p=quarantine, move to p=reject)",
            "raw": {},
        }
    policy = re.search(r"\bp=(\w+)", dmarc, re.I)
    value = (policy.group(1).lower() if policy else "none")
    if value == "none":
        return {
            "severity": "medium",
            "title": "DMARC policy is p=none (monitor only)",
            "description": (
                f"DMARC record does not instruct receivers to quarantine or "
                f"reject spoofed mail: {dmarc[:120]}"
            ),
            "recommendation": "Move to p=quarantine then p=reject once reports look clean",
            "raw": {"dmarc": dmarc, "policy": value},
        }
    return None


class EmailSecurityStep(BaseToolStep):
    """Audit email-security DNS records (SPF/DMARC/DKIM) and CAA."""

    name = "email_security"
    description = "Audit SPF/DMARC/DKIM/CAA DNS records for spoofing protection"
    severity = "medium"
    MODULE = "passive"
    _tool_binary = "dig"
    DNS_TIMEOUT = 15

    def __init__(
        self,
        target: Optional[Target] = None,
        config: Optional[Config] = None,
        http=None,
    ):
        super().__init__(
            target=target, config=config,
            name=self.name, description=self.description,
        )

    def build_command(self, query: str = "", record_type: str = "TXT") -> list[str]:
        return [
            self._tool_binary, query or "", record_type,
            "+short", "+time=5", "+tries=2",
        ]

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing email security DNS records...")

        exists, _error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.warning("'dig' binary not found - skipping email security audit")
            return self.findings

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        domain = self.target.domain

        # 1. SPF + DMARC via TXT
        txt_records = self._query_txt(domain)
        txt_sub = self._query_txt(f"_dmarc.{domain}")

        spf_issue = analyze_spf(txt_records)
        if spf_issue:
            self._add_issue(spf_issue, f"TXT {domain}")

        # DMARC: check apex TXT then _dmarc subdomain
        all_txt = txt_records + txt_sub
        dmarc_issue = analyze_dmarc(all_txt)
        if dmarc_issue:
            self._add_issue(dmarc_issue, f"TXT _dmarc.{domain}")

        # 2. DKIM selector probes
        dkim_found = False
        for selector in DKIM_SELECTORS[:5]:
            records = self._query_txt(f"{selector}._domainkey.{domain}", "TXT")
            if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
                dkim_found = True
                break
        if not dkim_found:
            self._add_issue(
                {
                    "severity": "low",
                    "title": "No DKIM record found on common selectors",
                    "description": (
                        "Probed common DKIM selectors and found none. "
                        "Unsigned mail is more likely to be flagged/spoofed."
                    ),
                    "recommendation": "Publish DKIM keys for your mail senders",
                    "raw": {"selectors_probed": DKIM_SELECTORS[:5]},
                },
                f"TXT <selector>._domainkey.{domain}",
            )

        # 3. CAA
        caa = self._query_txt(domain, "CAA")
        if not caa:
            self._add_issue(
                {
                    "severity": "low",
                    "title": "No CAA record found",
                    "description": (
                        "No CAA record restricts which certificate "
                        "authorities can issue certificates for this domain."
                    ),
                    "recommendation": "Publish CAA records listing your CAs",
                    "raw": {},
                },
                f"CAA {domain}",
            )

        self.logger.info(f"Email security audit: {len(self.findings)} finding(s)")
        return self.findings

    # -- helpers ----------------------------------------------------------

    def _query_txt(self, query: str, record_type: str = "TXT") -> list[str]:
        """Run a dig query and return non-empty answer lines."""
        try:
            result = self._tool_runner.run(
                self.build_command(query, record_type),
                timeout=self.DNS_TIMEOUT,
            )
        except Exception as e:
            self.logger.debug(f"dig {record_type} {query} failed: {e}")
            return []
        if not result or not result.success:
            return []
        return [
            line.strip().strip('"')
            for line in (result.stdout or "").splitlines()
            if line.strip()
        ]

    def _add_issue(self, issue: dict, evidence: str) -> None:
        self._add_finding(
            module=self.MODULE,
            severity=issue["severity"],
            title=issue["title"],
            description=issue["description"],
            evidence=evidence,
            recommendation=issue["recommendation"],
            raw=issue.get("raw", {}),
        )

    # BaseToolStep abstract methods (direct execution path)
    def parse_output(self, result: ToolResult) -> list:
        return []
