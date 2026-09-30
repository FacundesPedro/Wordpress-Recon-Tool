# recon_wp/steps/passive/email_security_step.py
"""
Email security DNS audit - SPF strictness, DMARC policy, DKIM, CAA.

Complements the DNS step by evaluating the *quality* of email-related DNS
records: `_dmarc` policy strength (p=none is weak), SPF existence and
strictness (~all vs -all vs +all), common DKIM selectors, and CAA records
restricting certificate issuance. Uses the system `dig` binary.

Evidence rigor (UPDATE.md C6): a full `dig` response is parsed so "absent"
(NOERROR + 0 answers, or NXDOMAIN) is distinguished from a lookup failure
(SERVFAIL/REFUSED/timeout). A failed lookup is never reported as "no record";
it becomes an operational note. Queries fall back to the zone's authoritative
nameservers, and DMARC is evaluated for the organizational domain (subdomains
inherit it via `sp=`), while SPF is not inherited.
"""

# WHAT: Audits email-security DNS records (SPF/DMARC/DKIM) and CAA
# HOW: full dig TXT/CNAME/CAA queries; status/ANSWER-aware; authoritative NS
# WHY: Weak SPF/DMARC enables direct domain spoofing (phishing)

import re
from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import Config
from core.finding import Finding
from core.target import Target
from utils.dns_query import DigResult, build_dig_command, organizational_domain, parse_dig_output

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
    tokens = lowered.split()
    # `all` with a pass qualifier (bare `all` defaults to `+`). `~all`/`-all`/
    # `?all` are handled below and must not match here.
    if "+all" in tokens or "all" in tokens:
        return {
            "severity": "medium",
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


def analyze_dmarc(records: list[str], is_subdomain: bool = False) -> Optional[dict]:
    """Analyze DMARC record; return issue dict or None when strong/absent.

    For a subdomain inheriting the organizational DMARC record, the subdomain
    policy (`sp=`) takes precedence over `p=`.
    """
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

    value = None
    scope = "p"
    if is_subdomain:
        sub = re.search(r"\bsp=(\w+)", dmarc, re.I)
        if sub:
            value = sub.group(1).lower()
            scope = "sp"
    if value is None:
        policy = re.search(r"\bp=(\w+)", dmarc, re.I)
        value = policy.group(1).lower() if policy else "none"

    if value == "none":
        return {
            "severity": "medium",
            "title": f"DMARC policy is {scope}=none (monitor only)",
            "description": (
                f"DMARC record does not instruct receivers to quarantine or "
                f"reject spoofed mail: {dmarc[:120]}"
            ),
            "recommendation": "Move to p=quarantine then p=reject once reports look clean",
            "raw": {"dmarc": dmarc, "policy": value, "scope": scope},
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
        self._ns_cache: Optional[list[str]] = None

    def build_command(self, query: str = "", record_type: str = "TXT") -> list[str]:
        return build_dig_command(query or "", record_type, timeout=5)

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing email security DNS records...")

        exists, _error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.warning("'dig' binary not found - skipping email security audit")
            return self.findings

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        from utils.domain_utils import is_non_public_domain

        domain = self.target.domain
        if is_non_public_domain(domain):
            self.logger.info(
                f"Email security audit skipped: {domain} is not a public domain"
            )
            return self.findings

        # 1. SPF (never inherited by subdomains)
        txt = await self._query_with_fallback(domain, "TXT")
        if txt.indeterminate:
            self._add_lookup_failure(domain, "TXT", txt)
        else:
            spf_issue = analyze_spf(txt.records)
            if spf_issue:
                self._add_issue(spf_issue, f"TXT {domain} ({txt.evidence})")

        # 2. DMARC, with organizational-domain inheritance (subdomains inherit;
        #    `sp=` overrides `p=` for the subdomain).
        dmarc_name = f"_dmarc.{domain}"
        dmarc = await self._query_with_fallback(dmarc_name, "TXT")
        if dmarc.indeterminate:
            self._add_lookup_failure(dmarc_name, "TXT", dmarc)
        else:
            dmarc_records = dmarc.records
            is_subdomain = False
            evidence = f"TXT {dmarc_name} ({dmarc.evidence})"
            if dmarc.no_record:
                org = organizational_domain(domain)
                if org and org != domain:
                    org_res = await self._query_with_fallback(f"_dmarc.{org}", "TXT")
                    if not org_res.indeterminate and org_res.records:
                        dmarc_records = org_res.records
                        is_subdomain = True
                        evidence = (
                            f"DMARC inherited from _dmarc.{org} "
                            f"({org_res.evidence})"
                        )
            dmarc_issue = analyze_dmarc(dmarc_records, is_subdomain=is_subdomain)
            if dmarc_issue:
                self._add_issue(dmarc_issue, evidence)

        # 3. DKIM selector probes
        await self._check_dkim(domain)

        # 4. CAA
        caa = await self._query_with_fallback(domain, "CAA")
        if caa.indeterminate:
            self._add_lookup_failure(domain, "CAA", caa)
        elif caa.no_record:
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
                f"CAA {domain} ({caa.evidence})",
            )

        self.logger.info(f"Email security audit: {len(self.findings)} finding(s)")
        return self.findings

    # -- DKIM --------------------------------------------------------------

    async def _check_dkim(self, domain: str) -> None:
        selectors = DKIM_SELECTORS[:5]
        indeterminate: list[str] = []
        for selector in selectors:
            result = await self._dig(f"{selector}._domainkey.{domain}", "TXT")
            if result.indeterminate:
                indeterminate.append(selector)
                continue
            if any(
                r.lower().startswith("v=dkim1") or "p=" in r.lower()
                for r in result.records
            ):
                return
        if indeterminate and len(indeterminate) == len(selectors):
            # Every selector lookup failed - do not claim "no DKIM".
            self._add_lookup_failure(
                f"<selector>._domainkey.{domain}", "TXT", None
            )
            return
        self._add_issue(
            {
                "severity": "low",
                "title": "No DKIM record found on common selectors",
                "description": (
                    "Probed common DKIM selectors and found none. "
                    "Unsigned mail is more likely to be flagged/spoofed."
                ),
                "recommendation": "Publish DKIM keys for your mail senders",
                "raw": {"selectors_probed": selectors},
            },
            f"TXT <selector>._domainkey.{domain}",
        )

    # -- helpers -----------------------------------------------------------

    async def _authoritative_ns(self) -> list[str]:
        """Nameservers for the target zone (cached), or [] on failure."""
        if self._ns_cache is not None:
            return self._ns_cache
        self._ns_cache = []
        domain = self.target.domain if self.target else ""
        if not domain:
            return self._ns_cache
        result = await self._dig(domain, "NS")
        if result.no_error:
            self._ns_cache = [
                r.rstrip(".") for r in result.records if r.strip()
            ]
        return self._ns_cache

    async def _query_with_fallback(
        self, name: str, record_type: str = "TXT"
    ) -> DigResult:
        """Run a query, retrying against authoritative NS on failure."""
        result = await self._dig(name, record_type)
        if not result.indeterminate:
            return result
        for ns in await self._authoritative_ns():
            alt = await self._dig(name, record_type, nameserver=ns)
            if not alt.indeterminate:
                return alt
        return result

    async def _dig(
        self, name: str, record_type: str = "TXT", nameserver: Optional[str] = None
    ) -> DigResult:
        """Run ``dig`` and parse the full response (status + answers)."""
        cmd = build_dig_command(
            name, record_type, nameserver=nameserver, timeout=5
        )
        try:
            result = self._tool_runner.run(cmd, timeout=self.DNS_TIMEOUT)
        except Exception as e:
            self.logger.debug(f"dig {record_type} {name} failed: {e}")
            return DigResult(error=True, raw=str(e), nameserver=nameserver or "")
        parsed = parse_dig_output(getattr(result, "stdout", "") or "")
        parsed.nameserver = nameserver or ""
        if (
            not getattr(result, "success", False)
            and not parsed.records
            and not parsed.status
        ):
            parsed.error = True
        return parsed

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

    def _add_lookup_failure(
        self, name: str, record_type: str, result: Optional[DigResult]
    ) -> None:
        detail = result.evidence if result is not None else "no response"
        self._add_finding(
            module=self.MODULE,
            severity="info",
            title=f"DNS lookup failed: {record_type} {name}",
            description=(
                "A DNS lookup for email-security records could not be "
                "completed, so the absence of a finding here is not evidence "
                "of absence. This is an execution note."
            ),
            evidence=detail,
            recommendation=(
                "Re-run when DNS resolution is healthy, or query the zone's "
                "authoritative nameserver directly."
            ),
            raw={"operational": True, "query": name, "type": record_type},
        )

    # BaseToolStep abstract methods (direct execution path)
    def parse_output(self, result: ToolResult) -> list:
        return []
