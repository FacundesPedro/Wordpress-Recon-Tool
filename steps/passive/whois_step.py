# recon_wp/steps/passive/whois_step.py
"""
WHOIS enumeration - gathers domain registration information.

Uses the system 'whois' binary to get registrar, dates, nameservers.
"""

# WHAT: Retrieves domain registration info via WHOIS protocol
# HOW: Runs 'whois' binary, parses output for registrar/dates/nameservers
# WHY: Registration info aids OSINT and identifies ownership

from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import Config
from core.finding import Finding
from core.target import Target
from utils.whois_parser import WhoisParser


class WhoisStep(BaseToolStep):
    """Gather WHOIS information for the target domain.

    Uses the system 'whois' binary to enumerate domain registration details.
    Supports wordlist-based field extraction for better coverage.
    """

    name = "whois"
    description = "WHOIS lookup for domain information"
    severity = "info"
    MODULE = "passive"
    _tool_binary = "whois"

    WHOIS_TIMEOUT = 30

    def __init__(
        self,
        target: Optional[Target] = None,
        config: Optional[Config] = None,
        http=None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self._parser = WhoisParser()

    def build_command(self) -> list[str]:
        if not self.target or not self.target.domain:
            return [self._tool_binary]
        return [self._tool_binary, self.target.domain]

    async def run(self) -> list[Finding]:
        self.logger.debug("Starting WHOIS enumeration...")

        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.warning(f"'{self._tool_binary}' binary not found")
            self.logger.warning(
                "Install whois: 'brew install whois' (macOS) or 'apt install whois' (Linux)"
            )
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="WHOIS check skipped",
                description="The 'whois' binary is not installed on this system",
                evidence=error or "Binary not found in PATH",
                recommendation="Install whois to enable domain registration lookups",
                raw={"binary": self._tool_binary, "error": error},
            )
            return self.findings

        if not self.target or not self.target.domain:
            self.logger.warning("No target domain provided")
            return self.findings

        self.logger.debug(f"Running whois for: {self.target.domain}")

        try:
            result = self._tool_runner.run(
                [self._tool_binary, self.target.domain], timeout=self.WHOIS_TIMEOUT
            )

            if result.success:
                self.logger.debug("WHOIS query completed, parsing output...")
                findings = self.parse_output(result)
                self.findings.extend(findings)
            else:
                self.logger.warning(f"WHOIS query failed with code {result.returncode}")
                if result.stderr:
                    self.logger.debug(f"Error output: {result.stderr[:200]}")

        except Exception as e:
            self.logger.error(f"Error running WHOIS: {str(e)}")

        return self.findings

    def parse_output(self, result: ToolResult) -> list[Finding]:
        findings = []

        if not result or not result.stdout:
            self.logger.debug("WHOIS output is empty")
            return findings

        output = result.stdout

        try:
            parsed = self._parser.parse(
                output, self.target.domain if self.target else ""
            )
            finding_data = self._parser.to_finding_dict(parsed)

            if self._parser.using_wordlist:
                self.logger.info(
                    f"WHOIS patterns loaded from {self._parser.get_status_message()}"
                )
            else:
                self.logger.info(
                    f"Wordlist not found, using {self._parser.get_status_message()}"
                )

            description_parts = []
            evidence_parts = []

            if finding_data.get("registrar"):
                description_parts.append(f"Registrar: {finding_data['registrar']}")
                self.logger.debug(f"Found registrar: {finding_data['registrar']}")

            if finding_data.get("creation_date"):
                description_parts.append(f"Created: {finding_data['creation_date']}")
                self.logger.debug("Found creation date")

            if finding_data.get("expiry_date"):
                description_parts.append(f"Expires: {finding_data['expiry_date']}")
                self.logger.debug("Found expiry date")

            if finding_data.get("nameservers"):
                ns_list = finding_data["nameservers"]
                evidence_parts.append(f"Nameservers: {', '.join(ns_list[:5])}")
                if len(ns_list) > 5:
                    evidence_parts.append(f"...and {len(ns_list) - 5} more")
                self.logger.debug(f"Found {len(ns_list)} nameserver(s)")

            if finding_data.get("owner"):
                evidence_parts.append(f"Owner: {finding_data['owner']}")

            if finding_data.get("responsible"):
                evidence_parts.append(f"Responsible: {finding_data['responsible']}")

            if finding_data.get("country"):
                evidence_parts.append(f"Country: {finding_data['country']}")

            if finding_data.get("status"):
                status_list = finding_data["status"]
                evidence_parts.append(f"Status: {', '.join(status_list[:3])}")

            if description_parts or evidence_parts:
                description = (
                    ", ".join(description_parts)
                    if description_parts
                    else "WHOIS information retrieved"
                )
                evidence = (
                    " | ".join(evidence_parts)
                    if evidence_parts
                    else f"Domain: {self.target.domain if self.target else 'unknown'}"
                )

                findings.append(
                    Finding(
                        step=self.name,
                        module=self.MODULE,
                        severity=self.severity,
                        title="WHOIS Information Retrieved",
                        description=description,
                        evidence=evidence,
                        recommendation="Review domain registration details for any concerning information",
                        raw=finding_data,
                    )
                )
                self.logger.debug("WHOIS finding created successfully")
            else:
                self.logger.debug("No data extracted from WHOIS output")

        except Exception as e:
            self.logger.error(f"Error parsing WHOIS output: {str(e)}")

        return findings
