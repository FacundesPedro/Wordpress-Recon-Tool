# recon_wp/steps/tools/wpscan_step.py
"""
WPScan integration - comprehensive WordPress vulnerability scanner.

WPScan is a black-box WordPress security scanner that checks for known
vulnerabilities in WordPress core, plugins, and themes using a continuously
updated vulnerability database.
"""

# WHAT: Runs WPScan CLI tool for comprehensive WordPress vulnerability scanning
# HOW: Invokes wpscan binary, parses JSON output into structured findings
# WHY: Provides CVE-based vulnerability detection for WP core, plugins, themes

import json
import shutil
from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.finding import Finding
from core.target import Target


class WpscanStep(BaseToolStep):
    """
    WPScan wrapper for WordPress vulnerability enumeration.

    SECURITY:
    - Verifies wpscan binary exists before execution
    - Uses shell=False to prevent injection
    - Parses JSON output safely
    - Respects API token for vulnerability database access

    CAPABILITIES:
    - WordPress version detection + CVE mapping
    - Plugin enumeration + vulnerability detection
    - Theme enumeration + vulnerability detection
    - User enumeration
    - Config backup discovery
    - Timthumbs (image resizing vulnerabilities)
    """

    name = "wpscan"
    description = "WPScan vulnerability scanner for WordPress"
    severity = "info"
    _tool_binary = "wpscan"
    MODULE = "tools"

    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        http=None,  # Accepted for BaseToolStep compatibility
        api_token: Optional[str] = None,
        enumerate: Optional[str] = None,
        timeout: int = 600,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.api_token = api_token or getattr(config, "wpscan_api_token", None)
        self.enumerate = enumerate or "vp,vt,tt,cb,u"
        self.timeout = timeout
        self._binary_path = shutil.which(self._tool_binary) or self._tool_binary

    def build_command(self) -> list[str]:
        """Build WPScan command with all options."""
        cmd = [self._tool_binary, "--url", str(self.target.url)]

        cmd.extend(["--format", "json"])

        if self.api_token:
            cmd.extend(["--api-token", self.api_token])
        else:
            self.logger.warning(
                "No WPScan API token - vulnerability data may be incomplete. "
                "Get a free token at https://wpscan.com/profile"
            )

        cmd.extend(["--enumerate", self.enumerate])

        cmd.extend(["--random-user-agent"])

        if getattr(self.config, "insecure", False):
            cmd.append("--disable-tls-checks")

        if getattr(self.config, "quiet", False):
            cmd.append("--quiet")

        return cmd

    def parse_output(self, result: ToolResult) -> list[Finding]:
        """Parse WPScan JSON output into findings."""
        findings = []

        if not result.stdout:
            if result.stderr:
                self.logger.debug(f"WPScan stderr: {result.stderr[:500]}")
            return findings

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse WPScan JSON: {e}")
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="low",
                    title="WPScan Output Parse Error",
                    description="Failed to parse WPScan JSON output",
                    evidence=str(e),
                    recommendation="Check WPScan installation and output format",
                    raw={"stderr": result.stderr[:500] if result.stderr else ""},
                )
            )
            return findings

        findings.extend(self._parse_version(data))
        findings.extend(self._parse_plugins(data))
        findings.extend(self._parse_themes(data))
        findings.extend(self._parse_users(data))
        findings.extend(self._parse_config_backups(data))
        findings.extend(self._parse_timthumbs(data))

        if not findings:
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title="WPScan Completed",
                    description="WPScan completed without notable findings",
                    evidence=f"Target: {self.target.url}",
                    recommendation="Manual review of WPScan output may reveal additional details",
                    raw=data,
                )
            )

        return findings

    def _parse_version(self, data: dict) -> list[Finding]:
        """Extract WordPress version and vulnerabilities."""
        findings = []
        version_data = data.get("version", {})

        if not version_data:
            return findings

        version = version_data.get("number", "unknown")
        vulnerabilites = version_data.get("vulnerabilities", [])

        if version != "unknown":
            if vulnerabilites:
                vuln_titles = ', '.join(v.get('title', '') for v in vulnerabilites[:3])
                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="high",
                    title=f"WordPress {version} - Vulnerable",
                    description=f"WordPress {version} has {len(vulnerabilites)} known vulnerabilities",
                    evidence=f"Version: {version}",
                    recommendation=f"Upgrade WordPress immediately. Vulnerabilities: {vuln_titles}",
                    raw={"version": version, "vulnerabilities": vulnerabilites},
                )
            else:
                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"WordPress Version Detected: {version}",
                    description="WordPress version identified via fingerprinting",
                    evidence=f"Version: {version}",
                    recommendation="Ensure WordPress is updated to latest version",
                    raw={"version": version, "vulnerabilities": vulnerabilites},
                )

            findings.append(finding)

        return findings

    def _parse_plugins(self, data: dict) -> list[Finding]:
        """Extract plugin information and vulnerabilities."""
        findings = []
        plugins = data.get("plugins", {})

        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue

            version = plugin_data.get("version", "unknown")
            vulnerabilites = plugin_data.get("vulnerabilities", [])
            location = plugin_data.get("location", "")
            confidence = plugin_data.get("confidence", "")

            if vulnerabilites:
                vuln_list = []
                for v in vulnerabilites:
                    vuln_title = v.get("title", "Unknown vulnerability")
                    vuln_type = v.get("type", "vulnerability")
                    vuln_list.append(f"{vuln_title} ({vuln_type})")

                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="critical",
                    title=f"Plugin Vulnerable: {plugin_name}",
                    description=f"Plugin '{plugin_name}' has {len(vulnerabilites)} known vulnerabilities",
                    evidence=f"Plugin: {plugin_name} | Version: {version} | Location: {location}",
                    recommendation=f"UPDATE OR REMOVE this plugin immediately. Vulnerabilities: {'; '.join(vuln_list[:3])}",
                    raw={
                        "plugin": plugin_name,
                        "version": version,
                        "location": location,
                        "confidence": confidence,
                        "vulnerabilities": vulnerabilites,
                    },
                )
            else:
                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"Plugin Detected: {plugin_name}",
                    description=f"Plugin found with confidence: {confidence}",
                    evidence=f"Plugin: {plugin_name} | Version: {version} | Location: {location}",
                    recommendation="Ensure plugin is updated and monitored for vulnerabilities",
                    raw={
                        "plugin": plugin_name,
                        "version": version,
                        "location": location,
                        "confidence": confidence,
                        "vulnerabilities": vulnerabilites,
                    },
                )

            findings.append(finding)

        return findings

    def _parse_themes(self, data: dict) -> list[Finding]:
        """Extract theme information and vulnerabilities."""
        findings = []
        themes = data.get("themes", {})

        for theme_name, theme_data in themes.items():
            if not isinstance(theme_data, dict):
                continue

            version = theme_data.get("version", "unknown")
            vulnerabilites = theme_data.get("vulnerabilities", [])
            location = theme_data.get("location", "")

            if vulnerabilites:
                vuln_titles = ', '.join(v.get('title', '') for v in vulnerabilites[:3])
                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="high",
                    title=f"Theme Vulnerable: {theme_name}",
                    description=f"Theme '{theme_name}' has {len(vulnerabilites)} known vulnerabilities",
                    evidence=f"Theme: {theme_name} | Version: {version} | Location: {location}",
                    recommendation=f"Update or replace theme immediately. Vulnerabilities: {vuln_titles}",
                    raw={
                        "theme": theme_name,
                        "version": version,
                        "location": location,
                        "vulnerabilities": vulnerabilites,
                    },
                )
            else:
                finding = Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"Theme Detected: {theme_name}",
                    description="Theme found on the target",
                    evidence=f"Theme: {theme_name} | Version: {version} | Location: {location}",
                    recommendation="Ensure theme is updated to latest version",
                    raw={
                        "theme": theme_name,
                        "version": version,
                        "location": location,
                        "vulnerabilities": vulnerabilites,
                    },
                )

            findings.append(finding)

        return findings

    def _parse_users(self, data: dict) -> list[Finding]:
        """Extract user accounts."""
        findings = []
        users = data.get("users", {})

        for user_id, user_data in users.items():
            if not isinstance(user_data, dict):
                continue

            username = user_data.get("username", user_id)
            id = user_data.get("id", user_id)
            roles = user_data.get("roles", [])

            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"User Found: {username}",
                    description=f"WordPress user with roles: {', '.join(roles) if roles else 'unknown'}",
                    evidence=f"ID: {id} | Username: {username} | Roles: {', '.join(roles)}",
                    recommendation="Disable user enumeration if not needed. Ensure strong passwords for admin accounts.",
                    raw={"id": id, "username": username, "roles": roles},
                )
            )

        return findings

    def _parse_config_backups(self, data: dict) -> list[Finding]:
        """Extract config backup information."""
        findings = []
        interesting_files = data.get("interesting_entries", [])

        for entry in interesting_files:
            if not isinstance(entry, str):
                continue

            if any(
                pattern in entry.lower()
                for pattern in ["config", "wp-config", ".bak", ".old", ".save"]
            ):
                findings.append(
                    Finding(
                        module=self.MODULE,
                        step=self.name,
                        severity="critical",
                        title="Config Backup Detected",
                        description="Potential configuration backup file exposed",
                        evidence=entry,
                        recommendation="Remove or block access to configuration backup files immediately",
                        raw={"file": entry},
                    )
                )

        return findings

    def _parse_timthumbs(self, data: dict) -> list[Finding]:
        """Extract Timthumb vulnerability information."""
        findings = []
        timthumbs = data.get("timthumbs", [])

        for thumb in timthumbs:
            if not isinstance(thumb, str):
                continue

            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="high",
                    title="Timthumb Detected",
                    description="Timthumb image resizing script found - known RCE vector",
                    evidence=thumb,
                    recommendation="Update Timthumb to latest version or remove if not needed",
                    raw={"timthumb": thumb},
                )
            )

        return findings

    def _detect_wpscan_error(
        self, stderr: str, stdout: str
    ) -> tuple[bool, Optional[Finding]]:
        """Detect specific WPScan errors and return helpful findings.

        Args:
            stderr: WPScan stderr output
            stdout: WPScan stdout output

        Returns:
            Tuple of (error_detected, finding_if_any)
        """
        combined_output = (stderr + stdout).lower()

        if "cannot load such file -- readline" in combined_output:
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="WPScan Ruby Readline Error",
                description="WPScan cannot load the 'readline' Ruby gem. This is typically caused by installing Ruby via Homebrew without readline support.",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation=(
                    "Fix: Run 'brew install readline' and reinstall Ruby or WPScan, OR\n"
                    "Install WPScan with bundler: gem install bundler && bundle install\n"
                    "Alternative: Use Docker: docker run -it wpscanteam/wpscan --url <target>"
                ),
            )

        if (
            "no such file or directory" in combined_output
            and "wpscan" in combined_output
        ):
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="WPScan Binary Not Found",
                description="WPScan executable could not be found or executed",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Install WPScan: gem install wpscan",
            )

        if "permission denied" in combined_output:
            return True, Finding(
                module=self.MODULE,
                step=self.name,
                severity="low",
                title="WPScan Permission Denied",
                description="WPScan encountered a permission error",
                evidence=stderr[:500] if stderr else stdout[:500],
                recommendation="Check WPScan installation permissions or use sudo/brew permissions",
            )

        return False, None

    async def run(self) -> list[Finding]:
        """Execute WPScan and parse results."""
        exists, error = self.check_binary(self._tool_binary)
        if not exists:
            self.logger.error(error)
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="WPScan Not Available",
                description="WPScan binary not found or not installed",
                evidence=error,
                recommendation="Install WPScan: gem install wpscan",
            )
            return self.findings

        self.logger.info(f"Running WPScan on {self.target.url}")

        cmd = self.build_command()
        self.logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = await self._async_tool_runner.run(cmd, timeout=self.timeout)

            detected, error_finding = self._detect_wpscan_error(
                result.stderr or "", result.stdout or ""
            )
            if detected and error_finding:
                self.logger.error(
                    f"WPScan specific error detected: {error_finding.title}"
                )
                self.findings.append(error_finding)
                return self.findings

            if result.success or result.stdout:
                self.findings = self.parse_output(result)
                self.logger.info(f"WPScan completed: {len(self.findings)} findings")
            else:
                self.logger.error(
                    f"WPScan failed: {result.stderr[:500] if result.stderr else 'Unknown error'}"
                )
                self._add_finding(
                    module=self.MODULE,
                    severity="low",
                    title="WPScan Execution Failed",
                    description="WPScan completed with errors",
                    evidence=result.stderr[:500]
                    if result.stderr
                    else result.output[:500],
                    recommendation="Check WPScan installation and network connectivity",
                )

        except ToolTimeoutError:
            self.logger.error(f"WPScan timed out after {self.timeout}s")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="WPScan Timeout",
                description=f"WPScan exceeded timeout of {self.timeout} seconds",
                evidence=f"Timeout: {self.timeout}s",
                recommendation="Increase timeout or reduce enumeration scope",
            )
        except Exception as e:
            self.logger.error(f"WPScan error: {e}")
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="WPScan Error",
                description="WPScan encountered an unexpected error",
                evidence=str(e),
                recommendation="Check WPScan installation",
            )

        return self.findings
