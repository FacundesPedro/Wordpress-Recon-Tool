# recon_wp/steps/tools/nmap_step.py
"""
Nmap integration - direct host port scanning and NSE script scanning.

Two separate steps:
- NmapPortScanStep: TCP connect scan with service/version detection (-sV)
- NmapScriptScanStep: Nmap default NSE scripts (-sV -sC)

Unlike the WordPress pingback SSRF ports step, these scan the target host
directly from the local machine. Only use on authorized targets.
"""

# WHAT: Direct port scanning + version detection, and NSE default script scan
# HOW: Runs nmap -oX (XML to stdout) via AsyncToolRunner, parses host/port data
# WHY: Reveals exposed services, versions, and protocol-level weaknesses on the
#      host itself, for generic web security assessments (non-WordPress too)

import xml.etree.ElementTree as ET
from typing import Optional

from base.step import BaseToolStep
from base.tool import ToolResult
from core.finding import Finding
from core.target import Target

RISKY_SERVICES = {
    22: "SSH",
    23: "Telnet",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
    11211: "Memcached",
}

NOTABLE_SCRIPTS = {
    "ftp-anon": ("high", "Anonymous FTP access enabled"),
    "upnp-info": ("low", "UPnP device discovered"),
    "snmp-info": ("low", "SNMP information exposed"),
    "smb-os-discovery": ("info", "SMB OS discovery"),
    "http-headers": ("info", "HTTP server headers"),
    "http-title": ("info", "HTTP page title"),
    "ssl-cert": ("info", "TLS certificate details"),
}


def _local_tag(element: ET.Element) -> str:
    """Return an element's tag without any XML namespace prefix."""
    tag = element.tag
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _table_value(table: ET.Element) -> object:
    """Convert an NSE ``<table>`` into a dict, or a list when it nests tables."""
    nested = [child for child in table if _local_tag(child) == "table"]
    if nested:
        items: list[object] = []
        for nested_table in nested:
            value = _table_value(nested_table)
            if isinstance(value, dict):
                _normalize_vuln_keys(value)
            items.append(value)
        return items

    elems: dict[str, object] = {}
    for child in table:
        if _local_tag(child) == "elem":
            key = child.get("key")
            if key:
                elems[key] = child.text
    return elems


def _normalize_vuln_keys(item: dict) -> None:
    """Map real nmap NSE vuln fields (title/cvss) to the internal schema."""
    if "name" not in item and item.get("title"):
        item["name"] = item["title"]
    if "severity" not in item:
        try:
            score = float(item.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            score = 0.0
        if score >= 9.0:
            item["severity"] = "critical"
        elif score >= 7.0:
            item["severity"] = "high"
        elif score >= 4.0:
            item["severity"] = "medium"
        elif score > 0:
            item["severity"] = "low"


def _parse_script(script: ET.Element) -> dict:
    """Convert an NSE ``<script>`` element into a structured dict."""
    result: dict = {}
    for child in script:
        tag = _local_tag(child)
        if tag == "elem":
            key = child.get("key")
            if key:
                result[key] = child.text
        elif tag == "table":
            key = child.get("key")
            if key:
                result[key] = _table_value(child)
    if not result and script.get("output"):
        result["output"] = script.get("output")
    return result


def parse_nmap_xml(stdout: str) -> dict:
    """Parse nmap ``-oX`` output into the internal nmap-run dict ({} on failure)."""
    if not stdout:
        return {}

    start = stdout.find("<nmaprun")
    if start < 0:
        return {}
    end = stdout.find("</nmaprun>")
    xml_text = stdout[start : end + len("</nmaprun>")] if end >= 0 else stdout[start:]

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        host: dict = {"ports": []}

        status_el = host_el.find("status")
        if status_el is not None:
            host["status"] = dict(status_el.attrib)
        address_el = host_el.find("address")
        if address_el is not None:
            host["address"] = dict(address_el.attrib)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port: dict = {
                    "portid": int(port_el.get("portid", 0) or 0),
                    "protocol": port_el.get("protocol", "tcp"),
                }

                state_el = port_el.find("state")
                if state_el is not None:
                    port["state"] = state_el.get("state", "")
                    port["reason"] = state_el.get("reason", "")

                service_el = port_el.find("service")
                if service_el is not None:
                    port["service"] = dict(service_el.attrib)

                scripts: dict = {}
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    if script_id:
                        scripts[script_id] = _parse_script(script_el)
                if scripts:
                    port["scripts"] = scripts

                host["ports"].append(port)

        hosts.append(host)

    return {"host": hosts}


def iter_hosts(run: dict) -> list[dict]:
    """Return host dicts from a parsed nmap-run (handles single-host dict)."""
    hosts = run.get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]
    return [h for h in hosts if isinstance(h, dict)]


def _format_port(port: dict) -> str:
    portid = port.get("portid", "?")
    protocol = port.get("protocol", "tcp")
    service = (port.get("service") or {}).get("name") or "unknown"
    version = (port.get("service") or {}).get("version")
    suffix = f" {version}" if version else ""
    return f"{portid}/{protocol} {service}{suffix}"


class NmapPortScanStep(BaseToolStep):
    """Direct port scan with service/version detection."""

    name = "nmap_ports"
    description = "Nmap port scan with version detection"
    severity = "info"
    _tool_binary = "nmap"
    MODULE = "tools"
    min_version = "7.92"

    def __init__(
        self,
        target: Target,
        config,
        http=None,
        top_ports: Optional[int] = None,
        ports: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.top_ports = top_ports or getattr(config, "nmap_top_ports", 100)
        self.custom_ports = ports or getattr(config, "nmap_ports", "")
        self.timeout = timeout or getattr(config, "nmap_timeout", 300)

    def build_command(self) -> list[str]:
        cmd = [
            self._tool_binary,
            "-oX",
            "-",
            "-Pn",
            "-sT",
            "-T4",
            "-sV",
        ]
        if self.custom_ports:
            cmd.extend(["-p", self.custom_ports])
        else:
            cmd.extend(["--top-ports", str(self.top_ports)])
        cmd.append(self._scan_host())
        return cmd

    def _scan_host(self) -> str:
        host = self.target.domain or ""
        if not host:
            from urllib.parse import urlparse

            host = urlparse(self.target.url).netloc
        return host

    def parse_output(self, result: ToolResult) -> list[Finding]:
        findings: list[Finding] = []
        run = parse_nmap_xml(result.stdout)
        if not run:
            if result.stderr:
                self.logger.debug(f"Nmap stderr: {result.stderr[:500]}")
            return findings

        host = self._scan_host()
        open_ports: list[dict] = []
        risky_found: list[str] = []

        for host_data in iter_hosts(run):
            for port in host_data.get("ports", []) or []:
                if not isinstance(port, dict):
                    continue
                if port.get("state") != "open":
                    continue
                open_ports.append(port)
                service = (port.get("service") or {}).get("name", "")
                risk = RISKY_SERVICES.get(port.get("portid"))
                if risk:
                    risky_found.append(f"{port.get('portid')}/{service or 'unknown'} ({risk})")

        if not open_ports:
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title="Nmap: No Open Ports Detected",
                    description=f"nmap found no open ports on {host}",
                    evidence=f"nmap scan of {host}",
                    recommendation="Verify port list and timing are appropriate for the target",
                    raw={"scan_type": "nmap_ports", "host": host, "open_ports": 0},
                )
            )
            return findings

        port_summaries = [_format_port(p) for p in open_ports]
        severity = "medium" if risky_found else "info"
        description = (
            f"nmap found {len(open_ports)} open port(s) on {host}: "
            + ", ".join(port_summaries)
        )
        if risky_found:
            description += (
                " - potentially sensitive service(s) exposed: " + ", ".join(risky_found)
            )

        findings.append(
            Finding(
                module=self.MODULE,
                step=self.name,
                severity=severity,
                title=f"Nmap: {len(open_ports)} Open Port(s) on {host}",
                description=description,
                evidence=", ".join(port_summaries),
                recommendation=(
                    "Close or firewall ports that do not need to be exposed; "
                    "review each service for known vulnerabilities"
                ),
                raw={
                    "scan_type": "nmap_ports",
                    "host": host,
                    "open_ports": open_ports,
                    "risky_services": risky_found,
                },
            )
        )
        return findings


class NmapScriptScanStep(BaseToolStep):
    """Nmap default NSE script scan (-sC)."""

    name = "nmap_scripts"
    description = "Nmap default NSE script scan"
    severity = "info"
    _tool_binary = "nmap"
    MODULE = "tools"
    min_version = "7.92"

    def __init__(
        self,
        target: Target,
        config,
        http=None,
        top_ports: Optional[int] = None,
        ports: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        super().__init__(
            target=target,
            config=config,
            name=self.name,
            description=self.description,
        )
        self.top_ports = top_ports or getattr(config, "nmap_top_ports", 100)
        self.custom_ports = ports or getattr(config, "nmap_ports", "")
        self.timeout = timeout or getattr(config, "nmap_timeout", 300)

    def build_command(self) -> list[str]:
        cmd = [
            self._tool_binary,
            "-oX",
            "-",
            "-Pn",
            "-sT",
            "-T4",
            "-sV",
            "-sC",
        ]
        if self.custom_ports:
            cmd.extend(["-p", self.custom_ports])
        else:
            cmd.extend(["--top-ports", str(self.top_ports)])
        host = self.target.domain or ""
        if not host:
            from urllib.parse import urlparse

            host = urlparse(self.target.url).netloc
        cmd.append(host)
        return cmd

    def parse_output(self, result: ToolResult) -> list[Finding]:
        findings: list[Finding] = []
        run = parse_nmap_xml(result.stdout)
        if not run:
            if result.stderr:
                self.logger.debug(f"Nmap stderr: {result.stderr[:500]}")
            return findings

        host = self.target.domain or ""
        if not host:
            from urllib.parse import urlparse

            host = urlparse(self.target.url).netloc

        total_scripts = 0
        vuln_findings = 0

        for host_data in iter_hosts(run):
            for port in host_data.get("ports", []) or []:
                if not isinstance(port, dict):
                    continue
                scripts = port.get("scripts") or {}
                if not isinstance(scripts, dict):
                    continue
                port_label = _format_port(port)

                for script_name, output in scripts.items():
                    total_scripts += 1
                    if not isinstance(output, dict):
                        continue

                    summary = self._summarize_script_output(output)

                    notable = NOTABLE_SCRIPTS.get(script_name)
                    if notable:
                        severity, title = notable
                        findings.append(
                            Finding(
                                module=self.MODULE,
                                step=self.name,
                                severity=severity,
                                title=f"Nmap script: {title} ({port_label})",
                                description=(
                                    f"NSE script '{script_name}' produced output "
                                    f"on {port_label} of {host}."
                                ),
                                evidence=summary or script_name,
                                recommendation=(
                                    "Review the service behavior indicated by this "
                                    "script output and harden the service if needed"
                                ),
                                raw={
                                    "scan_type": "nmap_scripts",
                                    "host": host,
                                    "port": port,
                                    "script": script_name,
                                    "output": output,
                                },
                            )
                        )

                    for vuln in output.get("vulns", []) or []:
                        if not isinstance(vuln, dict):
                            continue
                        vuln_findings += 1
                        severity = str(vuln.get("severity", "medium")).lower()
                        if severity not in ("low", "medium", "high", "critical"):
                            severity = "medium"
                        if severity == "high" or severity == "critical":
                            severity = "high"
                        cve = vuln.get("id", "")
                        vuln_name = vuln.get("name", "Vulnerability")
                        findings.append(
                            Finding(
                                module=self.MODULE,
                                step=self.name,
                                severity=severity,
                                title=f"Nmap vuln script: {vuln_name} ({port_label})",
                                description=(
                                    f"NSE vulnerability script '{script_name}' "
                                    f"flagged {vuln_name} on {port_label} of {host}"
                                    + (f" (CVE: {cve})" if cve else "")
                                ),
                                evidence=summary or cve or script_name,
                                recommendation=(
                                    "Patch or mitigate the flagged vulnerability"
                                ),
                                raw={
                                    "scan_type": "nmap_scripts",
                                    "host": host,
                                    "port": port,
                                    "script": script_name,
                                    "vuln": vuln,
                                },
                            )
                        )

        if total_scripts == 0:
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title="Nmap: No NSE Script Output",
                    description=(
                        f"nmap default scripts produced no output on {host} "
                        "(no open ports or scripts not applicable)"
                    ),
                    evidence=f"nmap -sC scan of {host}",
                    recommendation="Verify port list and that NSE scripts are installed with nmap",
                    raw={"scan_type": "nmap_scripts", "host": host, "scripts": 0},
                )
            )
        elif not findings:
            findings.append(
                Finding(
                    module=self.MODULE,
                    step=self.name,
                    severity="info",
                    title=f"Nmap: {total_scripts} NSE Script(s) Ran",
                    description=(
                        f"nmap default scripts ran on {host} "
                        f"({total_scripts} script output(s), nothing notable mapped)"
                    ),
                    evidence=f"nmap -sC scan of {host}",
                    recommendation="Inspect raw nmap output for context-specific details",
                    raw={"scan_type": "nmap_scripts", "host": host, "scripts": total_scripts},
                )
            )

        return findings

    @staticmethod
    def _summarize_script_output(output: dict, max_len: int = 300) -> str:
        """Build a short human-readable summary of NSE structured output."""
        parts: list[str] = []
        for key, value in output.items():
            if key == "vulns" or isinstance(value, (dict, list)):
                continue
            if isinstance(value, (str, int, float, bool)):
                parts.append(f"{key}={value}")
            if len(parts) >= 5:
                break
        summary = "; ".join(str(p) for p in parts)
        return summary[:max_len]
