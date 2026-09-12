"""Tests for NmapPortScanStep and NmapScriptScanStep."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from base.tool import ToolResult
from config import ScanConfig
from core.exceptions import ToolTimeoutError
from core.target import Target
from steps.tools.nmap_step import (
    NmapPortScanStep,
    NmapScriptScanStep,
    iter_hosts,
    parse_nmap_xml,
)


@pytest.fixture
def mock_config():
    config = MagicMock(spec=ScanConfig)
    config.nmap_top_ports = 100
    config.nmap_ports = ""
    config.nmap_timeout = 300
    config.quiet = False
    return config


@pytest.fixture
def mock_target():
    return Target(url="https://example.com", domain="example.com")


@pytest.fixture
def port_step(mock_target, mock_config):
    return NmapPortScanStep(target=mock_target, config=mock_config)


@pytest.fixture
def script_step(mock_target, mock_config):
    return NmapScriptScanStep(target=mock_target, config=mock_config)


# Real nmap -oX output shape (nmap 7.95)
SAMPLE_NMAP_XML = "\n".join(
    [
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<!DOCTYPE nmaprun>",
        '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" '
        'type="text/xsl"?>',
        "<!-- Nmap 7.95 scan initiated as: nmap -oX - -Pn -sT -sV -->",
        '<nmaprun scanner="nmap" args="nmap -oX - -Pn -sT -sV" '
        'version="7.95" xmloutputversion="1.05">',
        '<host><status state="up" reason="user-set" reason_ttl="0"/>',
        '<address addr="93.184.216.34" addrtype="ipv4"/>',
        "<ports>",
        '<port protocol="tcp" portid="80">'
        '<state state="open" reason="syn-ack" reason_ttl="0"/>'
        '<service name="http" product="nginx" version="1.25.1" '
        'method="probed" conf="10"/></port>',
        '<port protocol="tcp" portid="3306">'
        '<state state="open" reason="syn-ack" reason_ttl="0"/>'
        '<service name="mysql" method="probed" conf="10"/></port>',
        '<port protocol="tcp" portid="22">'
        '<state state="closed" reason="reset" reason_ttl="0"/>'
        '<service name="ssh" method="table" conf="3"/></port>',
        "</ports>",
        "</host>",
        '<runstats><finished time="0" elapsed="1.0" exit="success"/></runstats>',
        "</nmaprun>",
    ]
)

SAMPLE_SCRIPTS_XML = "\n".join(
    [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<nmaprun scanner="nmap" version="7.95">',
        '<host><status state="up"/><address addr="93.184.216.34" '
        'addrtype="ipv4"/>',
        "<ports>",
        '<port protocol="tcp" portid="21">'
        '<state state="open" reason="syn-ack"/>'
        '<service name="ftp" method="probed"/>'
        '<script id="ftp-anon" output="Anonymous access allowed">'
        '<table key="vulns"><table><elem key="id">CVE-2000-0642</elem>'
        '<elem key="title">Anonymous FTP access</elem>'
        '<elem key="cvss">9.8</elem></table></table></script></port>',
        '<port protocol="tcp" portid="80">'
        '<state state="open" reason="syn-ack"/>'
        '<service name="http" method="probed"/>'
        '<script id="http-title" output="Welcome to nginx">'
        '<elem key="title">Welcome to nginx</elem></script></port>',
        "</ports>",
        "</host>",
        "</nmaprun>",
    ]
)


class TestParseNmapXml:
    def test_parses_real_xml(self):
        run = parse_nmap_xml(SAMPLE_NMAP_XML)
        assert "host" in run
        hosts = iter_hosts(run)
        assert len(hosts) == 1
        assert hosts[0]["address"]["addr"] == "93.184.216.34"

    def test_strips_xml_prologue(self):
        run = parse_nmap_xml(SAMPLE_NMAP_XML)
        ports = iter_hosts(run)[0]["ports"]
        assert {p["portid"] for p in ports} == {80, 3306, 22}

    def test_script_vulns_parsed(self):
        run = parse_nmap_xml(SAMPLE_SCRIPTS_XML)
        ports = iter_hosts(run)[0]["ports"]
        ftp = next(p for p in ports if p["portid"] == 21)
        vulns = ftp["scripts"]["ftp-anon"]["vulns"]
        assert vulns[0]["id"] == "CVE-2000-0642"
        assert vulns[0]["name"] == "Anonymous FTP access"
        assert vulns[0]["severity"] in ("high", "critical")

    def test_invalid_xml(self):
        assert parse_nmap_xml("not xml at all") == {}

    def test_empty(self):
        assert parse_nmap_xml("") == {}

    def test_single_host_dict_fallback(self):
        run = parse_nmap_xml("<nmaprun><host><ports/></host></nmaprun>")
        hosts = iter_hosts(run)
        assert len(hosts) == 1


class TestPortStepBuildCommand:
    def test_default_command(self, port_step):
        cmd = port_step.build_command()
        assert cmd[0] == "nmap"
        assert "-oX" in cmd
        assert "-" in cmd
        assert "-Pn" in cmd
        assert "-sT" in cmd
        assert "-T4" in cmd
        assert "-sV" in cmd
        assert "--top-ports" in cmd
        assert "100" in cmd
        assert cmd[-1] == "example.com"

    def test_custom_ports(self, mock_target, mock_config):
        mock_config.nmap_ports = "80,443,8080"
        step = NmapPortScanStep(target=mock_target, config=mock_config)
        cmd = step.build_command()
        assert "-p" in cmd
        assert "80,443,8080" in cmd
        assert "--top-ports" not in cmd

    def test_custom_top_ports(self, mock_target, mock_config):
        mock_config.nmap_top_ports = 1000
        step = NmapPortScanStep(target=mock_target, config=mock_config)
        cmd = step.build_command()
        assert "1000" in cmd


class TestPortStepParseOutput:
    def test_open_ports_found(self, port_step):
        result = ToolResult(
            stdout=SAMPLE_NMAP_XML, stderr="", returncode=0, success=True
        )
        findings = port_step.parse_output(result)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == "medium"
        assert "2 Open Port(s)" in finding.title
        assert "80/tcp http 1.25.1" in finding.evidence
        assert "3306/tcp mysql" in finding.evidence
        assert finding.raw["risky_services"]
        assert "3306/mysql (MySQL)" in finding.raw["risky_services"][0]

    def test_no_risky_services_info_severity(self, port_step):
        data = (
            "<nmaprun><host><ports>"
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port>'
            "</ports></host></nmaprun>"
        )
        result = ToolResult(stdout=data, stderr="", returncode=0, success=True)
        findings = port_step.parse_output(result)
        assert findings[0].severity == "info"

    def test_no_open_ports(self, port_step):
        data = (
            "<nmaprun><host><ports>"
            '<port protocol="tcp" portid="80"><state state="closed"/></port>'
            "</ports></host></nmaprun>"
        )
        result = ToolResult(stdout=data, stderr="", returncode=0, success=True)
        findings = port_step.parse_output(result)
        assert len(findings) == 1
        assert "No Open Ports" in findings[0].title
        assert findings[0].severity == "info"

    def test_invalid_output_no_findings(self, port_step):
        result = ToolResult(stdout="garbage", stderr="", returncode=1, success=False)
        findings = port_step.parse_output(result)
        assert findings == []


class TestScriptStepBuildCommand:
    def test_default_command(self, script_step):
        cmd = script_step.build_command()
        assert "-sC" in cmd
        assert "-sV" in cmd
        assert "-oX" in cmd
        assert cmd[-1] == "example.com"

    def test_custom_ports(self, mock_target, mock_config):
        mock_config.nmap_ports = "21,80"
        step = NmapScriptScanStep(target=mock_target, config=mock_config)
        cmd = step.build_command()
        assert "-p" in cmd
        assert "21,80" in cmd


class TestScriptStepParseOutput:
    def test_notable_scripts_and_vulns(self, script_step):
        result = ToolResult(
            stdout=SAMPLE_SCRIPTS_XML, stderr="", returncode=0, success=True
        )
        findings = script_step.parse_output(result)
        titles = [f.title for f in findings]
        assert "Nmap script: Anonymous FTP access enabled (21/tcp ftp)" in titles
        assert "Nmap vuln script: Anonymous FTP access (21/tcp ftp)" in titles
        assert "Nmap script: HTTP page title (80/tcp http)" in titles
        vuln = [f for f in findings if "vuln script" in f.title][0]
        assert vuln.severity == "high"
        assert "CVE-2000-0642" in vuln.description
        ftp_anon = [f for f in findings if "Anonymous FTP access enabled" in f.title][0]
        assert ftp_anon.severity == "high"

    def test_no_scripts_info_finding(self, script_step):
        data = (
            "<nmaprun><host><ports>"
            '<port protocol="tcp" portid="80"><state state="closed"/></port>'
            "</ports></host></nmaprun>"
        )
        result = ToolResult(stdout=data, stderr="", returncode=0, success=True)
        findings = script_step.parse_output(result)
        assert len(findings) == 1
        assert "No NSE Script Output" in findings[0].title

    def test_scripts_run_nothing_notable(self, script_step):
        data = (
            "<nmaprun><host><ports>"
            '<port protocol="tcp" portid="80"><state state="open"/><service name="http"/>'
            '<script id="some-unknown-script" output="foo"/></port>'
            "</ports></host></nmaprun>"
        )
        result = ToolResult(stdout=data, stderr="", returncode=0, success=True)
        findings = script_step.parse_output(result)
        assert len(findings) == 1
        assert "1 NSE Script(s) Ran" in findings[0].title


class TestStepRun:
    async def test_binary_not_available(self, port_step):
        with patch("shutil.which", return_value=None):
            findings = await port_step.run()
        assert len(findings) == 1
        assert "Nmap Not Available" in findings[0].title

    async def test_run_success(self, port_step):
        port_step.check_binary = lambda binary: (True, "")
        port_step.check_version_compatibility = lambda: True
        port_step._async_tool_runner.run = AsyncMock(
            return_value=ToolResult(
                stdout=SAMPLE_NMAP_XML, stderr="", returncode=0, success=True
            )
        )
        findings = await port_step.run()
        assert any("2 Open Port(s)" in f.title for f in findings)
        port_step._async_tool_runner.run.assert_awaited_once()

    async def test_run_timeout(self, port_step):
        port_step.check_binary = lambda binary: (True, "")
        port_step.check_version_compatibility = lambda: True
        port_step._async_tool_runner.run = AsyncMock(
            side_effect=ToolTimeoutError("nmap", 300)
        )
        findings = await port_step.run()
        assert any("Nmap Timeout" in f.title for f in findings)
