"""Tests for ShodanStep."""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.asyncio


MOCK_HOST_DATA = {
    "ports": [80, 443, 8080],
    "isp": "Example ISP",
    "org": "Example Organization",
    "asn": "AS12345",
    "country_name": "United States",
    "city": "San Francisco",
    "ssl": {
        "cert": {
            "subject": {"CN": "example.com"},
            "issuer": {"O": "Let's Encrypt"},
        }
    },
}


MOCK_SEARCH_MATCHES_WORDPRESS = [
    {"port": 443, "transport": "tcp", "product": "WordPress", "version": "6.4"},
    {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.24"},
]


class TestSkipConditions:
    """Tests for early return conditions."""

    async def test_returns_empty_when_no_domain(self):
        mock_target = MagicMock()
        mock_target.domain = None
        mock_http = MagicMock()
        mock_config = MagicMock()

        from steps.passive.shodan_step import ShodanStep

        step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()
        assert findings == []

    async def test_returns_empty_when_no_http(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()

        from steps.passive.shodan_step import ShodanStep

        step = ShodanStep(target=mock_target, config=mock_config, http=None)
        findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_no_api_key(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_config = MagicMock()
        mock_config.shodan_api_key = ""

        from steps.passive.shodan_step import ShodanStep

        step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
        findings = await step.run()

        assert findings == []

    async def test_returns_empty_when_dns_fails(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", side_effect=socket.gaierror("no address")):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert findings == []


class TestHostQuery:
    """Tests for Shodan host information query."""

    async def test_200_returns_host_findings(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = MOCK_HOST_DATA
        mock_http.request = AsyncMock(return_value=mock_resp)
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        ports_finding = [f for f in findings if "Open Ports" in f.title]
        host_info_finding = [f for f in findings if "Host Information" in f.title]
        ssl_finding = [f for f in findings if "SSL/TLS" in f.title]

        assert len(ports_finding) == 1
        assert len(host_info_finding) == 1
        assert len(ssl_finding) == 1

        assert ports_finding[0].raw["total_ports"] == 3
        assert "Let's Encrypt" in ssl_finding[0].evidence

    async def test_401_invalid_key_records_error(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_resp = MagicMock(status_code=401)
        mock_http.request = AsyncMock(return_value=mock_resp)
        mock_config = MagicMock()
        mock_config.shodan_api_key = "invalid-key"

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        error_findings = [f for f in findings if "Open Ports" in f.title]
        assert len(error_findings) == 0

    async def test_host_query_timeout(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=TimeoutError("timed out"))
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        host_findings = [f for f in findings if "Host Information" in f.title]
        assert len(host_findings) == 0


class TestSearchQuery:
    """Tests for Shodan search query."""

    async def test_wordpress_detected_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        host_resp = MagicMock(status_code=404)
        search_resp = MagicMock(status_code=200)
        search_resp.json.return_value = {"matches": MOCK_SEARCH_MATCHES_WORDPRESS}

        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[host_resp, search_resp])

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        wp = [f for f in findings if "WordPress" in f.title]
        services = [f for f in findings if "Service Fingerprints" in f.title]

        assert len(wp) == 1
        assert len(services) == 1
        assert wp[0].severity == "info"

    async def test_no_wordpress_no_separate_finding(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        host_resp = MagicMock(status_code=404)
        search_resp = MagicMock(status_code=200)
        search_resp.json.return_value = {
            "matches": [
                {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24"}
            ]
        }

        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[host_resp, search_resp])

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        wp = [f for f in findings if "WordPress" in f.title]
        assert len(wp) == 0


class TestEmptyFallback:
    """Tests for no-data-found fallback."""

    async def test_no_shodan_data_returns_empty(self):
        mock_target = MagicMock()
        mock_target.domain = "example.com"
        mock_config = MagicMock()
        mock_config.shodan_api_key = "valid-key"

        host_resp = MagicMock(status_code=404)
        search_resp = MagicMock(status_code=404)

        mock_http = MagicMock()
        mock_http.request = AsyncMock(side_effect=[host_resp, search_resp])

        from steps.passive.shodan_step import ShodanStep

        with patch("steps.passive.shodan_step.socket.gethostbyname", return_value="1.2.3.4"):
            step = ShodanStep(target=mock_target, config=mock_config, http=mock_http)
            findings = await step.run()

        assert len(findings) == 0
