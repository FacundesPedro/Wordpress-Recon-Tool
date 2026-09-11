# tests/conftest.py
"""Shared pytest fixtures and configuration."""

import asyncio
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_domain() -> str:
    """Sample domain for testing."""
    return "example.com"


@pytest.fixture
def sample_ip() -> str:
    """Sample IP address for testing."""
    return "8.8.8.8"


@pytest.fixture
def private_ip_ranges():
    """List of private IP ranges for testing."""
    return {
        "10.0.0.1": True,
        "172.16.0.1": True,
        "192.168.1.1": True,
        "127.0.0.1": True,
        "169.254.1.1": True,
        "::1": True,
    }


@pytest.fixture
def public_ip_ranges():
    """List of public IP ranges for testing."""
    return {
        "8.8.8.8": False,
        "1.1.1.1": False,
        "9.9.9.9": False,
        "208.67.222.222": False,
    }


@pytest.fixture
def localhost_names():
    """Localhost variations for testing."""
    return ["localhost", "localhost.localdomain", "ip6-localhost", "127.0.0.1", "::1"]


@pytest.fixture
def cloud_metadata_endpoints():
    """Cloud metadata endpoints for testing."""
    return {
        "169.254.169.254": True,
        "169.254.170.2": True,
        "100.100.100.200": True,
        "metadata.google.internal": True,
    }


@pytest.fixture
def safe_urls():
    """Safe URLs for testing."""
    return [
        "https://example.com",
        "https://www.example.com/path",
        "http://api.github.com/users",
    ]


@pytest.fixture
def unsafe_urls():
    """Unsafe URLs for testing."""
    return [
        "http://127.0.0.1",
        "http://localhost:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]


@pytest.fixture(autouse=True)
def mock_wordpress_detection(request, monkeypatch):
    """Default WordPress-detection result for step tests.

    WP-gated steps call utils.wordpress_detect.is_wordpress; tests mock
    the HTTP layer rather than real WP markers, so the gate would skip
    every WP step. Default to True (target looks like WordPress); tests
    that exercise the gate itself override this explicitly.
    """
    async def always_wp(http, url, logger=None):
        return True

    monkeypatch.setattr(
        "utils.wordpress_detect.is_wordpress",
        staticmethod(always_wp),
    )


@pytest.fixture
def mock_http():
    """Mock HttpClient for step testing."""
    http = MagicMock()
    http.unreachable = False
    http.get = AsyncMock(
        return_value=MagicMock(status_code=200, text="Mock response text")
    )
    return http


@pytest.fixture
def mock_target():
    """Mock Target for step testing."""
    target = MagicMock()
    target.url = "https://example.com"
    return target


@pytest.fixture
def mock_config():
    """Mock Config for step testing."""
    config = MagicMock()
    config.bruteforce_concurrency = 4
    config.bruteforce_max_probes = 0
    return config


@pytest.fixture
def plugin_step(mock_http, mock_target, mock_config):
    """Create PluginVersionStep with mocks for testing."""
    from steps.fingerprint.plugin_version_step import PluginVersionStep

    return PluginVersionStep(
        target=mock_target,
        config=mock_config,
        http=mock_http,
    )
