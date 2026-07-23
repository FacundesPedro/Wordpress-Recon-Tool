# recon_wp/core/http_client.py
"""Async HTTP client for making requests to WordPress targets.

SECURITY:
- Supports TLS certificate verification control via insecure flag
- User-Agent rotation to avoid simple detection
- All requests go through consistent session management
"""

from typing import Optional

import httpx

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]


class HttpClient:
    """Shared async HTTP client with session management and User-Agent rotation.

    SECURITY:
    - User-Agent rotation to avoid simple WAF/IPS detection
    - Configurable TLS verification via insecure flag
    - Consistent session for cookie handling
    """

    def __init__(self, timeout: int = 10, insecure: bool = False):
        self.timeout = timeout
        self.insecure = insecure
        self._client: Optional[httpx.AsyncClient] = None
        self._user_agents = COMMON_USER_AGENTS
        self._current_ua_index = 0

    def _get_next_user_agent(self) -> str:
        """Get next User-Agent, cycling through the list."""
        ua = self._user_agents[self._current_ua_index]
        self._current_ua_index = (self._current_ua_index + 1) % len(self._user_agents)
        return ua

    def set_user_agents(self, user_agents: list[str]):
        """Set custom User-Agent list."""
        if user_agents:
            self._user_agents = user_agents
            self._current_ua_index = 0

    async def __aenter__(self):
        default_headers = {
            "User-Agent": self._get_next_user_agent(),
        }
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=not self.insecure,
            follow_redirects=True,
            headers=default_headers,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    def _refresh_user_agent(self):
        """Refresh the User-Agent header for the next request."""
        if self._client:
            self._client.headers["User-Agent"] = self._get_next_user_agent()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        """GET request with User-Agent rotation."""
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        self._refresh_user_agent()
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        """POST request with User-Agent rotation."""
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        self._refresh_user_agent()
        return await self._client.post(url, **kwargs)

    async def head(self, url: str, **kwargs) -> httpx.Response:
        """HEAD request with User-Agent rotation."""
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        self._refresh_user_agent()
        return await self._client.head(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Generic request with User-Agent rotation."""
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        self._refresh_user_agent()
        return await self._client.request(method, url, **kwargs)
