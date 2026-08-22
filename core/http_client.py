"""Async HTTP client for making requests to WordPress targets.

SECURITY:
- Supports TLS certificate verification control via insecure flag
- User-Agent rotation to avoid simple detection
- All requests go through consistent session management
- Stealth mode adds timing jitter, referer spoofing, request dedup, rate limiting
"""

import asyncio
import random
import ssl
from typing import TYPE_CHECKING, Optional

import httpx

from core.logger import Logger

if TYPE_CHECKING:
    from config import ScanConfig

logger = Logger("HttpClient")


def friendly_network_error(exc: Exception) -> str:
    """Produce a human-readable message for a network/transport exception."""
    name = type(exc).__name__
    detail = str(exc).strip()

    if isinstance(exc, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in name or "CERTIFICATE_VERIFY_FAILED" in detail:
        if "certificate has expired" in detail.lower():
            return f"TLS certificate has expired: {detail}"
        return f"TLS certificate verification failed: {detail}"

    if isinstance(exc, httpx.ConnectError):
        if "nodename" in detail or "Name or service not known" in detail:
            return f"DNS resolution failed — domain may not exist or is unreachable: {detail}"
        if "Connection refused" in detail:
            return f"Connection refused — no service listening on target: {detail}"
        return f"Connection failed: {detail}"

    if isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout, TimeoutError)):
        return f"Connection timed out — host may be unreachable or firewalled: {detail}"

    if isinstance(exc, httpx.TransportError):
        return f"Network error: {detail}"

    return f"Network error ({name}): {detail}"

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
]

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; OnePlus 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/114.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/115.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.0.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/127.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/125.0.0.0 Mobile Safari/537.36",
]

REFERERS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=wordpress+development",
    "https://www.bing.com/",
    "https://www.bing.com/search?q=wordpress+security",
    "https://duckduckgo.com/",
    "https://duckduckgo.com/?q=wordpress+plugin+review",
    "https://www.facebook.com/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/r/WordPress/",
    "https://www.reddit.com/r/Wordpress/",
    "https://wordpress.org/",
    "https://wordpress.org/support/",
    "https://developer.wordpress.org/",
    "https://make.wordpress.org/",
    "https://twitter.com/",
    "https://github.com/",
    "https://stackoverflow.com/questions/tagged/wordpress",
    "https://www.cloudflare.com/",
    "https://wpengine.com/",
    "https://siteground.com/",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-CA,en;q=0.9,fr;q=0.8",
    "en-AU,en;q=0.9",
    "en,fr;q=0.9,en-US;q=0.8",
    "en,de;q=0.9,en-US;q=0.8",
    "en,es;q=0.9,en-US;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8,en-US;q=0.7",
    "fr-FR,fr;q=0.9,en;q=0.8,en-US;q=0.7",
    "de-DE,de;q=0.9,en;q=0.8,en-US;q=0.7",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "en-US,en;q=0.9,ar;q=0.8",
    "en-US,en;q=0.9,pt;q=0.8",
    "en-US,en;q=0.9,ko;q=0.8",
]


class HttpClient:
    """Shared async HTTP client with session management and stealth capabilities.

    SECURITY:
    - User-Agent rotation to avoid simple WAF/IPS detection
    - Configurable TLS verification via insecure flag
    - Consistent session for cookie handling

    STEALTH MODE (when config has stealth_enabled=True):
    - Expanded User-Agent pool (50+ real browser UAs)
    - Random timing jitter between requests
    - Referer header spoofing from realistic sources
    - Request deduplication to avoid identical probes
    - Rate limiting with configurable requests/second
    """

    def __init__(
        self,
        timeout: int = 10,
        insecure: bool = False,
        config: Optional["ScanConfig"] = None,
    ):
        self.timeout = timeout
        self.insecure = insecure
        self._client: Optional[httpx.AsyncClient] = None
        self._current_ua_index = 0
        self._seen_requests: set[tuple[str, str]] = set()
        self._consecutive_errors = 0
        self.unreachable = False
        self.unreachable_threshold = (
            config.unreachable_threshold if config is not None else 5
        )

        if config is not None and config.stealth_enabled:
            self.stealth_enabled = True
            self._user_agents = list(STEALTH_USER_AGENTS)
            self._referers = list(REFERERS)
            self._accept_languages = list(ACCEPT_LANGUAGES)
            self.min_delay = config.stealth_min_delay
            self.max_delay = config.stealth_max_delay
            self.rotate_ua = config.stealth_rotate_ua
            self.rotate_referer = config.stealth_rotate_referer
            self.dedup_enabled = config.stealth_dedup_requests
            if config.stealth_rate_limit > 0:
                from utils.rate_limiter import RateLimiter
                self._rate_limiter = RateLimiter(
                    max_requests=int(config.stealth_rate_limit),
                    per_seconds=1.0,
                )
            else:
                self._rate_limiter = None
        else:
            self.stealth_enabled = False
            self._user_agents = list(COMMON_USER_AGENTS)
            self._referers = []
            self._accept_languages = []
            self.min_delay = 0.0
            self.max_delay = 0.0
            self.rotate_ua = True
            self.rotate_referer = False
            self.dedup_enabled = False
            self._rate_limiter = None

    def _get_next_user_agent(self) -> str:
        ua = self._user_agents[self._current_ua_index]
        self._current_ua_index = (self._current_ua_index + 1) % len(self._user_agents)
        return ua

    def set_user_agents(self, user_agents: Optional[list[str]]):
        if user_agents:
            self._user_agents = list(user_agents)
            self._current_ua_index = 0

    async def _apply_jitter(self):
        if self.stealth_enabled and self.max_delay > 0:
            delay = self.min_delay + random.random() * (self.max_delay - self.min_delay)
            await asyncio.sleep(delay)

    async def _apply_rate_limit(self):
        if self._rate_limiter is not None:
            await self._rate_limiter._acquire()

    def _is_duplicate(self, method: str, url: str) -> bool:
        if not self.dedup_enabled:
            return False
        key = (method.upper(), url)
        if key in self._seen_requests:
            return True
        self._seen_requests.add(key)
        return False

    async def _execute(self, coro):
        """Run a request coroutine with circuit-breaker tracking.

        Counts consecutive transport-level failures. When the count reaches
        `unreachable_threshold`, the target is marked unreachable and all
        further requests raise immediately.
        """
        if self.unreachable:
            coro.close()
            raise RuntimeError(
                "Target marked unreachable — skipping request (circuit breaker open)"
            )
        try:
            result = await coro
        except (httpx.TransportError, OSError) as exc:
            self._consecutive_errors += 1
            if self._consecutive_errors >= self.unreachable_threshold:
                self.unreachable = True
                logger.warning(
                    f"Target marked unreachable after {self._consecutive_errors} "
                    f"consecutive network errors: {friendly_network_error(exc)}"
                )
            raise
        else:
            self._consecutive_errors = 0
            return result

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
        if self._client and self.rotate_ua:
            self._client.headers["User-Agent"] = self._get_next_user_agent()

    def _apply_referer(self):
        if self._client and self.rotate_referer and self._referers:
            self._client.headers["Referer"] = random.choice(self._referers)

    def _apply_accept_language(self):
        if self._client and self.stealth_enabled and self._accept_languages:
            self._client.headers["Accept-Language"] = random.choice(self._accept_languages)

    async def _prepare_request(self):
        self._refresh_user_agent()
        self._apply_referer()
        self._apply_accept_language()
        await self._apply_rate_limit()
        await self._apply_jitter()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        await self._prepare_request()
        return await self._execute(self._client.get(url, **kwargs))

    async def post(self, url: str, **kwargs) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        await self._prepare_request()
        return await self._execute(self._client.post(url, **kwargs))

    async def head(self, url: str, **kwargs) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        await self._prepare_request()
        return await self._execute(self._client.head(url, **kwargs))

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        if not self._client:
            raise RuntimeError("HttpClient must be used as async context manager")
        await self._prepare_request()
        return await self._execute(self._client.request(method, url, **kwargs))

    async def request_unique(
        self,
        method: str,
        url: str,
        force: bool = False,
        **kwargs,
    ) -> Optional[httpx.Response]:
        """Send request only if it hasn't been made before (dedup-aware).

        When dedup_enabled is True and force is False, duplicate (method, url)
        pairs return None instead of making a redundant request.
        """
        if not force and self._is_duplicate(method, url):
            return None
        return await self.request(method, url, **kwargs)
