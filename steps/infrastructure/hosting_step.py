# WHAT: Fingerprint WordPress hosting provider from response headers and IP ranges
# HOW: HTTP header analysis for known provider signals, plus CDN detection
# WHY: Hosting provider determines attack surface and available mitigation options

from base.http_step import BaseHttpStep
from core.finding import Finding


class HostingStep(BaseHttpStep):
    name = "hosting"
    description = "Detect WordPress hosting provider from response headers"
    severity = "info"
    MODULE = "infrastructure"

    SIGNALS: dict[str, list[tuple[str, str | None]]] = {
        "WP Engine": [
            ("X-WP-Engine", None),
        ],
        "Kinsta": [
            ("X-Kinsta", None),
        ],
        "Pantheon": [
            ("X-Pantheon-Styx-Hostname", None),
        ],
        "Cloudways": [
            ("X-Cloudways", None),
        ],
        "Flywheel": [
            ("X-Flywheel", None),
        ],
        "WordPress.com": [
            ("x-hacker", None),
        ],
        "wpX": [
            ("x-wpx-token", None),
        ],
        "Pressable": [
            ("x-pressable", None),
        ],
        "SiteGround": [
            ("x-sg-origin", None),
            ("x-sg-nginx", None),
        ],
        "GoDaddy": [
            ("X-Proxy-Scheme", None),
        ],
    }

    BEDROCK_PATH_SIGNAL = "web/app/"

    async def run(self) -> list[Finding]:
        self.logger.info("Detecting hosting platform...")

        if self.target is None:
            return self.findings
        try:
            resp = await self.http.get(self.target.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text
        except Exception as e:
            self.logger.debug(f"Hosting detection failed: {e}")
            return self.findings

        detected = self._detect_from_headers(headers)

        if not detected and self._is_bedrock(body):
            detected = ["Bedrock (roots.io)"]

        if detected:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title=f"Hosting platform detected: {', '.join(detected)}",
                description=f"Detected {len(detected)} hosting platform signal(s)",
                evidence="\n".join(f"  - {d}" for d in detected),
                recommendation=(
                    "Knowing the hosting provider helps tailor further "
                    "reconnaissance and select appropriate exploit paths."
                ),
                raw={"platforms": detected, "headers_matched": [
                    {d: dict(headers)} for d in detected
                ]},
            )
        else:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Hosting platform not detected",
                description="No known hosting provider signatures found in response headers",
                evidence="Checked response headers and page source for provider signals",
                recommendation="No action needed.",
                raw={"detected": False, "checked_headers": list(headers.keys())},
            )

        return self.findings

    def _detect_from_headers(self, headers: dict[str, str]) -> list[str]:
        found = []
        for platform, signals in self.SIGNALS.items():
            for header_name, _ in signals:
                if header_name.lower() in headers:
                    found.append(platform)
                    break
        return found

    def _is_bedrock(self, body: str) -> bool:
        return self.BEDROCK_PATH_SIGNAL in body
