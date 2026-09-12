# recon_wp/steps/discovery/wp_cron_step.py
"""
WP-Cron enumeration - checks for wp-cron.php accessibility.

Detects if wp-cron.php is accessible (potential DoS/abuse vector).
"""

# WHAT: Checks if wp-cron.php is accessible without authentication
# HOW: HTTP GET to wp-cron.php with doing_wp_cron param
# WHY: Can be abused for DoS (executes MySQL queries on every request)

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector, is_html_body


class WpCronStep(BaseHttpStep):
    """Check for wp-cron.php which can be used for DoS."""

    name = "wp_cron"
    description = "Check for wp-cron.php (potential DoS)"
    severity = "low"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping wp-cron check"
            )
            return self.findings

        self.logger.info("Checking for wp-cron.php...")
        url = self.urljoin("wp-cron.php")

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        try:
            response = await self.http.get(url, params={"doing_wp_cron": "1"})
            status = response.status_code
            body = getattr(response, "text", "") or ""
            if not isinstance(body, str):
                body = ""

            if (
                status == 200
                and not detector.is_soft404(response)
                and not is_html_body(body)
            ):
                self._add_finding(
                    module=self.MODULE,
                    severity=self.severity,
                    title="wp-cron.php is active",
                    description="wp-cron.php is accessible and may be abused for DoS attacks. "
                    "It performs MySQL queries on every page load.",
                    evidence=url,
                    recommendation="Disable wp-cron and create a real cronjob instead",
                    raw={
                        "url": url,
                        "final_url": str(getattr(response, "url", None) or url),
                        "status": status,
                    },
                )
                self.logger.info("wp-cron.php found and accessible")
            else:
                self.logger.debug(f"wp-cron.php returned status {status}")
        except Exception as e:
            self.logger.error(f"Error checking wp-cron.php: {e}")

        return self.findings
