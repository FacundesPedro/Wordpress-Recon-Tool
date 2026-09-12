# recon_wp/steps/discovery/woocommerce_step.py
"""
WooCommerce detection and Store API surface enumeration.

Detects WooCommerce via the Store API (`/wp-json/wc/store/v1/products`),
`/?wc-ajax=` AJAX endpoints, and plugin path markers; extracts the version
from readme.txt when exposed; reports exposed store endpoints (cart,
checkout, my-account, order-received).
"""

# WHAT: Detects WooCommerce and maps its exposed store surface
# HOW: Store API + wc-ajax probes + readme.txt version extraction
# WHY: WooCommerce stores expose order/customer endpoints that warrant
#      dedicated review (Store API is unauthenticated by design)

import re
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.http_validation import is_json_body
from utils.soft404 import Soft404Detector

STORE_API = "wp-json/wc/store/v1/products"
WC_AJAX_FRAGMENT = "?wc-ajax=get_refreshed_fragments"

STORE_PATHS = [
    "cart/",
    "checkout/",
    "my-account/",
    "my-account/orders/",
    "my-account/downloads/",
    "shop/",
    "product-category/",
    "order-received/",
]

MAX_FINDINGS = 8


def extract_version(readme: str) -> Optional[str]:
    """Extract the stable tag from a WooCommerce readme.txt."""
    match = re.search(r"Stable tag:\s*([\d.]+)", readme or "", re.I)
    return match.group(1) if match else None


class WooCommerceStep(BaseHttpStep):
    """Detect WooCommerce and enumerate its exposed store surface."""

    name = "woocommerce"
    description = "Detect WooCommerce and enumerate Store API/cart surface"
    severity = "info"
    MODULE = "discovery"

    async def run(self) -> list[Finding]:
        from utils.wordpress_detect import is_wordpress

        if not await is_wordpress(self.http, self.target.url, self.logger):
            self.logger.info(
                "Target does not appear to be WordPress - skipping WooCommerce check"
            )
            return self.findings

        self.logger.info("Probing for WooCommerce...")

        detected = await self._detect()
        if not detected:
            self.logger.info("WooCommerce: not detected")
            return self.findings

        version = await self._detect_version()
        self._add_finding(
            module=self.MODULE,
            severity="info",
            title="WooCommerce detected" + (f" (version {version})" if version else ""),
            description=(
                f"WooCommerce is installed ({detected}). The Store API exposes "
                f"unauthenticated store endpoints that should be reviewed."
            ),
            evidence=detected,
            recommendation="Review Store API exposure and cart/checkout flows",
            raw={"signal": detected, "version": version},
        )

        if version:
            self._add_finding(
                module=self.MODULE,
                severity="low",
                title=f"WooCommerce version disclosed ({version})",
                description=(
                    "The WooCommerce version is publicly readable via "
                    "readme.txt. Version disclosure aids targeted research."
                ),
                evidence=f"readme.txt Stable tag: {version}",
                recommendation="Block access to plugin readme files at the web server",
                raw={"version": version},
            )

        # exposed store paths
        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()
        for path in STORE_PATHS:
            if len(self.findings) >= MAX_FINDINGS:
                break
            try:
                response = await self.fetch(path)
            except Exception as e:
                self.logger.debug(f"Store path {path} failed: {e}")
                continue
            status = getattr(response, "status_code", None)
            if status != 200:
                continue
            if detector.is_soft404(response):
                self.logger.debug(
                    f"Store path {path}: SPA/soft-404 shell - skipped"
                )
                continue
            if "cart" in path or "checkout" in path or "my-account" in path:
                url = self.urljoin(path)
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title=f"Store endpoint exposed: {path}",
                    description=(
                        f"The WooCommerce endpoint {path} is publicly "
                        f"reachable. Include it in manual review scope."
                    ),
                    evidence=f"GET {url} -> 200",
                    recommendation="Verify authentication requirements on account endpoints",
                    raw={"path": path, "url": url},
                )

        # wc-ajax endpoint
        try:
            response = await self.fetch(WC_AJAX_FRAGMENT)
            if getattr(response, "status_code", None) == 200 and is_json_body(response):
                ajax_url = self.urljoin(WC_AJAX_FRAGMENT)
                self._add_finding(
                    module=self.MODULE,
                    severity="info",
                    title="WooCommerce AJAX endpoint active",
                    description=(
                        "The wc-ajax fragment refresh endpoint responds. "
                        "It is a common target for abuse/cart manipulation "
                        "testing."
                    ),
                    evidence=f"GET {ajax_url} -> 200",
                    recommendation="Rate-limit wc-ajax endpoints; verify session handling",
                    raw={"path": WC_AJAX_FRAGMENT, "url": ajax_url},
                )
        except Exception as e:
            self.logger.debug(f"wc-ajax probe failed: {e}")

        self.logger.info(f"WooCommerce: {len(self.findings)} finding(s)")
        return self.findings

    async def _detect(self) -> Optional[str]:
        """Return a detection signal string or None."""
        try:
            response = await self.fetch(STORE_API)
            if getattr(response, "status_code", None) == 200 and is_json_body(response):
                return f"Store API reachable at {STORE_API}"
        except Exception as e:
            self.logger.debug(f"Store API probe failed: {e}")
        try:
            response = await self.fetch("/")
            if "woocommerce" in (response.text or "").lower():
                return "woocommerce marker in homepage HTML"
        except Exception:
            pass
        return None

    async def _detect_version(self) -> Optional[str]:
        try:
            response = await self.fetch("wp-content/plugins/woocommerce/readme.txt")
            if getattr(response, "status_code", None) == 200:
                return extract_version(response.text or "")
        except Exception:
            pass
        return None
