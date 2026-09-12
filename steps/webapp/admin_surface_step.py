# recon_wp/steps/webapp/admin_surface_step.py
"""
Admin/management surface enumeration - probes for exposed management consoles
and service/debug endpoints.

Covers WSTG 4.2.5 (Enumerate Infrastructure and Application Admin Interfaces)
and 4.2.13 (Test for Path Confusion): probes a wordlist of common admin,
monitoring, and debug paths and reports what responds.
"""

# WHAT: Enumerates exposed admin/management/service interfaces
# HOW: Probes a wordlist of common console/debug paths, reports 2xx (exposed)
#      and 401/403 (protected) responses with page-title identification
# WHY: Exposed Grafana/Jenkins/actuator-style consoles are a frequent path
#      to credential access, RCE, and data exfiltration

import re
from typing import Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.soft404 import Soft404Detector

DEFAULT_ADMIN_PATHS = [
    "admin",
    "admin/",
    "administrator",
    "manager/html",
    "catalina",
    "grafana",
    "grafana/login",
    "jenkins",
    "jenkins/login",
    "kibana",
    "solr",
    "solr/admin",
    "nagios",
    "zabbix",
    "airflow",
    "superset",
    "minio",
    "registry/v2/",
    "console",
    "phpmyadmin",
    "phpmyadmin/index.php",
    "pma",
    "adminer",
    "horizon",
    "webconsole",
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/heapdump",
    "actuator/mappings",
    "actuator/configprops",
    "debug",
    "debug/vars",
    "trace",
    "error",
    "server-status",
    "server-info",
    "status",
    "health",
    "metrics",
    "prometheus",
    "node_modules",
    ".well-known/security.txt",
]

# Severity when a path responds 2xx. Unlisted paths default to "info".
PATH_SEVERITIES: dict[str, str] = {
    "actuator/heapdump": "high",
    "actuator/env": "high",
    "debug/vars": "high",
    "admin": "medium",
    "admin/": "medium",
    "administrator": "medium",
    "manager/html": "medium",
    "catalina": "low",
    "grafana": "medium",
    "grafana/login": "medium",
    "jenkins": "medium",
    "jenkins/login": "medium",
    "kibana": "medium",
    "solr": "medium",
    "solr/admin": "medium",
    "nagios": "medium",
    "zabbix": "medium",
    "airflow": "medium",
    "superset": "medium",
    "minio": "medium",
    "registry/v2/": "medium",
    "console": "medium",
    "phpmyadmin": "medium",
    "phpmyadmin/index.php": "medium",
    "pma": "medium",
    "adminer": "medium",
    "horizon": "medium",
    "webconsole": "medium",
    "actuator": "low",
    "actuator/mappings": "low",
    "actuator/configprops": "low",
    "debug": "medium",
    "trace": "low",
    "error": "info",
    "server-status": "low",
    "server-info": "low",
    "status": "info",
    "health": "info",
    "metrics": "info",
    "prometheus": "info",
    "node_modules": "info",
    "actuator/health": "info",
    ".well-known/security.txt": "info",
}

_MAX_PROTECTED_LIST = 10

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(text: str) -> str:
    """Extract a cleaned <title> from HTML, or "" if absent."""
    match = _TITLE_RE.search(text or "")
    if not match:
        return ""
    return " ".join(match.group(1).split())[:80]


class AdminSurfaceStep(BaseHttpStep, WordlistDependencyMixin):
    """Enumerate exposed admin/management/service interfaces."""

    name = "admin_surface"
    description = "Enumerate exposed admin/management/service interfaces"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Enumerating admin/management surface...")

        paths = self.resolve_wordlist_or_fallback(
            config_key="admin_paths",
            defaults=DEFAULT_ADMIN_PATHS,
            name="admin path wordlist",
            wordlist_file="webapp/admin_paths.txt",
        )
        if not paths:
            return self.findings

        max_paths = getattr(self.config, "webapp_max_admin_paths", 40)
        unique_paths = list(
            dict.fromkeys(p.strip().lstrip("/") for p in paths if p.strip())
        )
        unique_paths = unique_paths[:max_paths]

        # Calibrate against a guaranteed-nonexistent path. SPA routers and
        # soft-404 handlers return the app shell (200) for it - any probed
        # path matching that fingerprint is a false positive, not a real page.
        detector = Soft404Detector(
            self.http, self.target.url, self.logger
        )
        await detector.calibrate()

        protected: list[str] = []
        security_txt: Optional[str] = None
        skipped_baseline = 0

        for path in unique_paths:
            try:
                response = await self.fetch(path)
            except Exception as e:
                self.logger.debug(f"GET {path} failed: {e}")
                continue

            status = response.status_code
            text = getattr(response, "text", "") or ""

            if status == 200:
                if path == "security.txt" or path.endswith("security.txt"):
                    security_txt = text
                    continue
                if detector.is_soft404(response):
                    skipped_baseline += 1
                    continue
                title = extract_title(text)
                severity = PATH_SEVERITIES.get(path, "info")
                url = self.urljoin(path)
                self._add_finding(
                    module=self.MODULE,
                    severity=severity,
                    title=f"Admin/management surface exposed: /{path}",
                    description=(
                        f"/{path} responds with HTTP 200"
                        + (f" (title: {title})" if title else "")
                        + ". Management interfaces should not be publicly "
                        "accessible."
                    ),
                    evidence=f"GET {url} -> HTTP 200 {title}".strip(),
                    recommendation=(
                        "Remove the interface or restrict it to authenticated "
                        "administrators and internal networks"
                    ),
                    raw={"path": path, "url": url, "status": status,
                         "title": title},
                )
            elif status in (401, 403):
                protected.append(path)
            # 404 and other codes: not interesting, skip

        if skipped_baseline:
            self.logger.debug(
                f"Admin surface: {skipped_baseline} path(s) skipped as "
                f"SPA/soft-404 baseline matches"
            )

        if protected:
            protected_urls = [self.urljoin(p) for p in protected]
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Admin interfaces behind authentication",
                description=(
                    "Path(s) requiring authentication (401/403): "
                    + ", ".join(protected_urls[:_MAX_PROTECTED_LIST])
                ),
                evidence=", ".join(protected_urls[:_MAX_PROTECTED_LIST]),
                recommendation=(
                    "Verify these interfaces enforce strong authentication "
                    "and are not reachable with default credentials"
                ),
                raw={"paths": protected, "urls": protected_urls},
            )

        if security_txt is not None:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="security.txt published",
                description=(
                    "An RFC 9116 security policy is published at "
                    "/.well-known/security.txt."
                ),
                evidence=" ".join(security_txt.split())[:200],
                recommendation="Keep the security contact details in security.txt current",
                raw={"length": len(security_txt)},
            )

        self.logger.info(
            f"Admin surface: {len(self.findings)} finding(s), "
            f"{len(protected)} protected path(s)"
        )
        return self.findings
