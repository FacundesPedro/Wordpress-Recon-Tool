# recon_wp/steps/webapp/api_surface_step.py
"""
API surface discovery - maps API roots, documentation, and GraphQL endpoints.

Covers WSTG 4.12.1 (API Reconnaissance), 4.12.99 (Testing GraphQL), and
4.1.4 (Attack Surface Identification): probes robots.txt, sitemaps, and
common API/OpenAPI documentation paths; tests GraphQL introspection.
"""

# WHAT: Discovers API endpoints, OpenAPI/Swagger docs, and GraphQL endpoints
# HOW: Probes a wordlist of API/doc paths, parses robots.txt and sitemaps,
#      and POSTs a harmless GraphQL introspection query
# WHY: Exposed API documentation and introspection are a primary attack
#      surface for enumeration and authorization testing

import json
import re
from typing import Any, Optional

from base.dependencies import WordlistDependencyMixin
from base.http_step import BaseHttpStep
from core.finding import Finding
from utils.http_validation import is_robots, is_xml_body

DEFAULT_API_PATHS = [
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "api",
    "api/",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/graphql",
    "graphql",
    "rest",
    "rest/api",
    "v1",
    "v2",
    "swagger.json",
    "swagger-ui.html",
    "swagger-ui/",
    "swagger-ui/index.html",
    "api-docs",
    "openapi.json",
    "openapi.yaml",
    "v2/api-docs",
    "v3/api-docs",
    "docs",
    "redoc",
]

GRAPHQL_PATHS = {"graphql", "api/graphql"}
ROBOTS_PATHS = {"robots.txt"}
SITEMAP_PATHS = {"sitemap.xml", "sitemap_index.xml"}
OPENAPI_JSON_PATHS = {
    "swagger.json",
    "openapi.json",
    "api-docs",
    "v2/api-docs",
    "v3/api-docs",
}
OPENAPI_YAML_PATHS = {"openapi.yaml"}

GRAPHQL_INTROSPECTION = {"query": "{__schema{types{name}}}"}
_SENSITIVE_HINTS = (
    "admin",
    "user",
    "auth",
    "login",
    "internal",
    "export",
    "backup",
    "debug",
    "token",
    "key",
    "secret",
)
_MAX_SENSITIVE_PATHS = 10
_MAX_ROBOTS_PATHS = 10
_MAX_SITEMAP_SAMPLES = 10
_MAX_GRAPHQL_TYPES = 20
_MAX_ENDPOINT_LIST = 15

_SITEMAP_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str) -> dict:
    """Parse robots.txt into Disallow entries and Sitemap references."""
    disallowed: list[str] = []
    sitemaps: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        lowered = line.lower()
        if lowered.startswith("disallow:") and len(line) > 9:
            value = line.split(":", 1)[1].strip()
            if value:
                disallowed.append(value)
        elif lowered.startswith("sitemap:") and len(line) > 8:
            value = line.split(":", 1)[1].strip()
            if value:
                sitemaps.append(value)
    return {"disallowed": disallowed, "sitemaps": sitemaps}


def parse_sitemap(text: str) -> list[str]:
    """Extract <loc> URL entries from a sitemap XML document."""
    return [u.strip() for u in _SITEMAP_LOC_RE.findall(text or "") if u.strip()]


def _try_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _looks_like_openapi(text: str) -> bool:
    head = (text or "").lstrip()[:500]
    return head.startswith("{") and ('"openapi"' in head or '"swagger"' in head)


class ApiSurfaceStep(BaseHttpStep, WordlistDependencyMixin):
    """Discover API endpoints, documentation, and GraphQL surface."""

    name = "api_surface"
    description = "Discover API endpoints, OpenAPI/Swagger docs, and GraphQL"
    severity = "high"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Discovering API surface...")

        paths = self.resolve_wordlist_or_fallback(
            config_key="api_paths",
            defaults=DEFAULT_API_PATHS,
            name="API path wordlist",
            wordlist_file="webapp/api_paths.txt",
        )
        if not paths:
            return self.findings

        max_paths = getattr(self.config, "webapp_max_api_paths", 30)
        unique_paths = list(dict.fromkeys(p.strip().lstrip("/") for p in paths if p.strip()))
        unique_paths = unique_paths[:max_paths]

        api_endpoints: list[tuple[str, str]] = []
        swagger_ui: list[tuple[str, str]] = []
        openapi_docs: list[tuple[str, Any, str]] = []
        graphql_open: list[tuple[str, str, list[str]]] = []
        graphql_present: list[tuple[str, str]] = []
        robots_disallowed: list[str] = []
        robots_url: Optional[str] = None
        sitemaps: list[str] = []
        sitemap_urls: list[str] = []
        sitemap_source: Optional[str] = None

        # Calibrate against a nonexistent path: SPA catch-all servers return
        # the app shell (200) for every unknown path, which would otherwise
        # be reported as "API endpoint discovered".
        from utils.soft404 import Soft404Detector

        detector = Soft404Detector(self.http, self.target.url, self.logger)
        await detector.calibrate()

        for path in unique_paths:
            if path in ROBOTS_PATHS:
                response = await self._get(path)
                if (
                    response is not None
                    and response.status_code == 200
                    and is_robots(response)
                ):
                    parsed = parse_robots(getattr(response, "text", "") or "")
                    robots_disallowed.extend(parsed["disallowed"])
                    sitemaps.extend(parsed["sitemaps"])
                    robots_url = self.urljoin(path)
            elif path in SITEMAP_PATHS:
                response = await self._get(path)
                if (
                    response is not None
                    and response.status_code == 200
                    and is_xml_body(response)
                ):
                    sitemap_urls.extend(parse_sitemap(getattr(response, "text", "") or ""))
                    sitemap_source = self.urljoin(path)
            elif path in GRAPHQL_PATHS:
                await self._probe_graphql(
                    path, self.urljoin(path), graphql_open, graphql_present
                )
            else:
                response = await self._get(path)
                if response is None or response.status_code != 200:
                    continue
                if detector.is_soft404(response):
                    continue
                text = getattr(response, "text", "") or ""
                if not text:
                    continue
                url = self.urljoin(path)
                data = _try_json(text)
                if (
                    (path in OPENAPI_JSON_PATHS or _looks_like_openapi(text))
                    and isinstance(data, dict)
                    and "paths" in data
                ):
                    openapi_docs.append((path, data, url))
                    continue
                if path in OPENAPI_YAML_PATHS and text.lstrip().startswith("openapi:"):
                    openapi_docs.append((path, None, url))
                    continue
                head = text[:2000].lower()
                if "swagger-ui" in head or "swaggerui" in head or "redoc" in head:
                    swagger_ui.append((path, url))
                    continue
                if isinstance(data, (dict, list)):
                    api_endpoints.append((path, url))

        self._emit_findings(
            api_endpoints=api_endpoints,
            swagger_ui=swagger_ui,
            openapi_docs=openapi_docs,
            graphql_open=graphql_open,
            graphql_present=graphql_present,
            robots_disallowed=robots_disallowed,
            robots_url=robots_url,
            sitemaps=sitemaps,
            sitemap_urls=sitemap_urls,
            sitemap_source=sitemap_source,
        )
        return self.findings

    async def _get(self, path: str):
        try:
            return await self.fetch(path)
        except Exception as e:
            self.logger.debug(f"GET {path} failed: {e}")
            return None

    async def _probe_graphql(
        self, path: str, url: str, graphql_open: list, graphql_present: list
    ) -> None:
        """POST a harmless introspection query to a GraphQL candidate."""
        try:
            response = await self.post(
                path,
                json=GRAPHQL_INTROSPECTION,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            self.logger.debug(f"GraphQL probe {path} failed: {e}")
            return

        status = response.status_code
        text = getattr(response, "text", "") or ""
        data = _try_json(text)
        if status not in (200, 400, 403) or not isinstance(data, dict):
            return

        inner = data.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("types"), list) and inner["types"]:
            names = [
                t.get("name", "?") for t in inner["types"] if isinstance(t, dict)
            ]
            graphql_open.append((path, url, names))
            self.logger.info(f"GraphQL introspection enabled at {path}")
        elif data.get("errors") or "query" in text.lower():
            graphql_present.append((path, url))

    def _emit_findings(self, **kwargs) -> None:
        openapi_docs = kwargs["openapi_docs"]
        for path, data, url in openapi_docs:
            if isinstance(data, dict):
                paths_map = data.get("paths") or {}
                total_ops = 0
                sensitive: list[str] = []
                if isinstance(paths_map, dict):
                    for p, methods in paths_map.items():
                        if isinstance(methods, dict):
                            total_ops += len(methods)
                        if any(h in p.lower() for h in _SENSITIVE_HINTS) and len(
                            sensitive
                        ) < _MAX_SENSITIVE_PATHS:
                            sensitive.append(p)
                description = (
                    f"API documentation at {path} exposes the OpenAPI/Swagger "
                    f"specification ({total_ops} operations across "
                    f"{len(paths_map) if isinstance(paths_map, dict) else '?'} "
                    "paths)."
                )
            else:
                total_ops = 0
                sensitive = []
                description = (
                    f"API documentation at {path} exposes an OpenAPI "
                    "specification."
                )
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title="OpenAPI/Swagger documentation exposed",
                description=description,
                evidence=url,
                recommendation=(
                    "Remove or authenticate the API documentation in "
                    "production deployments"
                ),
                raw={
                    "path": path,
                    "url": url,
                    "endpoint_count": total_ops,
                    "sensitive_paths": sensitive,
                    "spec_version": (
                        (data.get("openapi") or data.get("swagger"))
                        if isinstance(data, dict)
                        else None
                    ),
                },
            )

        if kwargs["swagger_ui"]:
            entries = kwargs["swagger_ui"]
            paths = [p for p, _ in entries]
            urls = [u for _, u in entries]
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Swagger UI exposed",
                description=(
                    "Swagger UI documentation interface(s) are publicly "
                    "accessible: " + ", ".join(paths[:5])
                ),
                evidence=", ".join(urls[:5]),
                recommendation=(
                    "Remove or protect Swagger UI in production deployments"
                ),
                raw={"paths": paths, "urls": urls},
            )

        for path, url, names in kwargs["graphql_open"]:
            self._add_finding(
                module=self.MODULE,
                severity="high",
                title=f"GraphQL introspection enabled at {path}",
                description=(
                    f"The GraphQL endpoint at {path} answers introspection "
                    f"queries, exposing its full schema ({len(names)} types)."
                ),
                evidence=url,
                recommendation=(
                    "Disable introspection in production or require "
                    "authentication for the GraphQL endpoint"
                ),
                raw={
                    "path": path,
                    "url": url,
                    "type_count": len(names),
                    "types": names[:_MAX_GRAPHQL_TYPES],
                },
            )

        if kwargs["graphql_present"]:
            entries = kwargs["graphql_present"]
            paths = [p for p, _ in entries]
            urls = [u for _, u in entries]
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="GraphQL endpoint present",
                description=(
                    "GraphQL endpoint(s) detected (introspection not "
                    "answered): " + ", ".join(paths)
                ),
                evidence=", ".join(urls),
                recommendation=(
                    "Manually test the GraphQL endpoint for broken object "
                    "level authorization and excessive data exposure"
                ),
                raw={"paths": paths, "urls": urls},
            )

        if kwargs["api_endpoints"]:
            entries = kwargs["api_endpoints"][:_MAX_ENDPOINT_LIST]
            paths = [p for p, _ in entries]
            urls = [u for _, u in entries]
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="API endpoints discovered",
                description=(
                    f"Responsive API endpoint(s) found: {', '.join(paths)}"
                ),
                evidence=", ".join(urls),
                recommendation=(
                    "Review the discovered API endpoints for unauthenticated "
                    "access and missing authorization"
                ),
                raw={"paths": paths, "urls": urls},
            )

        if kwargs["robots_disallowed"]:
            disallowed = list(dict.fromkeys(kwargs["robots_disallowed"]))[
                :_MAX_ROBOTS_PATHS
            ]
            robots_url = kwargs.get("robots_url")
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="robots.txt discloses restricted paths",
                description=(
                    "robots.txt lists disallowed path(s) that reveal internal "
                    "structure: " + ", ".join(disallowed)
                ),
                evidence=robots_url or ", ".join(disallowed),
                recommendation=(
                    "Avoid revealing internal paths in robots.txt; these "
                    "hints are public attack surface"
                ),
                raw={
                    "url": robots_url,
                    "disallowed": kwargs["robots_disallowed"],
                },
            )

        if kwargs["sitemaps"] or kwargs["sitemap_urls"]:
            total = len(kwargs["sitemap_urls"])
            description = "Sitemap URL inventory discovered."
            if kwargs["sitemaps"]:
                description = (
                    "Sitemap reference(s) found in robots.txt: "
                    + ", ".join(kwargs["sitemaps"][:5])
                )
            if total:
                description += f" {total} URL(s) enumerated from sitemap."
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Sitemap URL inventory exposed",
                description=description,
                evidence=", ".join(kwargs["sitemap_urls"][:_MAX_SITEMAP_SAMPLES])
                or (kwargs.get("sitemap_source") or ""),
                recommendation=(
                    "Review the sitemap inventory for sensitive paths "
                    "(staging, internal, export endpoints)"
                ),
                raw={
                    "sitemaps": kwargs["sitemaps"],
                    "url": kwargs.get("sitemap_source"),
                    "url_count": total,
                    "sample": kwargs["sitemap_urls"][:_MAX_SITEMAP_SAMPLES],
                },
            )
