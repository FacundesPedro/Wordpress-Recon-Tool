# WHAT: Crawl same-origin links to discover hidden forms, upload dirs, and endpoints
# HOW: Recursive HTTP GET with link extraction, respects depth and page limits
# WHY: Discovers hidden pages, exposed paths, and unintended information disclosure

import re
from urllib.parse import urljoin, urlparse

from base.http_step import BaseHttpStep
from core.finding import Finding


class SpiderStep(BaseHttpStep):
    name = "spider"
    description = "Crawl same-origin links to discover hidden forms, upload dirs, and endpoints"
    severity = "info"
    MODULE = "discovery"

    MAX_DEPTH = 2
    MAX_PAGES = 50

    UPLOAD_PATTERNS = re.compile(
        r"(/wp-content/uploads/|/uploads/|/files/|/media/)",
        re.IGNORECASE,
    )
    FORM_PATTERN = re.compile(
        r'<form[^>]*\s+action\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    ADMIN_LIKE_PATTERNS = re.compile(
        r"(/wp-admin/|/admin/|/dashboard/|/manage/)",
        re.IGNORECASE,
    )
    COMMENT_PATTERN = re.compile(
        r'<div[^>]*\s+id\s*=\s*["\']comments["\']',
        re.IGNORECASE,
    )

    async def run(self) -> list[Finding]:
        self.logger.info("Starting content spider...")

        if self.target is None:
            return self.findings

        max_depth = getattr(self.config, "spider_max_depth", self.MAX_DEPTH)
        max_pages = getattr(self.config, "spider_max_pages", self.MAX_PAGES)

        start_url = self.target.url.rstrip("/")
        domain = urlparse(start_url).netloc

        forbidden_paths = await self._fetch_robots(start_url)

        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(start_url, 0)]

        discovered_forms: list[str] = []
        discovered_uploads: list[str] = []
        discovered_admin: list[str] = []
        has_comments = False

        while to_visit and len(visited) < max_pages:
            url, depth = to_visit.pop(0)

            if url in visited:
                continue
            visited.add(url)

            if self._is_forbidden(url, forbidden_paths, start_url):
                self.logger.debug(f"Skipping disallowed: {url}")
                continue

            try:
                resp = await self.http.get(url, follow_redirects=True)
            except Exception as e:
                self.logger.debug(f"Error fetching {url}: {e}")
                continue

            if resp.status_code != 200:
                continue

            body = resp.text

            for match in self.FORM_PATTERN.finditer(body):
                action = match.group(1)
                absolute = urljoin(url, action)
                if absolute not in discovered_forms:
                    discovered_forms.append(absolute)

            for match in self.UPLOAD_PATTERNS.finditer(body):
                if match.group(0) not in discovered_uploads:
                    discovered_uploads.append(match.group(0))

            for match in self.ADMIN_LIKE_PATTERNS.finditer(body):
                if match.group(0) not in discovered_admin:
                    discovered_admin.append(match.group(0))

            if self.COMMENT_PATTERN.search(body):
                has_comments = True

            if depth < max_depth:
                for href in self._extract_links(body, start_url):
                    abs_url = urljoin(url, href)
                    if self._is_same_origin(abs_url, domain) and abs_url not in visited:
                        to_visit.append((abs_url, depth + 1))

        self.logger.info(
            f"Spider completed: {len(visited)} pages visited, "
            f"{len(discovered_forms)} forms, {len(discovered_uploads)} upload dirs"
        )

        if discovered_forms:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Discovered form actions from spidering",
                description=f"Found {len(discovered_forms)} form action(s) across crawled pages",
                evidence="\n".join(f"  - {f}" for f in discovered_forms),
                recommendation="Review each form for CSRF protection and input validation.",
                raw={
                    "forms": discovered_forms,
                    "pages_visited": len(visited),
                },
            )

        if discovered_uploads:
            self._add_finding(
                module=self.MODULE,
                severity="medium",
                title="Upload directories discovered via crawling",
                description=f"Found {len(discovered_uploads)} upload/storage path reference(s)",
                evidence="\n".join(f"  - {u}" for u in discovered_uploads),
                recommendation=(
                    "Ensure upload directories have directory listing "
                    "disabled and validate file upload MIME types."
                ),
                raw={
                    "upload_dirs": discovered_uploads,
                    "pages_visited": len(visited),
                },
            )

        if discovered_admin:
            self._add_finding(
                module=self.MODULE,
                severity="info",
                title="Admin-like paths discovered via crawling",
                description=f"Found {len(discovered_admin)} admin/dashboard path reference(s)",
                evidence="\n".join(f"  - {a}" for a in discovered_admin),
                recommendation="Restrict access to admin and dashboard paths.",
                raw={
                    "admin_paths": discovered_admin,
                    "pages_visited": len(visited),
                },
            )

        self._add_finding(
            module=self.MODULE,
            severity="info",
            title="Content crawl summary",
            description=(
                f"Crawled {len(visited)} pages across {max_depth} depth "
                f"level(s). Found: {len(discovered_forms)} forms, "
                f"{len(discovered_uploads)} upload dirs, "
                f"{'comments section' if has_comments else 'no comments'}."
            ),
            evidence=(
                f"Pages visited: {len(visited)}\n"
                f"Forms: {len(discovered_forms)}\n"
                f"Upload dirs: {len(discovered_uploads)}\n"
                f"Admin paths: {len(discovered_admin)}\n"
                f"Comments: {'yes' if has_comments else 'no'}"
            ),
            recommendation="No action needed.",
            raw={
                "pages_visited": len(visited),
                "max_depth": max_depth,
                "max_pages": max_pages,
                "urls_visited": sorted(visited),
                "forms": discovered_forms,
                "upload_dirs": discovered_uploads,
                "admin_paths": discovered_admin,
                "has_comments": has_comments,
            },
        )

        return self.findings

    async def _fetch_robots(self, base_url: str) -> list[str]:
        try:
            resp = await self.http.get(f"{base_url}/robots.txt")
            if resp.status_code == 200:
                disallowed = re.findall(
                    r"^Disallow:\s*(.+)$", resp.text, re.MULTILINE
                )
                return [d.strip() for d in disallowed if d.strip()]
        except Exception:
            pass
        return []

    def _is_forbidden(self, url: str, forbidden: list[str], base_url: str) -> bool:
        path = url.replace(base_url, "")
        for rule in forbidden:
            if rule == "/" and url != base_url:
                continue
            if rule and path.startswith(rule):
                return True
        return False

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        hrefs = re.findall(r'href\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
        result = []
        for href in hrefs:
            href = href.strip()
            if href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            if href.startswith("http"):
                result.append(href)
            else:
                result.append(urljoin(base_url, href))
        return result

    def _is_same_origin(self, url: str, domain: str) -> bool:
        try:
            return urlparse(url).netloc == domain
        except Exception:
            return False
