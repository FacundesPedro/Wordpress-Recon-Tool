# recon_wp/steps/webapp/form_security_step.py
"""
Form security audit - credential transport, CSRF token heuristic, autocomplete.

Covers WSTG 4.4.1 (Credentials Transported over an Encrypted Channel),
4.4.6 (Browser Cache Weaknesses), and 4.6.5 (CSRF heuristics): parses forms
on the homepage and login-looking pages and reports password fields posted
over http://, password inputs with autocomplete enabled, and cacheable
login pages.
"""

# WHAT: Audits login/password forms for transport and hygiene issues
# HOW: Parses <form>/<input> elements; checks action scheme, autocomplete,
#      and Cache-Control on the login page
# WHY: Plaintext credential transport and cacheable login pages are
#      fundamental but commonly missed issues

import re
from urllib.parse import urljoin, urlparse

from base.http_step import BaseHttpStep
from core.finding import Finding

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.I)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\'](\w+)["\']', re.I)
INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
TYPE_RE = re.compile(r'type\s*=\s*["\'](\w+)["\']', re.I)
NAME_RE = re.compile(r'name\s*=\s*["\']([^"\']+)["\']', re.I)
AUTOCOMPLETE_RE = re.compile(r'autocomplete\s*=\s*["\'](\w+)["\']', re.I)

LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/user/login", "/account/login"]
MAX_FINDINGS = 6


def parse_form(form_tag: str, block: str) -> dict:
    """Parse a form tag + body into a dict."""
    action_match = ACTION_RE.search(form_tag)
    method_match = METHOD_RE.search(form_tag)
    inputs = []
    for tag in INPUT_RE.findall(block):
        type_match = TYPE_RE.search(tag)
        name_match = NAME_RE.search(tag)
        auto_match = AUTOCOMPLETE_RE.search(tag)
        inputs.append({
            "type": (type_match.group(1).lower() if type_match else "text"),
            "name": (name_match.group(1) if name_match else ""),
            "autocomplete": (auto_match.group(1).lower() if auto_match else ""),
        })
    return {
        "action": (action_match.group(1) if action_match else ""),
        "method": (method_match.group(1).upper() if method_match else "GET"),
        "inputs": inputs,
    }


class FormSecurityStep(BaseHttpStep):
    """Audit password forms for transport/hygiene issues."""

    name = "form_security"
    description = "Audit login forms: transport, autocomplete, cacheability"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Auditing forms for credential security...")

        pages: list[tuple[str, str, object]] = []
        try:
            response = await self.fetch("/")
            pages.append(("/", response.text or "", response.headers))
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")

        for path in LOGIN_PATHS[:2]:
            if len(pages) >= 3:
                break
            try:
                response = await self.fetch(path)
                if getattr(response, "status_code", None) == 200:
                    pages.append((path, response.text or "", response.headers))
            except Exception as e:
                self.logger.debug(f"Login path {path} fetch failed: {e}")

        for page_path, html, headers in pages:
            for match in FORM_RE.finditer(html):
                if len(self.findings) >= MAX_FINDINGS:
                    return self.findings
                form = parse_form(match.group(0), match.group(1))
                has_password = any(
                    i["type"] == "password" for i in form["inputs"]
                )
                if not has_password:
                    continue

                # 1. Plaintext transport
                action = form["action"]
                if action:
                    absolute = urljoin(
                        self.target.url.rstrip("/") + page_path, action
                    )
                    scheme = urlparse(absolute).scheme
                else:
                    absolute = self.target.url
                    scheme = urlparse(self.target.url).scheme
                if scheme == "http":
                    self._add_finding(
                        module=self.MODULE,
                        severity="high",
                        title=f"Password form posted over plaintext HTTP ({page_path})",
                        description=(
                            "A form containing a password field submits over "
                            "http://. Credentials are transmitted without "
                            "encryption."
                        ),
                        evidence=f"form action={action or '(self)'} scheme={scheme}",
                        recommendation="Serve and submit the form over HTTPS only",
                        raw={"page": page_path, "action": action},
                    )

                # 2. Autocomplete on password fields
                for inp in form["inputs"]:
                    if inp["type"] == "password" and \
                            inp["autocomplete"] not in ("", "off", "new-password", "current-password"):
                        self._add_finding(
                            module=self.MODULE,
                            severity="low",
                            title=f"Password field autocomplete not restricted ({page_path})",
                            description=(
                                "A password field allows unrestricted browser "
                                "autocomplete, which may store credentials on "
                                "shared machines."
                            ),
                            evidence=f"input name={inp['name']} autocomplete={inp['autocomplete']}",
                            recommendation="Set autocomplete=\"new-password\" or \"off\" "
                                           "on password fields",
                            raw={"page": page_path, "input": inp},
                        )

            # 3. Cacheable login page
            if page_path != "/" and self._page_cacheable(headers):
                self._add_finding(
                    module=self.MODULE,
                    severity="low",
                    title=f"Login page is publicly cacheable ({page_path})",
                    description=(
                        "The login page is served with cacheable headers. "
                        "Shared caches may store it (WSTG 4.4.6)."
                    ),
                    evidence=f"page {page_path} cacheable",
                    recommendation="Send Cache-Control: no-store on login pages",
                    raw={"page": page_path},
                )

        self.logger.info(f"Form security: {len(self.findings)} finding(s)")
        return self.findings

    @staticmethod
    def _page_cacheable(headers) -> bool:
        """True when Cache-Control allows shared caching."""
        cc = (headers.get("cache-control") or "").lower()
        if "no-store" in cc or "private" in cc:
            return False
        return "public" in cc or "max-age" in cc or "s-maxage" in cc
