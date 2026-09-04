# recon_wp/steps/webapp/stack_trace_step.py
"""
Stack trace / verbose error leak check.

Covers WSTG 4.8.1-4.8.2 (Improper Error Handling, Stack Traces): probes
endpoints with malformed input shapes (recon only, no injection payloads)
and looks for verbose framework error output.
"""

# WHAT: Detects stack traces and verbose errors in HTTP responses
# HOW: Sends malformed-shape query probes, matches known error signatures
# WHY: Stack traces leak code paths, frameworks, versions, and config

from base.http_step import BaseHttpStep
from core.finding import Finding

PROBE_PATHS = [
    ("?probe=1'", "single quote"),
    ("?probe=%", "malformed percent encoding"),
    ("?probe[]=", "array parameter"),
    ("?probe=1%00", "null byte"),
]

ERROR_SIGNATURES: list[tuple[str, str, str]] = [
    # (name, regex, framework)
    ("Python traceback", r"(?i)traceback \(most recent call last\)", "Python"),
    ("Generic stack trace", r"(?i)stack\s*trace\s*:", "unknown"),
    ("Unhandled exception", r"(?i)\bunhandled exception\b", "unknown"),
    ("PHP fatal error", r"(?i)\bfatal error\b.*\b(in|on line)\b", "PHP"),
    ("PHP parse error", r"(?i)syntax error, unexpected", "PHP"),
    ("Django error", r"(?i)django\.(?:core|db|views)", "Django"),
    ("Rails error", r"(?i)(?:actionpack|activerecord|railtie)\b", "Rails"),
    (".NET exception", r"(?i)System\.(?:Exception|Web\.HttpUtilities)", ".NET"),
    ("Spring exception", r"(?i)org\.springframework\.[\w.]+Exception", "Spring"),
    ("Java exception", r"(?i)java\.lang\.\w+Exception", "Java"),
    ("SQL state leak", r"(?i)SQLSTATE\[\d{5}\]", "SQL"),
    (
        "Internal path leak",
        r"(?i)(?:/var/www|C:\\\\|/app/|/src/)[\w./-]+\.\w+ on line \d+",
        "unknown",
    ),
]


class StackTraceStep(BaseHttpStep):
    """Detect stack traces and verbose error messages."""

    name = "stack_trace"
    description = "Detect stack traces and verbose error messages"
    severity = "medium"
    MODULE = "webapp"

    async def run(self) -> list[Finding]:
        self.logger.info("Probing for stack traces and verbose errors...")

        reported: set[str] = set()

        for suffix, label in PROBE_PATHS:
            try:
                response = await self.fetch(f"/{suffix.lstrip('/')}")
            except Exception as e:
                self.logger.debug(f"Probe {label} failed: {e}")
                continue

            status = response.status_code
            text = getattr(response, "text", "") or ""
            if status < 400 or not text:
                continue

            for name, pattern, framework in ERROR_SIGNATURES:
                if name in reported:
                    continue
                if _matches(pattern, text):
                    reported.add(name)
                    excerpt = _excerpt_around(text, pattern, max_len=300)
                    self._add_finding(
                        module=self.MODULE,
                        severity=self.severity,
                        title=f"{name} leaked in error response",
                        description=(
                            f"A malformed {label} probe ({self.target.url}/"
                            f"{suffix.lstrip('/')}) returned HTTP {status} "
                            f"containing a {name}"
                            + (f" ({framework})" if framework != "unknown" else "")
                            + "."
                        ),
                        evidence=excerpt,
                        recommendation=(
                            "Disable debug mode and return generic error pages "
                            "in production; log details server-side only"
                        ),
                        raw={
                            "probe": suffix,
                            "label": label,
                            "status": status,
                            "signature": name,
                            "framework": framework,
                        },
                    )
                    self.logger.info(f"Stack trace signature found: {name}")

        if not reported:
            self.logger.info("No verbose error signatures detected")

        return self.findings


def _matches(pattern: str, text: str) -> bool:
    import re

    return re.search(pattern, text) is not None


def _excerpt_around(text: str, pattern: str, max_len: int = 300) -> str:
    import re

    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return text[:max_len]
    start = max(0, match.start() - 80)
    return text[start : start + max_len].replace("\n", " ")
