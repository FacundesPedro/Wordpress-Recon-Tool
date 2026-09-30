# recon_wp/utils/dns_query.py
"""``dig`` output parsing and DNS-evidence helpers.

WHAT: Build a ``dig`` command that keeps the response header and parse the full
      output, so callers can distinguish "no record" (NOERROR + 0 answers, or
      NXDOMAIN) from a resolver failure (SERVFAIL/REFUSED/timeout).
HOW:  ``build_dig_command`` + ``parse_dig_output`` (both pure and testable),
      plus ``organizational_domain`` for SPF/DMARC-inheritance reasoning.
WHY:  The email/DNS steps previously used ``dig +short`` and treated empty
      output as "no SPF/DMARC", which is a false positive when the lookup
      actually failed (and a false negative for authoritative-only records).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_STATUS_RE = re.compile(r"status:\s*([A-Za-z]+)", re.I)
# Matches both ";; ANSWER: 3" and "QUERY: 1, ANSWER: 3, AUTHORITY: 0".
_ANSWER_COUNT_RE = re.compile(r"ANSWER:\s*(\d+)", re.I)
_RR_RE = re.compile(r"^\S+\s+\d+\s+IN\s+\S+\s+(.*)$", re.I)

# Statuses that mean the answer could not be trusted.
_FAILURE_STATUSES = frozenset({"SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "TIMEOUT"})

# Common two-label public suffixes (enough for SPF/DMARC inheritance reasoning).
_MULTI_LABEL_SUFFIXES = frozenset({
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "co.nz", "co.za", "com.mx", "com.ar", "com.co",
})


@dataclass
class DigResult:
    """Parsed ``dig`` response."""

    status: str = ""
    answer_count: int = 0
    records: list[str] = field(default_factory=list)  # rdata values (quotes stripped)
    raw: str = ""
    error: bool = False
    nameserver: str = ""

    @property
    def no_error(self) -> bool:
        return self.status.upper() == "NOERROR"

    @property
    def no_record(self) -> bool:
        """Proven absence: NOERROR with zero answers, or NXDOMAIN."""
        return (self.no_error and self.answer_count == 0) or self.status.upper() == "NXDOMAIN"

    @property
    def indeterminate(self) -> bool:
        """The lookup failed or returned an untrustworthy status."""
        if self.error:
            return True
        status = self.status.upper()
        if not status:
            return True
        return status in _FAILURE_STATUSES

    @property
    def evidence(self) -> str:
        base = f"dig status={self.status or 'UNKNOWN'} ANSWER={self.answer_count}"
        if self.nameserver:
            base += f" @{self.nameserver}"
        return base


def build_dig_command(
    name: str,
    record_type: str = "A",
    nameserver: str | None = None,
    timeout: int = 5,
) -> list[str]:
    """Build a ``dig`` invocation that keeps the status header and answers."""
    cmd = ["dig"]
    if nameserver:
        cmd.append(f"@{nameserver}")
    cmd.extend([name, record_type, "+noall", "+answer", "+comments"])
    cmd.append(f"+time={timeout}")
    cmd.append("+tries=2")
    return cmd


def parse_dig_output(stdout: str) -> DigResult:
    """Parse full ``dig`` output (not ``+short``) into a ``DigResult``."""
    text = stdout or ""
    result = DigResult(raw=text)

    match = _STATUS_RE.search(text)
    if match:
        result.status = match.group(1).upper()

    counts = _ANSWER_COUNT_RE.findall(text)
    if counts:
        result.answer_count = int(counts[-1])

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        # Answer RRs are the only non-comment lines left with +noall +answer.
        rdata = _RR_RE.match(stripped)
        value = rdata.group(1).strip() if rdata else stripped
        result.records.append(value.strip().strip('"'))

    if not result.status and not result.records:
        result.error = True
    return result


def organizational_domain(host: str) -> str:
    """Return the registrable (organizational) domain of ``host``.

    Naive public-suffix handling (a small multi-label suffix list). Returns the
    host unchanged when it is already registrable or cannot be reduced.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
