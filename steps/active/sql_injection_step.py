# recon_wp/steps/active/sql_injection_step.py
"""
SQL injection detection - error-signature and optional time-based canaries.

Covers WSTG 4.7.5 (Testing for SQL Injection): injects quote/concat canaries
into discovered query parameters and looks for database error signatures.
Detection-only: no data extraction, no UNION exploitation.

Time-based blind probes (SLEEP/BENCHMARK canaries) are additionally gated
behind `WP_ACTIVE_TIME_BASED` because they intentionally slow the target.
"""

# WHAT: Detects SQL injection via error signatures (and optional timing)
# HOW: Probes discovered params with quote/break canaries, matches DB errors
# WHY: Error-based SQLi is the cheapest reliable signal for injection sinks

import re
import time
from typing import Optional

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

SQL_ERROR_SIGNATURES: list[tuple[str, str]] = [
    ("MySQL", r"you have an error in your sql syntax"),
    ("MySQL", r"warning: mysql"),
    ("MySQL", r"mysqli?_[a-z_]+\("),
    ("MySQL", r"mariadb"),
    ("PostgreSQL", r"pg_query"),
    ("PostgreSQL", r"postgresql"),
    ("PostgreSQL", r"unterminated quoted string"),
    ("MSSQL", r"microsoft sql server"),
    ("MSSQL", r"odbc sql server driver"),
    ("MSSQL", r"incorrect syntax near"),
    ("Oracle", r"ora-\d{5}"),
    ("SQLite", r"sqlite3?::"),
    ("SQLite", r"sqlite_master"),
    ("SQLite", r"unrecognized token"),
    ("Generic", r"sql syntax"),
    ("Generic", r"sqlstate\["),
]

_PAYLOADS = [
    "'",
    "\"",
    "')",
    "1' OR '1'='1",
    "1 OR 1=1",
    "1' ORDER BY 1-- -",
    "\\",
]

_TIME_PAYLOADS = [
    ("1' AND SLEEP(4)-- -", 3.5),
    ("1; WAITFOR DELAY '0:0:4'--", 3.5),
    ("1' AND pg_sleep(4)-- -", 3.5),
]

MAX_FINDINGS = 10


def match_sql_error(body: str) -> Optional[tuple[str, str]]:
    """Return (engine, matched_signature) for the first SQL error signature."""
    lowered = (body or "").lower()
    for engine, pattern in SQL_ERROR_SIGNATURES:
        match = re.search(pattern, lowered)
        if match:
            return engine, match.group(0)
    return None


class SqlInjectionStep(ActiveHttpStep):
    """Detect SQL injection via error signatures and optional timing canaries."""

    name = "sql_injection"
    description = "Detect SQL injection via error-signature canaries (detection-only)"
    severity = "critical"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for SQL injection (error-signature canaries)...")

        params = await self.discover_params()
        if not params:
            self.logger.info("SQLi probe: no query parameters discovered")
            return self.findings

        baseline_errors: set[str] = set()
        for path, _param in params[:3]:
            response = await self.probe(path)
            if response is not None:
                hit = match_sql_error(response.text or "")
                if hit:
                    baseline_errors.add(hit[1])

        for path, param in params:
            for payload in _PAYLOADS:
                if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                    break
                separator = "&" if "?" in path else "?"
                probe_path = f"{path}{separator}{param}={payload}"
                response = await self.probe(probe_path)
                if response is None:
                    continue
                hit = match_sql_error(response.text or "")
                if not hit:
                    continue
                engine, signature = hit
                if signature in baseline_errors:
                    continue  # error exists without injection - not a signal
                self.add_finding(
                    "high",
                    f"Possible SQL error disclosure via {param} ({engine})",
                    (
                        f"Parameter '{param}' at {path} triggers a {engine} error "
                        f"signature when quoting is manipulated. Review for "
                        f"SQL injection (error-based signal only)."
                    ),
                    f"GET {probe_path[:200]} -> {response.status_code}: "
                    f"signature '{signature}'",
                    "Use parameterized queries/prepared statements; validate "
                    "and confirm manually before exploitation",
                    raw={"path": path, "param": param, "payload": payload,
                         "engine": engine, "signature": signature},
                )
                break  # one finding per param is enough

        if getattr(self.config, "active_time_based", False) and self.budget_left():
            await self._time_based_probes(params)

        self.logger.info(
            f"SQLi probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings

    async def _time_based_probes(self, params: list[tuple[str, str]]) -> None:
        """Optional time-based blind probes (gated by WP_ACTIVE_TIME_BASED)."""
        self.logger.warning("Time-based SQLi probes enabled (WP_ACTIVE_TIME_BASED)")
        for path, param in params[:5]:
            for payload, threshold in _TIME_PAYLOADS:
                if not self.budget_left():
                    return
                separator = "&" if "?" in path else "?"
                probe_path = f"{path}{separator}{param}={payload}"
                start = time.monotonic()
                response = await self.probe(probe_path)
                elapsed = time.monotonic() - start
                if response is None or elapsed < threshold:
                    continue
                self.add_finding(
                    "high",
                    f"Possible time-based blind SQLi via {param}",
                    (
                        f"Parameter '{param}' at {path} delayed the response by "
                        f"{elapsed:.1f}s with a {engine_delay_signature(payload)} "
                        f"canary. Verify manually."
                    ),
                    f"GET {probe_path[:200]} -> {elapsed:.1f}s",
                    "Use parameterized queries; confirm with a controlled "
                    "timing test before reporting",
                    raw={"path": path, "param": param, "payload": payload,
                         "elapsed": round(elapsed, 2)},
                )
                break


def engine_delay_signature(payload: str) -> str:
    """Human label for the delay function used in a time-based payload."""
    if "SLEEP" in payload:
        return "MySQL SLEEP"
    if "WAITFOR" in payload:
        return "MSSQL WAITFOR"
    if "pg_sleep" in payload:
        return "PostgreSQL pg_sleep"
    return "delay"
