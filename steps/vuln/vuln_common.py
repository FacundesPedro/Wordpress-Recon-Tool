# recon_wp/steps/vuln/vuln_common.py
"""Shared helpers for the CVE-correlation steps."""

from __future__ import annotations


def add_db_unavailable_finding(step, db) -> None:
    """Emit an operational finding when the vulnerability DB was unreachable.

    Without this, "no CVEs found" is indistinguishable from "lookup failed",
    which can hide real, unverified exposure.
    """
    error = getattr(db, "error_message", "") or ""
    if not isinstance(error, str):
        error = ""
    step._add_finding(
        module="vuln",
        severity="info",
        title="Vulnerability database unreachable — CVE correlation unverified",
        description=(
            "The vulnerability database could not be queried, so the absence "
            "of CVE findings here does not mean the target is clean. This is a "
            "tool/network limitation, not a result."
        ),
        evidence=error or "lookup failed",
        recommendation=(
            "Check outbound connectivity to www.wpvulnerability.net / "
            "wpscan.com, or set a WPScan API token (WPSCAN_API_TOKEN), then "
            "re-run the scan."
        ),
        raw={"operational": True},
    )
