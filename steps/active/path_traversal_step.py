# recon_wp/steps/active/path_traversal_step.py
"""
Path traversal / local file inclusion detection - canary probes.

Covers WSTG 4.5.1 (Testing Directory Traversal / File Include): probes
file-like parameters with encoded traversal sequences and reports when
OS-specific file signatures appear in the response. Detection-only.
"""

# WHAT: Detects path traversal via traversal canaries and OS file signatures
# HOW: Probes file-ish params with ../ variants and encoded forms; matches
#      /etc/passwd and win.ini signatures
# WHY: Traversal to /etc/passwd or win.ini proves arbitrary file read

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

FILE_PARAMS = [
    "file", "path", "page", "include", "template", "dir", "doc",
    "load", "read", "cat", "view", "lang", "img", "download", "conf",
]

# (payload, signature, os_label)
PAYLOADS = [
    ("../../../../etc/passwd", "root:x:0:0", "Linux /etc/passwd"),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0", "Linux /etc/passwd (encoded)"),
    ("....//....//....//etc/passwd", "root:x:0:0", "Linux /etc/passwd (dot-filter bypass)"),
    ("..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "Windows win.ini (encoded)"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0", "Linux /etc/passwd (encoded dots)"),
]

MAX_FINDINGS = 5


class PathTraversalStep(ActiveHttpStep):
    """Detect path traversal via canary probes against file-like parameters."""

    name = "path_traversal"
    description = "Detect path traversal/LFI via canary probes (detection-only)"
    severity = "high"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings

        self.logger.info("Probing for path traversal (file-read canaries)...")

        params = await self.discover_params()
        candidate_params = {name for _path, name in params}
        # also test well-known file param names on the homepage
        candidate_params.update(FILE_PARAMS)
        ordered = list(candidate_params)[: self.max_params()]

        for param in ordered:
            if not self.budget_left() or len(self.findings) >= MAX_FINDINGS:
                break
            for payload, signature, label in PAYLOADS:
                if not self.budget_left():
                    break
                probe_path = f"/?{param}={payload}"
                response = await self.probe(probe_path)
                if response is None:
                    continue
                body = response.text or ""
                if signature not in body:
                    continue
                self.add_finding(
                    "high",
                    f"Path traversal via {param} ({label})",
                    (
                        f"Parameter '{param}' accepts a traversal sequence and "
                        f"returns contents matching {label}. Arbitrary file "
                        f"read is likely."
                    ),
                    f"GET {self.target.url}/?{param}={payload} -> "
                    f"signature '{signature}' present",
                    "Reject traversal sequences and resolve paths against an "
                    "allowlist; chroot/contain file access",
                    raw={"param": param, "payload": payload, "signature": signature},
                )
                break  # one finding per param

        self.logger.info(
            f"Traversal probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings
