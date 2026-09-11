# recon_wp/steps/active/file_upload_step.py
"""
File upload probing - safe marker file upload test.

Covers WSTG 4.10.8/4.10.9 (Upload of Unexpected/Malicious File Types):
detects upload forms, and when explicitly enabled (`WP_ACTIVE_FILE_UPLOAD`),
uploads a single harmless text marker file and reports whether it is stored
and publicly accessible.

NEVER uploads executable or double-extension filenames. The upload leaves an
artifact on the target - this step is double-gated and documented as such.
"""

# WHAT: Tests whether upload forms store and expose uploaded files
# HOW: Finds <input type="file"> forms; uploads a benign .txt marker; checks
#      accessibility of the returned path
# WHY: Unrestricted uploads are a direct RCE path when extensions are trusted

import re
import secrets
from urllib.parse import urljoin

from base.http_step import BaseHttpStep
from core.finding import Finding

from steps.active.base_active import ActiveHttpStep

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
FILE_INPUT_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']file[\"'][^>]*>", re.I)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\'](\w+)["\']', re.I)

MARKER_CONTENT = "recon-canary-marker-7q4\n"
MAX_FINDINGS = 2


class FileUploadStep(ActiveHttpStep):
    """Detect upload forms and test storage of a safe marker file."""

    name = "file_upload"
    description = "Test file upload handling with a safe marker file (double-gated)"
    severity = "medium"
    MODULE = "active"

    async def run(self) -> list[Finding]:
        if not self.gate():
            return self.findings
        if not getattr(self.config, "active_file_upload", False):
            self.logger.info(
                "File upload probe disabled (WP_ACTIVE_FILE_UPLOAD) - skipping"
            )
            return self.findings

        self.logger.warning("Probing file upload handling (safe marker only)...")

        try:
            response = await self.fetch("/")
        except Exception as e:
            self.logger.debug(f"Homepage fetch failed: {e}")
            return self.findings

        html = response.text or ""
        upload_forms = []
        for match in FORM_RE.finditer(html):
            block = match.group(1)
            if FILE_INPUT_RE.search(block):
                action_match = ACTION_RE.search(match.group(0))
                method_match = METHOD_RE.search(match.group(0))
                upload_forms.append({
                    "action": action_match.group(1) if action_match else "",
                    "method": (method_match.group(1).upper()
                               if method_match else "POST"),
                })

        if not upload_forms:
            self.logger.info("File upload: no upload forms discovered")
            return self.findings

        for form in upload_forms[:MAX_FINDINGS]:
            if not self.budget_left():
                break
            await self._test_upload(form)

        self.logger.info(
            f"File upload probe done: {len(self.findings)} finding(s), "
            f"{self._requests_sent} requests"
        )
        return self.findings

    async def _test_upload(self, form: dict) -> None:
        action = form["action"] or "/"
        url = urljoin(self.target.url, action)
        filename = f"recon-canary-{secrets.token_hex(4)}.txt"

        try:
            self._requests_sent += 1
            response = await self.http.request(
                "POST",
                url,
                files={"file": (filename, MARKER_CONTENT, "text/plain")},
            )
        except Exception as e:
            self.logger.debug(f"Upload to {url} failed: {e}")
            return

        body = response.text or ""
        stored_url = ""
        match = re.search(r'https?://[^\s"\'<>]+\.(?:txt|png|jpg|jpeg|gif)',
                          body)
        if match:
            stored_url = match.group(0)

        accessible = False
        if stored_url and self.budget_left():
            try:
                self._requests_sent += 1
                check = await self.http.request("GET", stored_url)
                accessible = (
                    check.status_code == 200
                    and "recon-canary-marker" in (check.text or "")
                )
            except Exception as e:
                self.logger.debug(f"Stored-file check failed: {e}")

        if response.status_code in (200, 201) and accessible:
            self.add_finding(
                "medium",
                f"Uploaded file is stored and publicly accessible at {action}",
                (
                    f"A marker text file was accepted by the upload form at "
                    f"'{action}' and is retrievable at {stored_url}. Verify "
                    f"extension/MIME restrictions manually - executable "
                    f"uploads would mean RCE. (A benign .txt artifact was "
                    f"left on the target.)"
                ),
                f"POST {url} ({filename}) -> {response.status_code}; "
                f"GET {stored_url} -> 200 with marker content",
                "Validate extensions/MIME server-side, store uploads outside "
                "the web root or on object storage, randomize filenames",
                raw={"action": action, "filename": filename,
                     "stored_url": stored_url,
                     "status": response.status_code},
            )
        elif response.status_code in (200, 201):
            self.add_finding(
                "low",
                f"Upload form accepted a marker file at {action}",
                (
                    f"The upload form at '{action}' accepted a text marker "
                    f"file (HTTP {response.status_code}) but the stored "
                    f"location could not be confirmed. Review upload "
                    f"validation manually."
                ),
                f"POST {url} ({filename}) -> {response.status_code}",
                "Validate extensions/MIME server-side and confirm storage "
                "location isolation",
                raw={"action": action, "filename": filename,
                     "status": response.status_code},
            )
