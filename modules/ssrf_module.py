# recon_wp/modules/ssrf_module.py
"""
SSRF module - Server-Side Request Forgery testing.

Tests for SSRF vulnerabilities in WordPress endpoints.
"""

# WHAT: Tests for SSRF vulnerabilities via oEmbed proxy and pingback.ping
# HOW: Sends crafted requests to internal-allowing endpoints
# WHY: SSRF can be used to access internal services and cloud metadata
# STEPS: OembedProxyStep, PingbackSsrfStep

from modules.module import Module
from steps.ssrf import (
    OembedProxyStep,
    PingbackSsrfStep,
)


class SsrfModule(Module):
    name = "ssrf"
    description = "SSRF checks (oembed proxy, pingback SSRF)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(OembedProxyStep)
        self.add_step(PingbackSsrfStep)
