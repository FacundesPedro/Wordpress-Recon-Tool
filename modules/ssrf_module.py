# recon_wp/modules/ssrf_module.py
"""
SSRF module - Server-Side Request Forgery testing.

Tests for SSRF vulnerabilities in WordPress endpoints.
"""

# WHAT: Tests for SSRF vulnerabilities via the oEmbed proxy
# HOW: Sends crafted requests to internal-allowing endpoints
# WHY: SSRF can be used to access internal services and cloud metadata
# STEPS: OembedProxyStep
# NOTE: pingback.ping SSRF is handled by XmlrpcSsrfStep (xmlrpc module) so it
# is not duplicated here.

from modules.module import Module
from steps.ssrf import OembedProxyStep


class SsrfModule(Module):
    name = "ssrf"
    description = "SSRF checks (oembed proxy)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(OembedProxyStep)
