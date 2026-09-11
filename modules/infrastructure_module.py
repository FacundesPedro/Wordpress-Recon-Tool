# recon_wp/modules/infrastructure_module.py
"""
Infrastructure module - server and network configuration checks.

Analyzes server headers, TLS config, WAF presence, and port accessibility.
"""

# WHAT: Checks server config, TLS, WAF protection, and port accessibility
# HOW: Analyzes HTTP headers, SSL/TLS handshake, response patterns, XML-RPC pingback
# WHY: Infrastructure weaknesses can enable attacks
# STEPS: HeadersStep, TlsStep, WafStep, PortsStep

from modules.module import Module
from steps.infrastructure import (
    HeadersStep,
    HostingStep,
    PhpVersionStep,
    PortsStep,
    TlsStep,
    WafStep,
)


class InfrastructureModule(Module):
    name = "infrastructure"
    description = "Infrastructure checks (headers, TLS, WAF, ports, hosting, PHP version)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(HeadersStep)
        self.add_step(HostingStep)
        self.add_step(TlsStep)
        self.add_step(WafStep)
        self.add_step(PortsStep)
        self.add_step(PhpVersionStep)
