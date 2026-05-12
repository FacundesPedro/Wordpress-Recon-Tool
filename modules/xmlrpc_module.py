# recon_wp/modules/xmlrpc_module.py
"""
XMLRPC module - XML-RPC interface testing.

Analyzes XML-RPC endpoint for methods, SSRF, and credential brute force.
"""

# WHAT: Tests XML-RPC for method availability, SSRF, and brute forceability
# HOW: Sends XML-RPC requests to xmlrpc.php, tests pingback.ping and credential methods
# WHY: XML-RPC is a common attack vector for DDoS, SSRF, and credential attacks
# STEPS: XmlrpcDetectStep, XmlrpcMethodsStep, XmlrpcCredsStep, XmlrpcMulticallStep, XmlrpcSsrfStep

from modules.module import Module
from steps.xmlrpc import (
    XmlrpcCredsStep,
    XmlrpcDetectStep,
    XmlrpcMethodsStep,
    XmlrpcMulticallStep,
    XmlrpcSsrfStep,
)


class XmlrpcModule(Module):
    name = "xmlrpc"
    description = "XMLRPC checks (detect, methods, creds, multicall, SSRF)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(XmlrpcDetectStep)
        self.add_step(XmlrpcMethodsStep)
        self.add_step(XmlrpcCredsStep)
        self.add_step(XmlrpcMulticallStep)
        self.add_step(XmlrpcSsrfStep)
