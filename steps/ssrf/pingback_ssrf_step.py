# recon_wp/steps/ssrf/pingback_ssrf_step.py
"""
Pingback SSRF compatibility alias.

Pingback detection is implemented once in :class:`XmlrpcSsrfStep`
(``steps/xmlrpc/xmlrpc_ssrf_step.py``). This class previously duplicated that
logic with a weaker substring check that also fired on *rejections*. It now
delegates to the canonical implementation, so the same issue is never reported
twice and the fault-code semantics stay consistent.
"""

# WHAT: pingback.ping SSRF detection (delegated)
# HOW: Subclasses XmlrpcSsrfStep
# WHY: Kept for import/API compatibility; `xmlrpc` owns the real check

from steps.xmlrpc.xmlrpc_ssrf_step import XmlrpcSsrfStep


class PingbackSsrfStep(XmlrpcSsrfStep):
    """Alias of :class:`XmlrpcSsrfStep` reporting under the ``ssrf`` module.

    The ``ssrf`` module no longer registers this step because the ``xmlrpc``
    module owns pingback detection and both modules run in the standard/full
    profiles. It remains importable for backward compatibility.
    """

    name = "pingback_ssrf"
    description = "Check for pingback.ping SSRF (delegates to xmlrpc_ssrf)"
    MODULE = "ssrf"
