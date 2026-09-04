# recon_wp/modules/__init__.py
"""Module registry and profiles."""

from modules.access_module import AccessModule
from modules.api_module import ApiModule
from modules.discovery_module import DiscoveryModule
from modules.fingerprint_module import FingerprintModule
from modules.infrastructure_module import InfrastructureModule
from modules.passive_module import PassiveModule
from modules.secrets_module import SecretsModule
from modules.ssrf_module import SsrfModule
from modules.tools_module import ToolsModule
from modules.users_module import UsersModule
from modules.vuln_module import VulnModule
from modules.webapp_module import WebappModule
from modules.xmlrpc_module import XmlrpcModule

MODULE_REGISTRY = {
    "access": AccessModule,
    "passive": PassiveModule,
    "infrastructure": InfrastructureModule,
    "discovery": DiscoveryModule,
    "fingerprint": FingerprintModule,
    "users": UsersModule,
    "api": ApiModule,
    "vuln": VulnModule,
    "xmlrpc": XmlrpcModule,
    "secrets": SecretsModule,
    "ssrf": SsrfModule,
    "webapp": WebappModule,
    "tools": ToolsModule,
}

PROFILES = {
    "passive": ["passive"],
    "light": ["passive", "infrastructure", "discovery", "fingerprint"],
    "standard": [
        "passive",
        "infrastructure",
        "discovery",
        "fingerprint",
        "vuln",
        "users",
        "api",
        "xmlrpc",
        "secrets",
        "ssrf",
    ],
    "web": ["passive", "infrastructure", "webapp", "secrets", "tools"],
    "full": list(MODULE_REGISTRY.keys()),
    "aggressive": ["users", "xmlrpc", "secrets", "tools"],
}

AVAILABLE_PROFILES = list(PROFILES.keys())
AVAILABLE_MODULES = list(MODULE_REGISTRY.keys())

RISK_TIERS: dict[int, list[str]] = {
    1: ["passive"],
    2: ["infrastructure", "discovery", "fingerprint", "access", "vuln", "webapp"],
    3: ["users", "api", "xmlrpc", "secrets", "ssrf"],
    4: ["tools"],
}


def validate_tier_coverage() -> None:
    """Assert every registered module maps to exactly one risk tier."""
    registered = set(MODULE_REGISTRY)
    tiered: set[str] = set()
    for names in RISK_TIERS.values():
        tiered.update(names)
    uncovered = registered - tiered
    if uncovered:
        raise ValueError(
            f"Modules registered but not assigned to any risk tier: {', '.join(sorted(uncovered))}"
        )
    extraneous = tiered - registered
    if extraneous:
        print(
            "Warning: RISK_TIERS references non-existent modules: "
            + ", ".join(sorted(extraneous))
        )


validate_tier_coverage()
