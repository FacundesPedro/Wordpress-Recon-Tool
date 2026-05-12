# recon_wp/modules/__init__.py
"""Module registry and profiles."""

from modules.api_module import ApiModule
from modules.discovery_module import DiscoveryModule
from modules.fingerprint_module import FingerprintModule
from modules.infrastructure_module import InfrastructureModule
from modules.passive_module import PassiveModule
from modules.secrets_module import SecretsModule
from modules.ssrf_module import SsrfModule
from modules.tools_module import ToolsModule
from modules.users_module import UsersModule
from modules.xmlrpc_module import XmlrpcModule

MODULE_REGISTRY = {
    "passive": PassiveModule,
    "infrastructure": InfrastructureModule,
    "discovery": DiscoveryModule,
    "fingerprint": FingerprintModule,
    "users": UsersModule,
    "api": ApiModule,
    "xmlrpc": XmlrpcModule,
    "secrets": SecretsModule,
    "ssrf": SsrfModule,
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
        "users",
        "api",
        "xmlrpc",
        "secrets",
        "ssrf",
    ],
    "full": list(MODULE_REGISTRY.keys()),
    "aggressive": ["users", "xmlrpc", "secrets", "tools"],
}

AVAILABLE_PROFILES = list(PROFILES.keys())
AVAILABLE_MODULES = list(MODULE_REGISTRY.keys())
