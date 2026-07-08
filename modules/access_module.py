# recon_wp/modules/access_module.py
"""
Authenticated access module.

Requires WordPress Application Password credentials (WP >= 5.6) to query
REST API endpoints for authoritative plugin/theme/user inventory.
"""

# WHAT: Authenticated REST API enumeration - plugins, themes, users
#      + Inactive plugin file accessibility check
# HOW: Uses Application Password Basic Auth against /wp-json/wp/v2/*
# WHY: Provides authoritative inventory with exact versions, bypasses fingerprint limits
# STEPS: WpJsonPluginsStep, WpJsonThemesStep, WpJsonUsersStep, InactivePluginCheckStep

from modules.module import Module
from steps.access import (
    InactivePluginCheckStep,
    LoginBruteforceStep,
    RestHardeningStep,
    SiteHealthStep,
    WpJsonPluginsStep,
    WpJsonThemesStep,
    WpJsonUsersStep,
)


class AccessModule(Module):
    name = "access"
    description = (
        "Authenticated REST API enumeration (plugins, themes, users, "
        "inactive plugin check, login brute-force, site health, "
        "REST API hardening)"
    )

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(WpJsonPluginsStep)
        self.add_step(WpJsonThemesStep)
        self.add_step(WpJsonUsersStep)
        self.add_step(InactivePluginCheckStep)
        self.add_step(LoginBruteforceStep)
        self.add_step(SiteHealthStep)
        self.add_step(RestHardeningStep)
