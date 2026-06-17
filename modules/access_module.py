# recon_wp/modules/access_module.py
"""
Authenticated access module.

Requires WordPress Application Password credentials (WP >= 5.6) to query
REST API endpoints for authoritative plugin/theme/user inventory.
"""

# WHAT: Authenticated REST API enumeration - plugins, themes, users
# HOW: Uses Application Password Basic Auth against /wp-json/wp/v2/*
# WHY: Provides authoritative inventory with exact versions, bypasses fingerprint limits
# STEPS: WpJsonPluginsStep, WpJsonThemesStep, WpJsonUsersStep

from modules.module import Module
from steps.access import WpJsonPluginsStep, WpJsonThemesStep, WpJsonUsersStep


class AccessModule(Module):
    name = "access"
    description = "Authenticated REST API enumeration (plugins, themes, users)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(WpJsonPluginsStep)
        self.add_step(WpJsonThemesStep)
        self.add_step(WpJsonUsersStep)
