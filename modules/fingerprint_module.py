# recon_wp/modules/fingerprint_module.py
"""
Fingerprint module - version and component detection.

Identifies WordPress version, themes, plugins, and scripts.
"""

# WHAT: Identifies WordPress version and installed components
# HOW: Parses HTML for version strings, theme/plugin paths, versioned assets
# WHY: Version info enables targeted vulnerability research
# STEPS: WpVersionStep, ThemeStep, PluginStep, PluginVersionStep, VersionedAssetsStep, ScriptsStep

from modules.module import Module
from steps.fingerprint import (
    PluginStep,
    PluginVersionStep,
    ScriptsStep,
    ThemeStep,
    VersionedAssetsStep,
    WpVersionStep,
)


class FingerprintModule(Module):
    name = "fingerprint"
    description = "Fingerprint checks (wp-version, themes, plugins, plugin versions, versioned assets, scripts)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(WpVersionStep)
        self.add_step(ThemeStep)
        self.add_step(PluginStep)
        self.add_step(PluginVersionStep)
        self.add_step(VersionedAssetsStep)
        self.add_step(ScriptsStep)
