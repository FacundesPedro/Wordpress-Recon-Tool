from modules.module import Module
from steps.vuln import CoreVulnStep, PluginAbandonmentStep, PluginVulnStep, ThemeVulnStep


class VulnModule(Module):
    name = "vuln"
    description = "Vulnerability correlation (core, plugin, theme CVEs, abandonment)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(CoreVulnStep)
        self.add_step(PluginVulnStep)
        self.add_step(ThemeVulnStep)
        self.add_step(PluginAbandonmentStep)
