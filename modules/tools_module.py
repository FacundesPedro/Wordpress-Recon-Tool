# recon_wp/modules/tools_module.py
"""
Tools module - external tool integrations.

Integrates with external security tools for deeper scanning.
"""

from config import ScanConfig
from modules.module import Module


class ToolsModule(Module):
    name = "tools"
    description = "External tool integrations (wpscan, nuclei, ffuf, opendoor, nmap)"

    def __init__(self, config: ScanConfig = None):
        super().__init__(self.name, self.description)
        self.config = config or ScanConfig()
        self._register_steps()

    def _register_steps(self):
        """Register external tool steps based on config."""
        if self.config.enable_wpscan:
            from steps.tools.wpscan_step import WpscanStep

            self.add_step(WpscanStep)

        if self.config.enable_nuclei:
            from steps.tools.nuclei_step import NucleiStep

            self.add_step(NucleiStep)

        if self.config.enable_ffuf:
            from steps.tools.ffuf_directory_step import FfufDirectoryStep
            from steps.tools.ffuf_files_step import FfufFilesStep
            from steps.tools.ffuf_wp_step import FfufWpStep

            self.add_step(FfufDirectoryStep)
            self.add_step(FfufFilesStep)
            self.add_step(FfufWpStep)

        if self.config.enable_opendoor:
            from steps.tools.opendoor_step import OpenDoorStep

            self.add_step(OpenDoorStep)

        if self.config.enable_nmap:
            from steps.tools.nmap_step import NmapPortScanStep

            self.add_step(NmapPortScanStep)

        if self.config.enable_nmap_scripts:
            from steps.tools.nmap_step import NmapScriptScanStep

            self.add_step(NmapScriptScanStep)
