# recon_wp/modules/discovery_module.py
"""
Discovery module - file and page enumeration.

Checks for publicly accessible WordPress files that may expose information.
"""

# WHAT: Discovers exposed files and pages (readme, license, sitemap, login, cron, uploads)
# HOW: Each step fetches specific paths and checks for presence/content
# WHY: Exposed files reveal version info, directory structure, and attack surface
# STEPS: ReadmeStep, LicenseStep, SitemapStep, LoginPageStep, WpCronStep, UploadsListingStep

from modules.module import Module
from steps.discovery import (
    LicenseStep,
    LoginPageStep,
    ReadmeStep,
    SitemapStep,
    UploadsListingStep,
    WpCronStep,
)


class DiscoveryModule(Module):
    name = "discovery"
    description = (
        "Discovery checks (readme, license, sitemap, login page, wp-cron, uploads)"
    )

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(ReadmeStep)
        self.add_step(LicenseStep)
        self.add_step(SitemapStep)
        self.add_step(LoginPageStep)
        self.add_step(WpCronStep)
        self.add_step(UploadsListingStep)
