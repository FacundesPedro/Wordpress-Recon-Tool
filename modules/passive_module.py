# recon_wp/modules/passive_module.py
"""
Passive reconnaissance module.

Gathers external intelligence without direct interaction with target.
"""

# WHAT: Passive recon - WHOIS, DNS, certificate transparency, Wayback Machine
# HOW: Uses external services (whois, dig, crt.sh, web.archive.org) - no direct target contact
# WHY: Discovers subdomains, historical data, domain registration info
# STEPS: WhoisStep, DnsStep, CrtShStep, WaymachineStep

from modules.module import Module
from steps.passive import CrtShStep, DnsStep, WaymachineStep, WhoisStep


class PassiveModule(Module):
    name = "passive"
    description = "Passive reconnaissance (whois, dns, crt.sh, wayback, shodan)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(WhoisStep)
        self.add_step(DnsStep)
        self.add_step(CrtShStep)
        self.add_step(WaymachineStep)
