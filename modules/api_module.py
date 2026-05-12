# recon_wp/modules/api_module.py
"""
API module - WordPress REST API and application-level checks.

Checks the API surface for information disclosure and vulnerabilities.
"""

# WHAT: API surface checks (REST API, pages IP leak, application passwords)
# HOW: Each step probes REST API endpoints and inspects responses
# WHY: API endpoints can expose sensitive data and provide attack vectors

from modules.module import Module


class ApiModule(Module):
    name = "api"
    description = "API surface checks (REST surface, pages IP leak, app passwords)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self._register_steps()

    def _register_steps(self):
        """Register API surface analysis steps."""
        from steps.api.app_passwords_step import AppPasswordsStep
        from steps.api.pages_ip_leak_step import PagesIpLeakStep
        from steps.api.rest_surface_step import RestSurfaceStep

        self.add_step(RestSurfaceStep)
        self.add_step(PagesIpLeakStep)
        self.add_step(AppPasswordsStep)
