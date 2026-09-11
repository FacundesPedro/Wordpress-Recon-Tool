# recon_wp/modules/active_module.py
"""
Active module - intrusive testing steps (risk tier 5).

These steps actively probe the target with canary payloads (SQLi, XSS, SSTI,
traversal, CRLF, auth bypass, rate limiting, etc.). Every step:

- Requires the master switch `WP_ACTIVE_ENABLED=true` (set automatically by
  `-p intrusive` / `-p web-intrusive` / `--active` together with `--authorized`)
- Honors hard request caps (`WP_ACTIVE_MAX_REQUESTS`) and inter-probe delay
  (`WP_ACTIVE_DELAY`)
- Is detection-only: no data extraction, no destructive payloads, no persisted
  state (except the explicitly double-gated file upload step)

Only run against systems you are authorized to test.
"""

# WHAT: Intrusive active testing - injection canaries, auth bypass, rate limits
# HOW: Canary payload probes over discovered parameters/paths with hard caps
# WHY: Detection-only active checks complete the pentest coverage that passive
#      recon cannot reach (WSTG 4.4.x, 4.5.x, 4.7.x, 4.10.x)

from modules.module import Module


class ActiveModule(Module):
    name = "active"
    description = (
        "Intrusive active testing (SQLi/XSS/SSTI/traversal canaries, auth bypass, "
        "rate limits, CSRF, smuggling) - requires WP_ACTIVE_ENABLED"
    )

    def __init__(self):
        super().__init__(self.name, self.description)
        # Steps are registered in phases 4-6; imported lazily to avoid
        # import cycles while steps are being added.
        from steps.active import (
            AuthBypassStep,
            CrlfInjectionStep,
            CsrfStep,
            DefaultCredentialsStep,
            FileUploadStep,
            HttpParameterPollutionStep,
            MassAssignmentStep,
            PasswordResetStep,
            PathTraversalStep,
            RaceConditionStep,
            RateLimitStep,
            ReflectedXssStep,
            RequestSmugglingStep,
            SqlInjectionStep,
            SstiStep,
        )

        self.add_step(SqlInjectionStep)
        self.add_step(ReflectedXssStep)
        self.add_step(SstiStep)
        self.add_step(PathTraversalStep)
        self.add_step(CrlfInjectionStep)
        self.add_step(HttpParameterPollutionStep)
        self.add_step(AuthBypassStep)
        self.add_step(RateLimitStep)
        self.add_step(PasswordResetStep)
        self.add_step(CsrfStep)
        self.add_step(DefaultCredentialsStep)
        self.add_step(RequestSmugglingStep)
        self.add_step(MassAssignmentStep)
        self.add_step(RaceConditionStep)
        self.add_step(FileUploadStep)
