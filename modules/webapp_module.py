# recon_wp/modules/webapp_module.py
"""
Webapp module - generic web application security checks (non-WordPress).

Covers OWASP WSTG client-side, configuration, and error-handling checks that
apply to any web application, making the tool reusable for generic web
security assessments (e.g. internal clients that are not WordPress sites).
"""

# WHAT: Generic web app checks - source review, sourcemaps, HTTP methods,
#       cookie flags, CORS, stack traces, content leaks, header quality
# HOW: Non-intrusive HTTP probing (GET/OPTIONS/TRACE/PUT/DELETE/PROPFIND)
# WHY: Extends the tool beyond WordPress for general web security analysis
# STEPS: SourceReviewStep, SourcemapStep, HttpMethodsStep, CookieFlagsStep,
#        CorsStep, StackTraceStep, ContentLeakStep, HeaderQualityStep

from modules.module import Module
from steps.webapp import (
    AdminSurfaceStep,
    ApiSurfaceStep,
    ContentLeakStep,
    CookieFlagsStep,
    CorsStep,
    CspAuditStep,
    HeaderQualityStep,
    HttpMethodsStep,
    SourcemapStep,
    SourceReviewStep,
    StackTraceStep,
)


class WebappModule(Module):
    name = "webapp"
    description = "Generic web app checks (source review, CORS, cookies, methods, leaks)"

    def __init__(self):
        super().__init__(self.name, self.description)
        self.add_step(SourceReviewStep)
        self.add_step(SourcemapStep)
        self.add_step(HttpMethodsStep)
        self.add_step(CookieFlagsStep)
        self.add_step(CorsStep)
        self.add_step(StackTraceStep)
        self.add_step(ContentLeakStep)
        self.add_step(HeaderQualityStep)
        self.add_step(CspAuditStep)
        self.add_step(ApiSurfaceStep)
        self.add_step(AdminSurfaceStep)
