# recon_wp/modules/webapp_module.py
"""
Webapp module - generic web application security checks (non-WordPress).

Covers OWASP WSTG client-side, configuration, and error-handling checks that
apply to any web application, making the tool reusable for generic web
security assessments (e.g. internal clients that are not WordPress sites).
"""

# WHAT: Generic web app checks - source review, sourcemaps, HTTP methods,
#       cookie flags, CORS, stack traces, content leaks, header quality,
#       CSP audit, API surface, admin surface, open redirects, host headers,
#       JWT audit, client-side audit, WebSockets, JS libraries, sensitive
#       files, cache analysis, form security, tech fingerprint
# HOW: Non-intrusive HTTP probing (GET/OPTIONS/TRACE/PUT/DELETE/PROPFIND)
#      plus canary-value probes (redirect params, Host/X-Forwarded-Host)
# WHY: Extends the tool beyond WordPress for general web security analysis
# STEPS: SourceReviewStep, SourcemapStep, HttpMethodsStep, CookieFlagsStep,
#        CorsStep, StackTraceStep, ContentLeakStep, HeaderQualityStep,
#        CspAuditStep, ApiSurfaceStep, AdminSurfaceStep, OpenRedirectStep,
#        HostHeaderStep, JwtAuditStep, ClientSideAuditStep, WebSocketStep,
#        JsLibraryStep, SensitiveFilesStep, CacheAnalysisStep,
#        FormSecurityStep, TechFingerprintStep

from modules.module import Module
from steps.webapp import (
    AdminSurfaceStep,
    ApiSurfaceStep,
    CacheAnalysisStep,
    ClientSideAuditStep,
    ContentLeakStep,
    CookieFlagsStep,
    CorsStep,
    CspAuditStep,
    FormSecurityStep,
    HeaderQualityStep,
    HostHeaderStep,
    HttpMethodsStep,
    JsLibraryStep,
    JwtAuditStep,
    OpenRedirectStep,
    SensitiveFilesStep,
    SourcemapStep,
    SourceReviewStep,
    StackTraceStep,
    TechFingerprintStep,
    WebSocketStep,
)


class WebappModule(Module):
    name = "webapp"
    description = (
        "Generic web app checks (source review, CORS, cookies, methods, leaks, "
        "CSP, API/admin surface, open redirects, host headers, JWT, client-side, "
        "WebSockets, JS libs, sensitive files, cache, forms, tech fingerprint)"
    )

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
        self.add_step(OpenRedirectStep)
        self.add_step(HostHeaderStep)
        self.add_step(JwtAuditStep)
        self.add_step(ClientSideAuditStep)
        self.add_step(WebSocketStep)
        self.add_step(JsLibraryStep)
        self.add_step(SensitiveFilesStep)
        self.add_step(CacheAnalysisStep)
        self.add_step(FormSecurityStep)
        self.add_step(TechFingerprintStep)
