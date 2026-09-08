"""Tests for WebappModule registration, web profile, and tier mapping."""

from config import ScanConfig
from main import build_modules, get_module_names
from modules import (
    AVAILABLE_MODULES,
    MODULE_REGISTRY,
    PROFILES,
    RISK_TIERS,
    validate_tier_coverage,
)
from modules.webapp_module import WebappModule

EXPECTED_WEBAPP_STEPS = [
    "SourceReviewStep",
    "SourcemapStep",
    "HttpMethodsStep",
    "CookieFlagsStep",
    "CorsStep",
    "StackTraceStep",
    "ContentLeakStep",
    "HeaderQualityStep",
    "CspAuditStep",
    "ApiSurfaceStep",
]


class TestWebappModule:
    def test_module_name(self):
        module = WebappModule()
        assert module.name == "webapp"

    def test_all_steps_registered(self):
        module = WebappModule()
        assert [s.__name__ for s in module.steps] == EXPECTED_WEBAPP_STEPS

    def test_registered_in_module_registry(self):
        assert MODULE_REGISTRY["webapp"] is WebappModule
        assert "webapp" in AVAILABLE_MODULES

    def test_tier_coverage_valid(self):
        validate_tier_coverage()

    def test_webapp_in_tier_2(self):
        assert "webapp" in RISK_TIERS[2]


class TestWebProfile:
    def test_profile_exists(self):
        assert "web" in PROFILES

    def test_profile_modules(self):
        assert set(PROFILES["web"]) == {
            "passive",
            "infrastructure",
            "webapp",
            "secrets",
            "tools",
        }

    def test_profile_modules_all_registered(self):
        for name in PROFILES["web"]:
            assert name in MODULE_REGISTRY

    def test_full_profile_includes_webapp(self):
        assert "webapp" in PROFILES["full"]


class TestBuildModules:
    def test_web_profile_with_nmap(self):
        module_names = get_module_names("web", enable_nmap=True)
        config = ScanConfig()
        config.enable_nmap = True
        modules = build_modules(module_names, enable_nmap=True, config=config)
        names = [m.name for m in modules]
        assert "webapp" in names
        assert "tools" in names
        tools = [m for m in modules if m.name == "tools"][0]
        assert "NmapPortScanStep" in [s.__name__ for s in tools.steps]

    def test_web_profile_without_tools_flags_skips_tools(self):
        module_names = get_module_names("web")
        modules = build_modules(module_names)
        names = [m.name for m in modules]
        assert "webapp" in names
        assert "tools" not in names

    def test_nmap_scripts_registration(self):
        config = ScanConfig()
        config.enable_nmap_scripts = True
        modules = build_modules(["tools"], enable_nmap_scripts=True, config=config)
        tools = modules[0]
        assert "NmapScriptScanStep" in [s.__name__ for s in tools.steps]

    def test_explicit_module_selection(self):
        module_names = get_module_names("light", modules_arg="webapp")
        assert module_names == ["webapp"]
