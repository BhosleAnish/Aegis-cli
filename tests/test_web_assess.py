"""Tests for web-layer assessment findings (TLS, headers, CORS) — offline."""
from aegis.models import Severity
from aegis.tools.base import ToolStatus
from aegis.tools.web_assess import _days_to, run_web_assessment, web_findings

TLS_BAD = {
    "valid": False, "validation_error": "hostname mismatch",
    "days_to_expiry": -5, "not_after": "Jan 1 00:00:00 2026 GMT",
    "legacy": {"TLSv1.0": True, "TLSv1.1": False},
}
HEADERS_BAD = {
    "status": 200, "present": ["server"],
    "missing_security": ["strict-transport-security", "content-security-policy",
                         "x-content-type-options"],
    "disclosure": {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4"},
}
CORS_BAD = {"allow_origin": "https://aegis-cors-probe.example",
            "allow_credentials": True, "verdict": "reflects-origin"}

TLS_OK = {"valid": True, "days_to_expiry": 200, "not_after": "x",
          "legacy": {"TLSv1.0": False, "TLSv1.1": False}}
HEADERS_OK = {"status": 200, "present": [], "missing_security": [], "disclosure": {}}
CORS_OK = {"allow_origin": None, "allow_credentials": False, "verdict": "none"}


def _titles(findings):
    return {f.title: f for f in findings}


def test_weak_web_surface_findings():
    t = _titles(web_findings("https://x", "x", TLS_BAD, HEADERS_BAD, CORS_BAD))
    assert any("Expired TLS certificate" in k and f.severity == Severity.HIGH
               for k, f in t.items())
    assert any("Invalid TLS certificate" in k for k in t)
    assert any("Deprecated TLS protocol TLSv1.0" in k for k in t)
    assert any("strict-transport-security" in k for k in t)
    assert any("Server/version disclosure" in k for k in t)
    # reflected origin + credentials is the worst CORS case
    assert any("Credentialed CORS reflects arbitrary origin" in k and f.severity == Severity.HIGH
               for k, f in t.items())


def test_clean_web_surface_no_findings():
    assert web_findings("https://x", "x", TLS_OK, HEADERS_OK, CORS_OK) == []


def test_wildcard_cors_with_credentials_is_high():
    cors = {"allow_origin": "*", "allow_credentials": True, "verdict": "wildcard"}
    t = _titles(web_findings("https://x", "x", {}, {}, cors))
    assert any("Wildcard CORS with credentials" in k and f.severity == Severity.HIGH
               for k, f in t.items())


def test_days_to_expiry_parses_cert_date():
    # a far-future date should yield a positive day count
    assert _days_to("Jan 1 00:00:00 2099 GMT") > 1000
    assert _days_to(None) is None
    assert _days_to("garbage") is None


def test_run_web_assessment_skips_without_target():
    res = run_web_assessment(None)
    assert res.status == ToolStatus.SKIPPED
