"""Tests for SAST adapters (parsing) and the orchestrator — offline."""
from datetime import date

import pytest

from aegis.models import Authorization, Engagement, Finding, Scope, Severity
from aegis.sast import run_sast
from aegis.scope import AuthorizationError
from aegis.tools.bandit_adapter import BanditAdapter
from aegis.tools.base import ToolResult, ToolStatus
from aegis.tools.gitleaks_adapter import GitleaksAdapter
from aegis.tools.semgrep_adapter import SemgrepAdapter


# --- adapter parsing ------------------------------------------------------- #
def test_bandit_finding_mapping():
    r = {"filename": "C:/repo/app.py", "line_number": 42, "issue_severity": "HIGH",
         "issue_confidence": "HIGH", "issue_text": "Use of eval", "test_id": "B307",
         "test_name": "blacklist", "code": "eval(x)", "more_info": "https://b.example"}
    f = BanditAdapter()._finding(r, "C:/repo", "repo")
    assert f.severity == Severity.HIGH
    assert f.location == "app.py:42"
    assert f.host == "repo"
    assert "B307" in f.tags
    assert f.references == ["https://b.example"]


def test_gitleaks_redacts_the_secret():
    r = {"RuleID": "aws-access-token", "Description": "AWS Access Token",
         "File": "config.py", "StartLine": 10,
         "Secret": "AKIAIOSFODNN7EXAMPLE", "Match": "key=AKIAIOSFODNN7EXAMPLE"}
    f = GitleaksAdapter()._finding(r, "repo")
    assert f.severity == Severity.HIGH
    assert f.location == "config.py:10"
    # the secret value must never appear anywhere in the finding
    blob = f.title + f.description + f.evidence + str(f.raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "secret" in f.tags


def test_semgrep_finding_mapping():
    r = {"check_id": "py.audit.dangerous-eval", "path": "C:/repo/app.py",
         "start": {"line": 42},
         "extra": {"message": "eval is dangerous", "severity": "ERROR",
                   "lines": "eval(x)",
                   "metadata": {"cwe": ["CWE-95"], "owasp": "A03",
                                "references": ["https://s.example"]}}}
    f = SemgrepAdapter()._finding(r, "C:/repo", "repo")
    assert f.severity == Severity.HIGH
    assert f.location == "app.py:42"
    assert "CWE-95" in f.tags


# --- Finding.location affects dedup ---------------------------------------- #
def test_location_differentiates_fingerprints():
    a = Finding(title="Use of eval", severity=Severity.HIGH, source_tool="bandit",
                host="repo", location="a.py:1")
    b = Finding(title="Use of eval", severity=Severity.HIGH, source_tool="bandit",
                host="repo", location="b.py:9")
    assert a.fingerprint != b.fingerprint


# --- orchestrator ---------------------------------------------------------- #
class _FakeAdapter:
    name = "fake"

    def scan(self, path, project):
        return ToolResult(tool="fake", status=ToolStatus.OK, findings=[
            Finding(title="Use of eval", severity=Severity.HIGH, source_tool="fake",
                    host=project, location="app.py:42")])


def _eng(valid=True):
    v_until = date(2026, 12, 31) if valid else date(2000, 12, 31)
    auth = Authorization("Code review", "Acme", "Jane", "x@c.test",
                         date(2026, 1, 1), v_until, "SOW-1")
    return Engagement(authorization=auth, scope=Scope(include=["X"]))


def test_run_sast_collects_and_scores():
    report = run_sast(_eng(), "X", adapters=[_FakeAdapter()])
    assert report.overall_risk == "HIGH"
    assert len(report.scored) == 1
    assert report.scored[0].finding.location == "app.py:42"


def test_run_sast_blocks_on_expired_auth():
    with pytest.raises(AuthorizationError):
        run_sast(_eng(valid=False), "X", adapters=[_FakeAdapter()])


# --- Trivy adapter (SCA + IaC + secrets) ----------------------------------- #
from aegis.tools.trivy_adapter import TrivyAdapter  # noqa: E402
from aegis.tools.gosec_adapter import GosecAdapter  # noqa: E402

_TRIVY_SAMPLE = {
    "SchemaVersion": 2,
    "Results": [
        {"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip",
         "Vulnerabilities": [
             {"VulnerabilityID": "CVE-2022-1234", "PkgName": "flask",
              "InstalledVersion": "0.12", "FixedVersion": "2.0.1", "Severity": "HIGH",
              "Title": "Flask debug RCE", "PrimaryURL": "https://nvd.example/CVE-2022-1234",
              "References": ["https://ref.example/1"]}]},
        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
         "Misconfigurations": [
             {"ID": "DS002", "Title": "Image user should not be 'root'", "Severity": "HIGH",
              "Message": "Specify at least 1 USER command", "Resolution": "Add 'USER <user>'",
              "PrimaryURL": "https://avd.example/DS002", "CauseMetadata": {"StartLine": 1}}]},
        {"Target": "app/config.py", "Class": "secret",
         "Secrets": [
             {"RuleID": "aws-access-key-id", "Title": "AWS Access Key ID", "Severity": "CRITICAL",
              "StartLine": 10, "Match": "key = AKIAIOSFODNN7EXAMPLE"}]},
    ],
}


def test_trivy_parses_vuln_misconfig_secret():
    fs = TrivyAdapter()._parse(_TRIVY_SAMPLE, "/repo", "repo")
    assert len(fs) == 3
    assert {f.source_tool for f in fs} == {"trivy"}
    vuln = next(f for f in fs if "sca" in f.tags)
    assert vuln.severity == Severity.HIGH
    assert "CVE-2022-1234" in vuln.cve and "flask" in vuln.title
    assert "2.0.1" in vuln.remediation
    mis = next(f for f in fs if "iac" in f.tags)
    assert mis.severity == Severity.HIGH and mis.location == "Dockerfile:1"
    sec = next(f for f in fs if "secret" in f.tags)
    assert sec.severity == Severity.CRITICAL and sec.location == "app/config.py:10"
    blob = sec.title + sec.description + sec.evidence + str(sec.raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob  # the matched secret is never stored


def test_trivy_unknown_severity_and_non_cve_id():
    f = TrivyAdapter()._vuln_finding(
        {"VulnerabilityID": "GHSA-abcd", "PkgName": "p", "InstalledVersion": "1",
         "Severity": "UNKNOWN"}, "go.mod", "/repo", "repo")
    assert f.severity == Severity.INFO
    assert f.cve == []  # GHSA id is not a CVE


# --- Gosec adapter (Go SAST) ----------------------------------------------- #
def test_gosec_finding_mapping():
    r = {"severity": "HIGH", "confidence": "HIGH", "rule_id": "G101",
         "details": "Potential hardcoded credentials", "file": "/repo/main.go",
         "line": "10", "code": "const pw = \"abc\"",
         "cwe": {"id": "798", "url": "https://cwe.mitre.org/data/definitions/798.html"}}
    f = GosecAdapter()._finding(r, "/repo", "repo")
    assert f.severity == Severity.HIGH
    assert f.location == "main.go:10"
    assert "G101" in f.tags and "go" in f.tags
    assert f.references == ["https://cwe.mitre.org/data/definitions/798.html"]


# --- wiring ---------------------------------------------------------------- #
def test_default_adapters_includes_trivy_and_gosec():
    from aegis.sast import default_adapters
    names = {a.name for a in default_adapters()}
    assert {"bandit", "semgrep", "gitleaks", "trivy", "gosec"} <= names
