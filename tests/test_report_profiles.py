"""Tests for endpoint posture findings and the profile-specific report renderers."""
from datetime import date

from aegis.models import (
    Authorization,
    Engagement,
    Finding,
    HostProfile,
    Scope,
    Severity,
)
from aegis.pipeline import RunReport
from aegis.report_profiles import (
    _classify_stack,
    render_appserver,
    render_endpoint,
    render_report,
)
from aegis.scoring import correlate
from aegis.tools.base import ToolResult, ToolStatus
from aegis.tools.endpoint_posture import posture_findings

WEAK_POSTURE = {
    "firewall": [{"name": "Public", "enabled": False}, {"name": "Private", "enabled": True}],
    "uacEnabled": 0,
    "defender": {"realtime": False, "antivirus": False, "signatureAgeDays": 2},
    "rdpEnabled": True,
    "listeningPorts": [{"port": 23, "address": "0.0.0.0", "process": "telnetd"},
                       {"port": 445, "address": "0.0.0.0", "process": "System"}],
    "hotfixes": [{"id": "KB1", "installedOn": "2020-01-01"}],
    "psScriptBlockLogging": 0,
    "screenLockSecs": 0,
    "localAdmins": ["HOST\\Administrator", "HOST\\user"],
}

CLEAN_POSTURE = {
    "firewall": [{"name": "Public", "enabled": True}, {"name": "Private", "enabled": True}],
    "uacEnabled": 1,
    "defender": {"realtime": True, "antivirus": True, "signatureAgeDays": 1},
    "rdpEnabled": False,
    "listeningPorts": [{"port": 443, "address": "0.0.0.0", "process": "nginx"}],
    "hotfixes": [],
    "psScriptBlockLogging": 1,
    "screenLockSecs": 900,
    "localAdmins": ["HOST\\Administrator"],
}


# --- posture findings ------------------------------------------------------ #
def test_weak_posture_raises_expected_findings():
    titles = {f.title: f for f in posture_findings(WEAK_POSTURE, "H")}
    assert any("Firewall disabled" in t for t in titles)
    assert any("UAC) disabled" in t and f.severity == Severity.HIGH for t, f in titles.items())
    assert any("Endpoint protection not active" in t for t in titles)
    assert any("Remote Desktop (RDP) enabled" in t for t in titles)
    assert any("port 23" in t and f.severity == Severity.HIGH for t, f in titles.items())
    assert any("updates appear overdue" in t for t in titles)
    assert any("script-block logging" in t for t in titles)
    assert any("Local administrators on H: 2" in t for t in titles)
    # port 445 is not in the risky set -> no finding
    assert not any("port 445" in t for t in titles)


def test_clean_posture_has_no_elevated_findings():
    findings = posture_findings(CLEAN_POSTURE, "H")
    elevated = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert elevated == []


def test_empty_posture_no_findings():
    assert posture_findings({}, "H") == []


# --- report rendering ------------------------------------------------------ #
def _report(profile, posture=None, findings=None):
    auth = Authorization("Eng", "Client", "Jane Doe", "x@c.test",
                         date(2026, 1, 1), date(2026, 12, 31), "SOW-1")
    eng = Engagement(auth, Scope(include=["H"]))
    hp = HostProfile(hostname="H", os_name="Microsoft Windows 11 Pro",
                     software=[{"name": "nginx", "version": "1.0"},
                               {"name": "python", "version": "3.11"}],
                     software_count=2,
                     volumes=[{"mount": "C:", "fileSystem": "NTFS",
                               "encryption": "BitLocker on"}],
                     posture=posture or {})
    return RunReport(engagement=eng, started="t0", finished="t1",
                     tool_results=[ToolResult(tool="infra-agent", status=ToolStatus.OK)],
                     scored=correlate(findings or []), host_profiles=[hp],
                     profile=profile, overall_risk="LOW")


def test_endpoint_report_has_all_sections():
    r = _report("endpoint", WEAK_POSTURE, posture_findings(WEAK_POSTURE, "H"))
    md = render_endpoint(r)
    for h in ["# Endpoint Assessment", "## 1. Header", "## 4. Asset inventory",
              "## 5. Attack surface", "## 8. Security controls",
              "## 11. Risk prioritization", "## 13. Appendices"]:
        assert h in md, f"missing section: {h}"
    assert "Listening ports" in md
    assert "telnetd" in md  # proof/evidence carried through


def test_appserver_report_marks_web_gaps_and_stack():
    r = _report("appserver", CLEAN_POSTURE)
    md = render_appserver(r)
    assert "# Application Server Assessment" in md
    assert "## 4. Asset inventory" in md
    assert "Not assessed" in md          # web-layer sections honestly gapped
    assert "OWASP" in md
    assert "nginx" in md.lower()          # stack classified from software


def test_render_report_dispatch():
    assert render_report(_report("endpoint")).startswith("# Endpoint")
    assert render_report(_report("appserver")).startswith("# Application Server")
    assert render_report(_report("")).startswith("# ")  # generic fallback


def test_stack_classification_whole_token():
    sw = [
        {"name": "Microsoft Visual C++ 2013 Redistributable (x86)", "version": "12.0"},
        {"name": "Oracle VirtualBox", "version": "7.2"},
        {"name": "nginx", "version": "1.25"},
        {"name": "PostgreSQL 16", "version": "16"},
        {"name": "Node.js", "version": "24"},
    ]
    stack = _classify_stack(sw)
    db = stack.get("database", [])
    # 'redis' must not match 'Redistributable'; 'oracle database' must not match VirtualBox
    assert not any("Redistributable" in x for x in db)
    assert not any("VirtualBox" in x for x in db)
    assert any("postgresql" in x.lower() for x in db)
    assert any("nginx" in x.lower() for x in stack.get("web server", []))
    assert any("node" in x.lower() for x in stack.get("runtime", []))
