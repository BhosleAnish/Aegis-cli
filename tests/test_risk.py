"""Tests for the risk model: likelihood×impact rating, matrix, ranking — offline."""
from aegis.models import Finding, Severity
from aegis.risk import (
    rate,
    render_remediation,
    render_risk_matrix,
    risk_overall,
)
from aegis.scoring import ScoredFinding


def _sf(severity, source_tool, tags, confidence="single"):
    f = Finding(title="t", severity=severity, source_tool=source_tool,
                host="h", tags=tags)
    return ScoredFinding(finding=f, confidence=confidence, corroborated_by=[source_tool])


# --- rating ---------------------------------------------------------------- #
def test_active_confirmed_exploit_is_top_risk():
    r = rate(_sf(Severity.CRITICAL, "nuclei", ["vuln"]))
    assert (r.likelihood, r.impact, r.score, r.level) == (5, 5, 25, "CRITICAL")


def test_active_high_crosses_into_critical():
    assert rate(_sf(Severity.HIGH, "nuclei", ["vuln"])).level == "CRITICAL"  # 5x4=20


def test_version_cve_is_likelihood_three():
    r = rate(_sf(Severity.HIGH, "nvd", ["cve", "sca"]))
    assert (r.likelihood, r.impact, r.score, r.level) == (3, 4, 12, "HIGH")


def test_corroboration_raises_likelihood():
    r = rate(_sf(Severity.HIGH, "nvd", ["cve"], confidence="confirmed"))
    assert r.likelihood == 4 and r.score == 16 and r.level == "HIGH"


def test_config_hygiene_stays_low():
    r = rate(_sf(Severity.LOW, "web-assess", ["headers", "web"]))
    assert (r.likelihood, r.impact, r.score, r.level) == (2, 2, 4, "LOW")


def test_exploitable_misconfig_is_likelihood_three():
    r = rate(_sf(Severity.HIGH, "web-assess", ["cors", "web"]))
    assert r.likelihood == 3 and r.score == 12 and r.level == "HIGH"


def test_backport_review_down_weights_below_plain_cve():
    # an upstream CVE flagged as a distro-backport candidate is likelihood 2,
    # not the 3 a plain version-based CVE gets — it ranks below confirmed issues.
    r = rate(_sf(Severity.HIGH, "nvd", ["cve", "sca", "backport-review"]))
    assert r.likelihood == 2 and r.score == 8 and r.level == "MEDIUM"


def test_backport_review_does_not_gain_corroboration_bump():
    # unverified by construction: a second tool seeing the same version must not
    # raise its likelihood the way it does for a confirmed version CVE.
    r = rate(_sf(Severity.HIGH, "nvd", ["cve", "backport-review"],
                 confidence="confirmed"))
    assert r.likelihood == 2


# --- aggregation / rendering ----------------------------------------------- #
def test_risk_overall_takes_the_worst():
    scored = [_sf(Severity.LOW, "web-assess", ["headers"]),
              _sf(Severity.CRITICAL, "nuclei", ["vuln"])]
    assert risk_overall(scored) == "CRITICAL"


def test_risk_overall_low_when_only_info():
    info = [_sf(Severity.INFO, "nmap", ["attack-surface"])]
    assert risk_overall(info) == "LOW"
    assert render_risk_matrix(info) == []        # nothing to plot
    assert render_remediation(info) == []


def test_remediation_is_ranked_highest_risk_first():
    low = _sf(Severity.LOW, "web-assess", ["headers"])          # 4
    crit = _sf(Severity.CRITICAL, "nuclei", ["vuln"])           # 25
    med = _sf(Severity.MEDIUM, "nvd", ["cve"])                  # 3x3=9
    lines = render_remediation([low, crit, med])
    body = [ln for ln in lines if ln.startswith("| 1 ")
            or ln.startswith("| 2 ") or ln.startswith("| 3 ")]
    # row 1 is the critical, row 3 is the low
    assert body[0].startswith("| 1 | CRITICAL |")
    assert body[2].startswith("| 3 | LOW |")


def test_matrix_renders_grid_when_findings_present():
    lines = render_risk_matrix([_sf(Severity.CRITICAL, "nuclei", ["vuln"])])
    assert any("Risk matrix" in ln for ln in lines)
    assert any(ln.startswith("| 5 (Critical) |") for ln in lines)
