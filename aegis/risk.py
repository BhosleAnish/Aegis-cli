"""Risk assessment: likelihood × impact rating, matrix, and prioritised fixes.

Severity alone (how bad a finding is) is not risk. Risk combines **impact** (the
severity if exploited) with **likelihood** (how readily it would be exploited in
practice). Aegis derives both from signals it already has — the finding's
severity/CVSS for impact, and the kind of evidence backing it for likelihood —
and combines them on a standard 5×5 matrix so findings can be ranked and
remediated by actual risk, not raw severity.

Likelihood bands (1–5), by the strength/kind of evidence:
  5  actively confirmed exploitable  (a live nuclei match / injection PoC)
  3  known CVE on a detected version (version-based, not confirmed reachable)
  3  directly-exploitable misconfig  (CORS reflect+creds, invalid/expired cert)
  2  upstream CVE on a distro build  (fix likely backported — flagged for review)
  2  config hygiene / observational  (missing headers, disclosure, weak protocol)
  +1 if the finding is corroborated by more than one tool (higher confidence)

Impact band = severity (info→1 … critical→5). Risk score = likelihood × impact
(1–25), bucketed: ≥20 CRITICAL, 12–19 HIGH, 6–11 MEDIUM, ≤5 LOW.

This is intentionally transparent and explainable (every rating shows its L×I),
so the output feeds a GRC register cleanly rather than being a black box.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Severity
from .scoring import ScoredFinding

_IMPACT = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
_IMPACT_LABEL = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

_ACTIVE_TOOLS = {"nuclei", "dalfox", "sqlmap"}
_CVE_TOOLS = {"nvd", "osv"}


@dataclass
class RiskRating:
    likelihood: int   # 1..5
    impact: int       # 1..5
    score: int        # likelihood * impact, 1..25
    level: str        # LOW | MEDIUM | HIGH | CRITICAL


def level_for(score: int) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def _impact(sf: ScoredFinding) -> int:
    return _IMPACT[sf.finding.severity]


def _likelihood(sf: ScoredFinding) -> int:
    f = sf.finding
    tags = set(f.tags)
    if f.source_tool in _ACTIVE_TOOLS and "vuln" in tags:
        base = 5                                   # confirmed exploitable
    elif "backport-review" in tags:
        base = 2                                   # upstream CVE on a distro build;
                                                   # fix likely backported — verify
    elif f.source_tool in _CVE_TOOLS or "cve" in tags:
        base = 3                                   # version-based CVE
    elif ({"cors", "certificate"} & tags
          or (f.source_tool == "web-assess"
              and f.severity.rank >= Severity.HIGH.rank)):
        base = 3                                   # directly-exploitable misconfig
    else:
        base = 2                                   # config hygiene / observational
    # A backport-review candidate is unverified by construction, so a second
    # tool detecting the same version does not raise how likely it is exploitable.
    if sf.confidence == "confirmed" and "backport-review" not in tags:
        base += 1                                  # multi-tool corroboration
    return max(1, min(5, base))


def rate(sf: ScoredFinding) -> RiskRating:
    likelihood = _likelihood(sf)
    impact = _impact(sf)
    score = likelihood * impact
    return RiskRating(likelihood, impact, score, level_for(score))


def _vulns(scored: list[ScoredFinding]) -> list[ScoredFinding]:
    """Risk-bearing findings only (exclude pure INFO attack-surface noise)."""
    return [sf for sf in scored if sf.finding.severity.rank > Severity.INFO.rank]


def rank_key(sf: ScoredFinding):
    """Sort key: highest risk first, then impact, likelihood, CVSS."""
    r = rate(sf)
    return (r.score, r.impact, r.likelihood, sf.finding.cvss or 0.0)


# --------------------------------------------------------------------------- #
# Report rendering (returns Markdown lines)
# --------------------------------------------------------------------------- #
def render_risk_matrix(scored: list[ScoredFinding]) -> list[str]:
    vulns = _vulns(scored)
    if not vulns:
        return []
    # grid[impact][likelihood] = count
    grid = {i: {l: 0 for l in range(1, 6)} for i in range(1, 6)}
    for sf in vulns:
        r = rate(sf)
        grid[r.impact][r.likelihood] += 1

    lines = [
        "### Risk matrix",
        "",
        "Counts of findings by likelihood (columns) and impact (rows).",
        "",
        "| Impact \\ Likelihood | 1 | 2 | 3 | 4 | 5 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for impact in range(5, 0, -1):
        cells = []
        for likelihood in range(1, 6):
            n = grid[impact][likelihood]
            level = level_for(likelihood * impact)
            cells.append(f"**{n}** ({level[0]})" if n else "-")
        lines.append(f"| {impact} ({_IMPACT_LABEL[impact]}) | " + " | ".join(cells) + " |")
    lines += ["", "_Cell tag: risk level of that likelihood×impact "
              "(C=Critical, H=High, M=Medium, L=Low)._", ""]
    return lines


def render_remediation(scored: list[ScoredFinding]) -> list[str]:
    vulns = sorted(_vulns(scored), key=rank_key, reverse=True)
    if not vulns:
        return []
    lines = [
        "### Prioritised remediation",
        "",
        "Findings ranked by risk (likelihood × impact), highest first.",
        "",
        "| # | Risk | L×I | Finding | Asset | Remediation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for i, sf in enumerate(vulns, 1):
        f = sf.finding
        r = rate(sf)
        asset = f.host + (f":{f.port}" if f.port else "")
        if f.location:
            asset = f.location
        fix = (f.remediation or "—").replace("\n", " ")
        if len(fix) > 140:
            fix = fix[:137] + "…"
        title = f.title if len(f.title) <= 70 else f.title[:67] + "…"
        lines.append(
            f"| {i} | {r.level} | {r.likelihood}×{r.impact}={r.score} "
            f"| {title} | {asset or '—'} | {fix} |")
    lines.append("")
    return lines


def risk_overall(scored: list[ScoredFinding]) -> str:
    """Headline risk level from the highest-rated finding (LOW if none)."""
    vulns = _vulns(scored)
    if not vulns:
        return "LOW"
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return max((rate(sf).level for sf in vulns), key=lambda lvl: order[lvl])
