"""Static code review (SAST) orchestrator.

Runs the available SAST tools over a source tree and normalizes everything into
the shared Finding schema / report:
  * bandit  — Python security linting
  * gosec   — Go security linting
  * semgrep — multi-language code-pattern rules
  * trivy   — dependency vulns (SCA) + IaC misconfig + secrets
  * gitleaks — hardcoded-secret detection

Like the other modules it runs behind the authorization gate; its "target" is a
code path rather than a host, so there is no network scope filter — the path
itself is the scope. Any tool whose binary is absent is skipped gracefully.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .models import Engagement
from .pipeline import RunReport
from .scope import ScopeGate
from .scoring import correlate, overall_risk
from .tools.bandit_adapter import BanditAdapter
from .tools.gitleaks_adapter import GitleaksAdapter
from .tools.gosec_adapter import GosecAdapter
from .tools.semgrep_adapter import SemgrepAdapter
from .tools.trivy_adapter import TrivyAdapter
from .tools.base import ToolStatus

Logger = Callable[[str], None]


def default_adapters():
    return [BanditAdapter(), GosecAdapter(), SemgrepAdapter(),
            TrivyAdapter(), GitleaksAdapter()]


def run_sast(engagement: Engagement, path: str, project: Optional[str] = None,
             adapters=None, logger: Optional[Logger] = None) -> RunReport:
    log: Logger = logger or (lambda m: None)
    gate = ScopeGate(engagement)
    gate.assert_authorized()
    auth = engagement.authorization
    log(f"Authorization OK: {auth.engagement} for {auth.client} "
        f"(ref {auth.signoff_reference})")

    project = project or Path(path).name or "code"
    started = datetime.now(timezone.utc)
    adapters = adapters if adapters is not None else default_adapters()

    results = []
    all_findings = []
    for ad in adapters:
        log(f"[{ad.name}] scanning {path}")
        res = ad.scan(path, project)
        results.append(res)
        if res.status == ToolStatus.UNAVAILABLE:
            log(f"  [{ad.name}] SKIPPED — {res.message}")
        elif res.status == ToolStatus.ERROR:
            log(f"  [{ad.name}] ERROR — {res.message}")
        else:
            log(f"  [{ad.name}] ok — {len(res.findings)} finding(s) in {res.duration_s}s")
            all_findings += res.findings

    scored = correlate(all_findings)
    report = RunReport(
        engagement=engagement,
        started=started.isoformat(),
        finished=datetime.now(timezone.utc).isoformat(),
        tool_results=results,
        scored=scored,
        scope_audit=[],
        overall_risk=overall_risk(scored),
    )
    log(f"Done. Overall risk: {report.overall_risk}. {len(scored)} distinct finding(s).")
    return report
