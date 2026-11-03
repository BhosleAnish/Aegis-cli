"""Infrastructure-analysis orchestrator.

Same guarantees as the network pipeline: authorization is asserted up front and
the analyzed host must be in scope (fail closed). The inventory comes from the
MonitoringAgent collectors (locally, or an ingested export); findings are the
deterministic hardening checks. Results reuse the shared RunReport / scoring /
report layer.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from .models import Engagement
from .pipeline import RunReport
from .scope import OutOfScopeError, ScopeGate
from .scoring import correlate, overall_risk
from .tools.infra_adapter import InfraAdapter
from .tools.osv_matcher import OSVMatcher, OSVUnavailable
from .tools.endpoint_posture import posture_findings
from .tools.base import ToolResult, ToolStatus

Logger = Callable[[str], None]


def run_infra(engagement: Engagement, adapter: InfraAdapter,
              logger: Optional[Logger] = None, cve: bool = False,
              cve_timeout: int = 20, profile: str = "") -> RunReport:
    log: Logger = logger or (lambda m: None)
    gate = ScopeGate(engagement)

    # 1. authorization gate
    gate.assert_authorized()
    auth = engagement.authorization
    log(f"Authorization OK: {auth.engagement} for {auth.client} "
        f"(ref {auth.signoff_reference})")

    started = datetime.now(timezone.utc)

    # 2. acquire inventory + derive findings
    src = adapter.inventory_json or adapter.agent_dir or "?"
    log(f"[infra-agent] acquiring inventory ({src})")
    result = adapter.run()
    profiles = []

    if result.status == ToolStatus.ERROR:
        log(f"  [infra-agent] ERROR — {result.message}")
    else:
        hp = getattr(result, "profile", None)
        if hp is not None:
            # 3. scope gate on the analyzed host identity (fail closed)
            decision = gate.is_in_scope(hp.hostname)
            log(f"  scope: {hp.hostname} -> "
                f"{'ALLOW' if decision.allowed else 'BLOCK'} ({decision.reason})")
            if not decision.allowed:
                raise OutOfScopeError(
                    f"host '{hp.hostname}' is not in scope: {decision.reason}. "
                    "Add the host identity to the scope include list."
                )
            profiles.append(hp)
            log(f"  [infra-agent] ok — {len(result.findings)} finding(s), "
                f"{hp.software_count} apps")

    all_findings = list(result.findings)
    tool_results = [result]

    # 4a. endpoint posture findings (ports, firewall, UAC, Defender, patches, ...)
    if profiles and profiles[0].posture:
        pf = posture_findings(profiles[0].posture, profiles[0].hostname)
        all_findings += pf
        if pf:
            log(f"  [endpoint-posture] {len(pf)} finding(s)")

    # 4. optional software -> CVE matching via OSV (opt-in; external lookup)
    if cve and profiles and profiles[0].software:
        hp = profiles[0]
        log(f"[osv] matching {hp.software_count} package(s) against OSV.dev")
        osv_res = ToolResult(tool="osv", status=ToolStatus.OK)
        try:
            findings, stats = OSVMatcher(timeout=cve_timeout).match(
                hp.software, hp.os_name, hp.hostname)
            osv_res.findings = findings
            osv_res.message = (f"{stats.vulnerable} vulnerable of {stats.queried} "
                               f"queried; {stats.unmatchable} not matchable")
            all_findings += findings
            log(f"  [osv] {stats.advisories} advisory finding(s) across "
                f"{stats.vulnerable} package(s); {stats.unmatchable} not matchable")
        except OSVUnavailable as exc:
            osv_res.status = ToolStatus.ERROR
            osv_res.message = f"OSV unavailable: {exc}"
            log(f"  [osv] ERROR — {exc}")
        tool_results.append(osv_res)
    elif cve:
        log("[osv] skipped — no software inventory to match")

    # 5. score + assemble
    scored = correlate(all_findings)
    report = RunReport(
        engagement=engagement,
        started=started.isoformat(),
        finished=datetime.now(timezone.utc).isoformat(),
        tool_results=tool_results,
        scored=scored,
        scope_audit=list(gate.audit),
        host_profiles=profiles,
        profile=profile,
        overall_risk=overall_risk(scored),
    )
    log(f"Done. Overall risk: {report.overall_risk}. {len(scored)} finding(s).")
    return report
