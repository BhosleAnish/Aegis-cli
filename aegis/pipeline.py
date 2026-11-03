"""The orchestrator: one call runs discovery -> probing -> vuln matching.

Every stage is gated. `assert_authorized()` runs once up front, and only
in-scope targets are ever handed to a tool. The pipeline is resilient: a missing
or failing tool is recorded and the run continues with whatever is available, so
"minimum human input" holds even on a partial toolchain.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from .models import Credentials, Engagement, Finding, Service
from .scope import ScopeGate
from .scoring import ScoredFinding, correlate, overall_risk, risk_summary
from .tools import (
    DalfoxAdapter,
    FfufAdapter,
    GauAdapter,
    HttpxAdapter,
    KatanaAdapter,
    NmapAdapter,
    NucleiAdapter,
)
from .tools.base import ToolResult, ToolStatus
from .tools.web_assess import run_web_assessment

Logger = Callable[[str], None]


@dataclass
class RunReport:
    engagement: Engagement
    started: str
    finished: str
    tool_results: list[ToolResult] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    scored: list[ScoredFinding] = field(default_factory=list)
    scope_audit: list = field(default_factory=list)
    host_profiles: list = field(default_factory=list)   # HostProfile, from the infra module
    endpoints: list[str] = field(default_factory=list)  # discovered, scope-gated URLs
    components: list[dict] = field(default_factory=list)  # detected tech (product+version)
    profile: str = ""                                   # "", "endpoint", or "appserver"
    mode: str = "blackbox"                              # blackbox | greybox | whitebox
    intensity: str = "safe"                             # safe | standard | aggressive
    overall_risk: str = "INFORMATIONAL"

    def severity_counts(self) -> dict[str, int]:
        return risk_summary(self.scored)


class Pipeline:
    def __init__(
        self,
        engagement: Engagement,
        nmap: Optional[NmapAdapter] = None,
        httpx: Optional[HttpxAdapter] = None,
        nuclei: Optional[NucleiAdapter] = None,
        katana: Optional[KatanaAdapter] = None,
        gau: Optional[GauAdapter] = None,
        ffuf: Optional[FfufAdapter] = None,
        dalfox: Optional[DalfoxAdapter] = None,
        wordlist: Optional[str] = None,
        logger: Optional[Logger] = None,
        host_header: Optional[str] = None,
        discovery: bool = True,
        web_cve: bool = False,
        cve_timeout: int = 20,
        nvd_api_key: Optional[str] = None,
        mode: str = "blackbox",
        intensity: str = "safe",
        credentials: Optional[Credentials] = None,
        sast_findings: Optional[list[Finding]] = None,
        extra_components: Optional[list] = None,
    ):
        self.engagement = engagement
        self.gate = ScopeGate(engagement)
        self.nmap = nmap or NmapAdapter()
        self.httpx = httpx or HttpxAdapter()
        self.nuclei = nuclei or NucleiAdapter()
        self.katana = katana or KatanaAdapter()
        self.gau = gau or GauAdapter()
        self.ffuf = ffuf or FfufAdapter()
        self.dalfox = dalfox or DalfoxAdapter()
        self.wordlist = wordlist
        self.discovery = discovery
        self.web_cve = web_cve
        self.cve_timeout = cve_timeout
        self.nvd_api_key = nvd_api_key
        self.mode = mode
        self.intensity = intensity
        # Active (traffic-generating) tools run only at standard/aggressive.
        self.active_enabled = intensity in ("standard", "aggressive")
        self.credentials = credentials
        self.sast_findings = sast_findings or []
        self.extra_components = extra_components or []
        self.log: Logger = logger or (lambda m: None)
        # When scanning an origin IP as a named vhost, present that Host to the
        # HTTP tools so they reach the real application behind a CDN/LB.
        self.host_header = host_header
        if host_header:
            hdr = f"Host: {host_header}"
            self.httpx.extra_args = list(self.httpx.extra_args) + ["-H", hdr]
            self.nuclei.extra_args = list(self.nuclei.extra_args) + ["-H", hdr]
        # White/grey-box authenticated scanning: inject credential headers into
        # the HTTP tools so they reach logged-in surface. Values are never logged.
        self._cred_count = 0
        if credentials and credentials.is_set():
            cred_args = credentials.header_args()
            for adapter in (self.httpx, self.nuclei, self.katana,
                            self.ffuf, self.dalfox):
                adapter.extra_args = list(adapter.extra_args) + cred_args
            self._cred_count = (len(credentials.headers)
                                + (1 if credentials.cookie else 0)
                                + (1 if credentials.basic else 0))

    def run(self) -> RunReport:
        # 1. authorization gate — hard stop before anything active happens
        self.gate.assert_authorized()
        auth = self.engagement.authorization
        self.log(f"Authorization OK: {auth.engagement} for {auth.client} "
                 f"(ref {auth.signoff_reference})")
        self.log(f"Assessment profile: mode={self.mode}, intensity={self.intensity}")
        if self._cred_count:
            self.log(f"Authenticated scan: {self._cred_count} credential "
                     f"header(s) injected (values not logged)")

        started = datetime.now(timezone.utc)
        results: list[ToolResult] = []
        all_findings: list[Finding] = []
        all_services: list[Service] = []

        # 2. scope filter — only in-scope targets proceed
        candidates = list(self.engagement.scope.include)
        targets = self.gate.filter(candidates)
        for d in self.gate.audit:
            self.log(f"  scope: {d.target} -> {'ALLOW' if d.allowed else 'BLOCK'} ({d.reason})")
        if not targets:
            self.log("No in-scope targets resolved — nothing to do.")
            return self._finalize(started, results, all_services, all_findings)

        # 3. discovery + service/version (nmap)
        self.log(f"[nmap] scanning {len(targets)} in-scope target(s)")
        nmap_res = self.nmap.run(targets, gate=self.gate)
        results.append(nmap_res)
        self._note(nmap_res)
        all_services += nmap_res.services
        all_findings += nmap_res.findings

        # 4. web probing (httpx)
        self.log(f"[httpx] probing {len(all_services)} discovered service(s)")
        httpx_res = self.httpx.run(targets, services=all_services, gate=self.gate)
        results.append(httpx_res)
        self._note(httpx_res)
        all_findings += httpx_res.findings
        urls = getattr(httpx_res, "urls", [])

        # 4b. web-layer assessment (TLS, security headers, CORS) on the primary
        #     host, using the scope hostname (or --host-header) as SNI/Host.
        if urls:
            web_target = targets[0]
            self.log(f"[web-assess] TLS/headers/CORS on {self.host_header or web_target}")
            web_res = run_web_assessment(web_target, self.host_header, logger=self.log)
            results.append(web_res)
            self._note(web_res)
            all_findings += web_res.findings

        # 4c. endpoint discovery (katana crawl + gau passive archives).
        #     Every discovered URL is scope-gated by hostname before it is ever
        #     handed to the vuln scanner — discovery must not widen the scope.
        endpoints = list(urls)
        if self.discovery:
            discovered: list[str] = []
            for res in self._discover(urls):
                results.append(res)
                self._note(res)
                all_findings += res.findings
                discovered += getattr(res, "endpoints", [])
            endpoints = self._scope_gate_urls(list(urls) + discovered)
            self.log(f"[discovery] {len(endpoints)} in-scope endpoint(s) "
                     f"after crawl + passive discovery")

        # 5. vulnerability matching (nuclei) against the discovered endpoint set
        scan_set = endpoints or urls
        self.log(f"[nuclei] matching templates against "
                 f"{len(scan_set) or len(targets)} endpoint(s)")
        nuclei_res = self.nuclei.run(targets, services=all_services,
                                     gate=self.gate, urls=scan_set)
        results.append(nuclei_res)
        self._note(nuclei_res)
        all_findings += nuclei_res.findings

        # 5b. active reflected-XSS testing (non-destructive proof), intensity-gated.
        #     Only parameterized, scope-gated endpoints are tested.
        if self.active_enabled:
            param_urls = [u for u in (endpoints or []) if "=" in u]
            if param_urls:
                self.log(f"[dalfox] reflected-XSS testing on {len(param_urls)} "
                         f"parameterized URL(s) (active, non-destructive)")
                dfx = self.dalfox.run(param_urls, gate=self.gate,
                                      host_header=self.host_header)
                results.append(dfx)
                self._note(dfx)
                all_findings += dfx.findings

        # 6. technology/version fingerprint -> CVE matching.
        #    Extraction is offline and always runs (powers the tech section);
        #    the external NVD/OSV lookup is opt-in (--web-cve).
        from .web_cve import extract_components, match_components, WebCveUnavailable
        components = extract_components(all_services, all_findings)
        if self.extra_components:
            # white-box: client-supplied tech inventory augments what we detect
            components = components + list(self.extra_components)
            self.log(f"[web-cve] + {len(self.extra_components)} client-supplied "
                     f"component(s) from inventory")
        if self.web_cve and components:
            self.log(f"[web-cve] matching {len(components)} versioned "
                     f"component(s) against NVD/OSV")
            wc_res = ToolResult(tool="web-cve", status=ToolStatus.OK)
            try:
                cve_findings, summary = match_components(
                    components, timeout=self.cve_timeout,
                    nvd_api_key=self.nvd_api_key, logger=self.log)
                wc_res.findings = cve_findings
                wc_res.message = summary
                all_findings += cve_findings
                self.log(f"  [web-cve] {summary}")
            except WebCveUnavailable as exc:
                wc_res.status = ToolStatus.ERROR
                wc_res.message = str(exc)
                self.log(f"  [web-cve] ERROR — {exc}")
            results.append(wc_res)
            self._note(wc_res)
        elif self.web_cve:
            self.log("[web-cve] skipped — no versioned components detected")

        # 7. white-box: fold in prior SAST (code) findings so the report rates
        #    code and runtime risk together.
        if self.sast_findings:
            self.log(f"[sast-ingest] folding in {len(self.sast_findings)} code "
                     f"finding(s) from a prior static review")
            all_findings += self.sast_findings

        return self._finalize(started, results, all_services, all_findings,
                              endpoints, components)

    # -- discovery helpers ----------------------------------------------------- #
    def _discover(self, seeds) -> list[ToolResult]:
        """Run the endpoint-discovery tools; return their ToolResults (each
        carrying an `.endpoints` list). Katana crawls live roots; gau pulls
        archived URLs by hostname (no traffic to the target)."""
        out: list[ToolResult] = []
        if seeds:
            self.log(f"[katana] crawling {len(seeds)} live root(s)")
            out.append(self.katana.run(seeds, gate=self.gate,
                                        host_header=self.host_header))
        gau_hosts = self._gau_hostnames()
        if gau_hosts:
            self.log(f"[gau] passive URL discovery for {', '.join(gau_hosts)}")
            out.append(self.gau.run(gau_hosts, gate=self.gate))
        if self.active_enabled and seeds:
            self.log(f"[ffuf] content discovery on {len(seeds)} root(s) "
                     f"(active, non-destructive)")
            out.append(self.ffuf.run(seeds, wordlist=self.wordlist, gate=self.gate,
                                     host_header=self.host_header))
        return out

    def _gau_hostnames(self) -> list[str]:
        """Hostnames gau should query: the presented vhost for an origin-IP scan,
        otherwise the non-IP entries in the scope include list."""
        if self.host_header:
            return [self.host_header]
        hosts = []
        for entry in self.engagement.scope.include:
            host = entry.strip().split("/")[0].split(":")[0]
            if host and not self._is_ip(host):
                hosts.append(host)
        return sorted(set(hosts))

    def _scope_gate_urls(self, urls) -> list[str]:
        """Dedup URLs and keep only those whose hostname is in scope. Each unique
        host is decided once (keeps the audit log readable); drops are logged."""
        seen: set[str] = set()
        unique: list[str] = []
        for u in urls:
            if u and u not in seen:
                seen.add(u)
                unique.append(u)
        host_ok: dict[str, bool] = {}
        for u in unique:
            host = (urlparse(u).hostname or "").lower()
            if host not in host_ok:
                decision = self.gate.is_in_scope(host) if host else None
                host_ok[host] = bool(decision and decision.allowed)
                if host and not host_ok[host]:
                    self.log(f"  discovery: dropped out-of-scope host {host}")
        return [u for u in unique if host_ok.get((urlparse(u).hostname or "").lower())]

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _finalize(self, started, results, services, findings, endpoints=None,
                  components=None) -> RunReport:
        scored = correlate(findings)
        report = RunReport(
            engagement=self.engagement,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            tool_results=results,
            services=services,
            scored=scored,
            scope_audit=list(self.gate.audit),
            endpoints=endpoints or [],
            components=[c.to_dict() for c in (components or [])],
            mode=self.mode,
            intensity=self.intensity,
            overall_risk=overall_risk(scored),
        )
        self.log(f"Done. Overall risk: {report.overall_risk}. "
                 f"{len(scored)} distinct finding(s).")
        return report

    def _note(self, res: ToolResult) -> None:
        if res.status == ToolStatus.UNAVAILABLE:
            self.log(f"  [{res.tool}] SKIPPED — {res.message}")
        elif res.status == ToolStatus.ERROR:
            self.log(f"  [{res.tool}] ERROR — {res.message}")
        elif res.status == ToolStatus.SKIPPED:
            self.log(f"  [{res.tool}] nothing to do — {res.message}")
        else:
            self.log(f"  [{res.tool}] ok — {len(res.findings)} finding(s) "
                     f"in {res.duration_s}s")


def _risk_dict(sf) -> dict:
    """Likelihood×impact risk rating for one scored finding (for findings.json)."""
    from .risk import rate
    r = rate(sf)
    return {"level": r.level, "likelihood": r.likelihood,
            "impact": r.impact, "score": r.score}


def write_run_artifacts(report: RunReport, out_dir: str | Path) -> Path:
    """Persist raw findings as JSON for later diffing / ingestion. Returns dir."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "engagement": report.engagement.authorization.engagement,
        "client": report.engagement.authorization.client,
        "started": report.started,
        "finished": report.finished,
        "overall_risk": report.overall_risk,
        "severity_counts": report.severity_counts(),
        "findings": [sf.finding.to_dict() | {"confidence": sf.confidence,
                                             "corroborated_by": sf.corroborated_by,
                                             "risk": _risk_dict(sf)}
                     for sf in report.scored],
        "host_profiles": [p.to_dict() for p in report.host_profiles],
        "endpoints": report.endpoints,
        "components": report.components,
        "scope_audit": [vars(d) for d in report.scope_audit],
    }
    (out / "findings.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )
    return out
