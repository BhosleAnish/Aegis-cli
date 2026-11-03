"""Command-line entry point.

    aegis scan --scope config/scope.yaml --auth config/authorization.yaml
    aegis check --scope config/scope.yaml --auth config/authorization.yaml
    aegis doctor

`scan` runs the full pipeline and writes a report. `check` validates scope +
authorization and prints the scope decisions WITHOUT sending a single packet —
use it to confirm an engagement is wired correctly before going live. `doctor`
reports which external tools are installed.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .infra import run_infra
from .models import Credentials, Engagement, Finding, Scope
from .pipeline import Pipeline, write_run_artifacts
from .report_profiles import render_report
from .sast import run_sast
from .scope import (
    AuthorizationError,
    OutOfScopeError,
    ScopeGate,
    _load_authorization,
    load_engagement,
)
from .tools import (
    DalfoxAdapter,
    FfufAdapter,
    GauAdapter,
    HttpxAdapter,
    KatanaAdapter,
    NmapAdapter,
    NucleiAdapter,
)
from .tools.bandit_adapter import BanditAdapter
from .tools.gitleaks_adapter import GitleaksAdapter
from .tools.gosec_adapter import GosecAdapter
from .tools.infra_adapter import InfraAdapter, InfraError
from .tools.semgrep_adapter import SemgrepAdapter
from .tools.trivy_adapter import TrivyAdapter


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _write_outputs(eng, report, out, pdf=False) -> int:
    """Write findings.json + report.md (+ optional report.pdf); print paths."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_dir = Path(out) / f"{eng.authorization.engagement}-{stamp}".replace(" ", "_")
    write_run_artifacts(report, run_dir)
    md = render_report(report)
    report_path = run_dir / "report.md"
    report_path.write_text(md, encoding="utf-8")
    print(f"\nReport:    {report_path}")
    print(f"Findings:  {run_dir / 'findings.json'}")
    if pdf:
        from .report_pdf import PdfUnavailable, markdown_to_pdf
        try:
            pdf_path = markdown_to_pdf(md, run_dir / "report.pdf",
                                       title=eng.authorization.engagement)
            print(f"PDF:       {pdf_path}")
        except PdfUnavailable as exc:
            _stderr(f"PDF export skipped: {exc}")
    print(f"Risk:      {report.overall_risk}")
    return 0


def _cmd_doctor(_args) -> int:
    print("Aegis tool check:")
    ok = True
    for adapter in (NmapAdapter(), HttpxAdapter(), NucleiAdapter(),
                    KatanaAdapter(), GauAdapter(), FfufAdapter(), DalfoxAdapter()):
        present = adapter.available()
        ok = ok and present
        mark = "present" if present else "MISSING"
        print(f"  [{'x' if present else ' '}] {adapter.binary:8} {mark}")
    print("  -- SAST --")
    for adapter in (BanditAdapter(), GosecAdapter(), SemgrepAdapter(),
                    TrivyAdapter(), GitleaksAdapter()):
        present = adapter.available()
        print(f"  [{'x' if present else ' '}] {adapter.name:8} "
              f"{'present' if present else 'MISSING'}")
    if not ok:
        print("\nSome tools are missing. Aegis still runs, skipping their stages.")
    return 0


def _cmd_sast(args) -> int:
    path = Path(args.path)
    if not path.is_dir():
        _stderr(f"path not found or not a directory: {path}")
        return 2
    try:
        auth = _load_authorization(args.auth)
    except (AuthorizationError, ValueError, FileNotFoundError) as exc:
        _stderr(f"config error: {exc}")
        return 2
    # SAST targets a code path, not a host: the path itself is the scope.
    eng = Engagement(authorization=auth, scope=Scope(include=[str(path)]))
    try:
        report = run_sast(eng, str(path), logger=_stderr)
    except AuthorizationError as exc:
        _stderr(f"GATE BLOCKED: {exc}")
        return 3
    return _write_outputs(eng, report, args.out, pdf=args.pdf)


def _cmd_check(args) -> int:
    try:
        eng = load_engagement(args.scope, args.auth)
    except (AuthorizationError, ValueError, FileNotFoundError) as exc:
        _stderr(f"config error: {exc}")
        return 2

    gate = ScopeGate(eng)
    try:
        gate.assert_authorized()
        print("Authorization: VALID")
    except AuthorizationError as exc:
        print(f"Authorization: INVALID — {exc}")
        return 3

    print(f"Engagement: {eng.authorization.engagement} / {eng.authorization.client}")
    print("Scope decisions:")
    for entry in eng.scope.include:
        d = gate.is_in_scope(entry)
        print(f"  {entry:30} -> {'ALLOW' if d.allowed else 'BLOCK'} ({d.reason})")
    for entry in eng.scope.exclude:
        print(f"  {entry:30} -> EXCLUDED")
    print("\nNo packets were sent (check mode).")
    return 0


def _cmd_scan(args) -> int:
    try:
        eng = load_engagement(args.scope, args.auth)
    except (AuthorizationError, ValueError, FileNotFoundError) as exc:
        _stderr(f"config error: {exc}")
        return 2

    nmap = NmapAdapter(extra_args=_split(args.nmap_args), timeout=args.timeout)
    httpx = HttpxAdapter(extra_args=_split(args.httpx_args), timeout=args.timeout)
    nuclei = NucleiAdapter(extra_args=_split(args.nuclei_args), timeout=args.timeout)
    katana = KatanaAdapter(extra_args=_split(args.katana_args), timeout=args.timeout)
    gau = GauAdapter(extra_args=_split(args.gau_args), timeout=args.timeout)
    ffuf = FfufAdapter(extra_args=_split(args.ffuf_args), timeout=args.timeout)
    dalfox = DalfoxAdapter(extra_args=_split(args.dalfox_args), timeout=args.timeout)

    default_host = eng.scope.include[0] if eng.scope.include else ""
    credentials = _build_credentials(args)
    sast_findings = _load_findings_json(args.sast_json, "SAST findings") \
        if args.sast_json else []
    inventory = _load_inventory(args.tech_inventory, default_host) \
        if args.tech_inventory else []

    if args.mode in ("greybox", "whitebox") and not (credentials or sast_findings
                                                     or inventory):
        _stderr(f"note: --mode {args.mode} given without credentials, --sast-json, "
                "or --tech-inventory — running as an unauthenticated black-box scan.")

    pipeline = Pipeline(eng, nmap=nmap, httpx=httpx, nuclei=nuclei,
                        katana=katana, gau=gau, ffuf=ffuf, dalfox=dalfox,
                        wordlist=args.wordlist, logger=_stderr,
                        host_header=args.host_header,
                        discovery=not args.no_discovery,
                        web_cve=args.web_cve, cve_timeout=args.cve_timeout,
                        nvd_api_key=args.nvd_api_key or os.environ.get("NVD_API_KEY"),
                        mode=args.mode, intensity=args.intensity,
                        credentials=credentials, sast_findings=sast_findings,
                        extra_components=inventory)
    try:
        report = pipeline.run()
    except (AuthorizationError, OutOfScopeError) as exc:
        _stderr(f"GATE BLOCKED: {exc}")
        return 3

    return _write_outputs(eng, report, args.out, pdf=args.pdf)


def _cmd_infra(args) -> int:
    try:
        eng = load_engagement(args.scope, args.auth)
    except (AuthorizationError, ValueError, FileNotFoundError) as exc:
        _stderr(f"config error: {exc}")
        return 2

    agent_dir = args.agent_dir or os.environ.get("AEGIS_AGENT_DIR")
    if not agent_dir and not args.infra_json:
        _stderr("provide --agent-dir (run collectors locally) or --infra-json "
                "(ingest inventory), or set AEGIS_AGENT_DIR")
        return 2

    adapter = InfraAdapter(agent_dir=agent_dir, inventory_json=args.infra_json,
                           timeout=args.timeout)
    try:
        report = run_infra(eng, adapter, logger=_stderr,
                           cve=args.cve, cve_timeout=args.cve_timeout,
                           profile=args.profile or "")
    except (AuthorizationError, OutOfScopeError) as exc:
        _stderr(f"GATE BLOCKED: {exc}")
        return 3
    except InfraError as exc:
        _stderr(f"infra error: {exc}")
        return 4

    return _write_outputs(eng, report, args.out, pdf=args.pdf)


def _split(value):
    import shlex
    return shlex.split(value) if value else []


def _load_findings_json(path, label):
    """Re-ingest findings from a prior run's findings.json (e.g. SAST)."""
    import json
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _stderr(f"could not read {label} {path}: {exc}")
        return []
    items = data.get("findings", []) if isinstance(data, dict) else data
    out = []
    for d in items:
        try:
            out.append(Finding.from_dict(d))
        except (TypeError, ValueError):
            continue
    return out


def _load_inventory(path, default_host):
    """Load a client-supplied tech inventory [{product, version, host?}] into
    WebComponents (white-box: skip guessing, match these versions directly)."""
    import json

    from .web_cve import WebComponent, canonicalize
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _stderr(f"could not read tech inventory {path}: {exc}")
        return []
    if isinstance(data, dict):
        data = data.get("components", [])
    out = []
    for it in data:
        product, version = it.get("product"), it.get("version")
        if product and version:
            out.append(WebComponent(
                product=str(product), version=str(version),
                host=str(it.get("host") or default_host or ""),
                source="client-inventory", canonical=canonicalize(str(product))))
    return out


def _build_credentials(args):
    creds = Credentials(headers=list(args.auth_header or []),
                        cookie=args.cookie or "", basic=args.basic or "")
    return creds if creds.is_set() else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis",
                                description="Automation-first VAPT orchestrator "
                                            "for authorized engagements.")
    sub = p.add_subparsers(dest="command", required=True)

    def add_cfg(sp):
        sp.add_argument("--scope", required=True, help="path to scope YAML")
        sp.add_argument("--auth", required=True, help="path to authorization YAML")

    sp_scan = sub.add_parser("scan", help="run the full VAPT pipeline")
    add_cfg(sp_scan)
    sp_scan.add_argument("--out", default="runs", help="output directory (default: runs)")
    sp_scan.add_argument("--pdf", action="store_true",
                         help="also export the report as PDF (needs markdown + xhtml2pdf)")
    sp_scan.add_argument("--host-header",
                         help="present this Host header to the HTTP tools (e.g. scan an "
                              "origin IP as its real vhost: --host-header prismgrc.co)")
    sp_scan.add_argument("--timeout", type=int, default=1800,
                         help="per-tool timeout in seconds")
    sp_scan.add_argument("--nmap-args", default="", help="extra args passed to nmap")
    sp_scan.add_argument("--httpx-args", default="", help="extra args passed to httpx")
    sp_scan.add_argument("--nuclei-args", default="", help="extra args passed to nuclei")
    sp_scan.add_argument("--katana-args", default="", help="extra args passed to katana")
    sp_scan.add_argument("--gau-args", default="", help="extra args passed to gau")
    sp_scan.add_argument("--ffuf-args", default="", help="extra args passed to ffuf")
    sp_scan.add_argument("--dalfox-args", default="", help="extra args passed to dalfox")
    sp_scan.add_argument("--wordlist",
                         help="wordlist for ffuf content discovery (needed for the "
                              "active content-discovery stage)")
    sp_scan.add_argument("--no-discovery", action="store_true",
                         help="skip endpoint discovery (katana crawl + gau passive URLs) "
                              "and scan only the live roots found by httpx")
    sp_scan.add_argument("--web-cve", action="store_true",
                         help="match detected web tech/versions against NVD + OSV known "
                              "CVEs (external call: sends product names+versions)")
    sp_scan.add_argument("--nvd-api-key", default="",
                         help="NVD API key to raise the rate limit (or set NVD_API_KEY)")
    sp_scan.add_argument("--cve-timeout", type=int, default=20,
                         help="per-request NVD/OSV timeout in seconds")
    # Assessment profile: mode (knowledge/credentials) + intensity (intrusiveness)
    sp_scan.add_argument("--mode", choices=["blackbox", "greybox", "whitebox"],
                         default="blackbox",
                         help="assessment mode (white/grey-box use credentials + context)")
    sp_scan.add_argument("--intensity", choices=["safe", "standard", "aggressive"],
                         default="safe",
                         help="how intrusive active testing may be (active tools are "
                              "gated on this; 'safe' is passive/non-destructive)")
    sp_scan.add_argument("--auth-header", action="append", metavar="'Name: value'",
                         help="credential header for authenticated scanning (repeatable)")
    sp_scan.add_argument("--cookie", default="", help="Cookie header value for auth scanning")
    sp_scan.add_argument("--basic", default="", metavar="user:pass",
                         help="HTTP Basic credentials for authenticated scanning")
    sp_scan.add_argument("--sast-json", help="white-box: fold in a prior SAST "
                                             "findings.json so code + runtime risk are "
                                             "rated together")
    sp_scan.add_argument("--tech-inventory", help="white-box: client-supplied tech "
                                                  "inventory JSON [{product,version,host}] "
                                                  "to match against CVEs with --web-cve")
    sp_scan.set_defaults(func=_cmd_scan)

    sp_infra = sub.add_parser(
        "infra", help="infrastructure analysis via the MonitoringAgent collectors")
    add_cfg(sp_infra)
    sp_infra.add_argument("--agent-dir",
                          help="path to the MonitoringAgent 'agent' dir to run collectors "
                               "locally; or set AEGIS_AGENT_DIR")
    sp_infra.add_argument("--infra-json",
                          help="ingest a pre-collected inventory JSON instead of collecting")
    sp_infra.add_argument("--profile", choices=["endpoint", "appserver"],
                          help="render a profile-specific report (endpoint or appserver)")
    sp_infra.add_argument("--cve", action="store_true",
                          help="match installed software against OSV.dev known "
                               "vulnerabilities (external call: sends package names+versions)")
    sp_infra.add_argument("--cve-timeout", type=int, default=20,
                          help="per-request OSV API timeout in seconds")
    sp_infra.add_argument("--out", default="runs", help="output directory (default: runs)")
    sp_infra.add_argument("--pdf", action="store_true",
                          help="also export the report as PDF (needs markdown + xhtml2pdf)")
    sp_infra.add_argument("--timeout", type=int, default=180,
                          help="collector timeout in seconds")
    sp_infra.set_defaults(func=_cmd_infra)

    sp_check = sub.add_parser("check",
                              help="validate scope + auth without scanning")
    add_cfg(sp_check)
    sp_check.set_defaults(func=_cmd_check)

    sp_sast = sub.add_parser(
        "sast", help="static code review of a source tree (bandit, semgrep, gitleaks)")
    sp_sast.add_argument("--path", required=True, help="path to the source tree to scan")
    sp_sast.add_argument("--auth", required=True, help="path to authorization YAML")
    sp_sast.add_argument("--out", default="runs", help="output directory (default: runs)")
    sp_sast.add_argument("--pdf", action="store_true",
                         help="also export the report as PDF")
    sp_sast.set_defaults(func=_cmd_sast)

    sp_doc = sub.add_parser("doctor", help="report which external tools are installed")
    sp_doc.set_defaults(func=_cmd_doctor)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
