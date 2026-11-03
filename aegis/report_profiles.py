"""Profile-specific report renderers: endpoint vs application server.

Both follow the standard VAPT report structure (13 sections). Each section is
filled from the data Aegis actually collected; anything that needs a data source
we have not wired yet is rendered as an explicit "Not assessed — requires X"
note rather than fabricated, so the report stays trustworthy.

`render_report(report)` dispatches on `report.profile`; an empty profile falls
back to the generic network renderer in report.py.
"""
from __future__ import annotations

import re

from .models import Severity
from .pipeline import RunReport
from .report import _SEV_EMOJI, _tpm_state, _tri, render_markdown


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _na(what: str) -> str:
    return f"> _Not assessed — requires {what}._"


def _findings(report: RunReport, exclude_info: bool = True):
    out = []
    for sf in report.scored:
        if exclude_info and sf.finding.severity.rank == Severity.INFO.rank:
            continue
        out.append(sf)
    return out


def _header(report: RunReport, kind: str) -> list[str]:
    a = report.engagement.authorization
    return [
        f"# {kind} Assessment — {a.engagement}",
        "",
        f"**Client:** {a.client}  ",
        f"**Overall risk:** {report.overall_risk}  ",
        f"**Window:** {report.started} → {report.finished}  ",
        "",
        "## 1. Header and authorization",
        "",
        f"- Authorized by: **{a.authorized_by}** ({a.contact_email})",
        f"- Sign-off reference: `{a.signoff_reference}`",
        f"- Validity: {a.valid_from} → {a.valid_until}",
    ]


def _exec_summary(report: RunReport) -> list[str]:
    counts = report.severity_counts()
    lines = ["## 3. Executive summary", "",
             f"Overall risk is **{report.overall_risk}**. Findings by severity:",
             "", "| Severity | Count |", "| --- | --- |"]
    for sev in reversed(list(Severity)):
        lines.append(f"| {_SEV_EMOJI[sev.value]} {sev.value.title()} | {counts[sev.value]} |")
    top = _findings(report)[:5]
    if top:
        lines += ["", "**Top findings:**"]
        for sf in top:
            f = sf.finding
            lines.append(f"- {_SEV_EMOJI[f.severity.value]} **{f.severity.value.upper()}** "
                         f"— {f.title}")
    else:
        lines += ["", "_No findings above informational severity._"]
    return lines


def _findings_section(report: RunReport, heading: str, proof_label: str) -> list[str]:
    lines = [f"## 6. {heading}", ""]
    vulns = _findings(report)
    if not vulns:
        lines += ["_No findings above informational severity._", ""]
        return lines
    for i, sf in enumerate(vulns, 1):
        f = sf.finding
        loc = f.host + (f":{f.port}" if f.port else "")
        lines += [
            f"### 6.{i} {_SEV_EMOJI[f.severity.value]} {f.title}",
            "",
            f"- **Severity:** {f.severity.value.upper()}"
            + (f" (CVSS {f.cvss})" if f.cvss else ""),
            f"- **Asset:** {loc}",
            f"- **Source:** {f.source_tool}"
            + (f" — corroborated by {', '.join(sf.corroborated_by)}"
               if sf.confidence == "confirmed" else ""),
        ]
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        if f.cve:
            lines.append(f"- **CVE:** {', '.join(f.cve)}")
        if f.description:
            lines += ["", f.description]
        if f.evidence:
            lines += ["", f"**{proof_label}:**", "", f"```\n{f.evidence}\n```"]
        if f.remediation:
            lines += ["", f"**Remediation:** {f.remediation}"]
        lines.append("")
    return lines


def _risk_prioritization(report: RunReport) -> list[str]:
    lines = ["## 11. Risk prioritization", "",
             "| # | Severity | CVSS | Finding | Asset |", "| --- | --- | --- | --- | --- |"]
    for i, sf in enumerate(_findings(report), 1):
        f = sf.finding
        loc = f.host + (f":{f.port}" if f.port else "")
        lines.append(f"| {i} | {f.severity.value.upper()} | {f.cvss or '—'} | "
                     f"{f.title} | {loc} |")
    if len(lines) == 4:
        lines.append("| — | — | — | _no elevated findings_ | — |")
    return lines


def _remediation(report: RunReport) -> list[str]:
    lines = ["## 12. Remediation and retest", "",
             "Fix in severity order; retest each item after remediation.", "",
             "| Severity | Finding | Remediation |", "| --- | --- | --- |"]
    for sf in _findings(report):
        f = sf.finding
        lines.append(f"| {f.severity.value.upper()} | {f.title} | "
                     f"{f.remediation or 'See finding detail.'} |")
    if len(lines) == 6:
        lines.append("| — | _none_ | — |")
    return lines


def _signoff(report: RunReport) -> list[str]:
    a = report.engagement.authorization
    lines = ["## 13. Appendices and sign-off", "", "**Tool coverage:**", "",
             "| Tool | Status | Findings |", "| --- | --- | --- |"]
    for res in report.tool_results:
        lines.append(f"| {res.tool} | {res.status.value} | {len(res.findings)} |")
    lines += ["", f"Assessment authorized under `{a.signoff_reference}` by "
              f"{a.authorized_by}. Scope and authorization enforced at collection time.",
              "", "Tester sign-off: ____________________   Date: __________",
              "", "---", "", "_Generated by Aegis._"]
    return lines


# --------------------------------------------------------------------------- #
# Endpoint profile
# --------------------------------------------------------------------------- #
def render_endpoint(report: RunReport) -> str:
    p = report.host_profiles[0] if report.host_profiles else None
    posture = (p.posture if p else {}) or {}
    L = _header(report, "Endpoint")
    L += ["- Management status (MDM / Intune / JAMF): ", _na("MDM/EDR enrolment data")]

    L += ["", "## 2. Scope and coverage", "",
          f"Host-based assessment of **{p.hostname if p else '?'}** via the Aegis "
          "agent collectors and endpoint posture checks. Network/web testing is out "
          "of scope for this profile.",
          "", "| Area | Covered |", "| --- | --- |",
          "| Hardware / OS / software inventory | yes |",
          "| Encryption, TPM, Secure Boot | yes (needs admin for definitive) |",
          "| Listening ports, firewall, UAC, Defender | yes |",
          "| Local administrators, patch recency | yes |",
          "| MDM enrolment, USB policy, drivers/firmware | not assessed |"]

    L += [""] + _exec_summary(report)

    # 4. Asset inventory
    L += ["", "## 4. Asset inventory", ""]
    if p:
        L += [
            f"- **OS:** {p.os_name or '?'} {p.os_version or ''} (build {p.os_build or '?'}, {p.architecture or '?'})",
            f"- **Machine:** {p.manufacturer or '?'} {p.model or ''}".rstrip(),
            f"- **Secure Boot:** {_tri(p.secure_boot)}  |  **TPM:** {_tpm_state(p)}",
            f"- **Installed software:** {p.software_count}",
        ]
        if p.volumes:
            L += ["", "**Volumes / encryption:**", "",
                  "| Volume | File system | Encryption |", "| --- | --- | --- |"]
            for v in p.volumes:
                lbl = f"{v.get('mount', '?')} {v.get('label', '')}".strip()
                L.append(f"| {lbl} | {v.get('fileSystem', '?')} | {v.get('encryption') or 'unknown'} |")
        admins = posture.get("localAdmins") or []
        if admins:
            L += ["", f"**Local administrators ({len(admins)}):** " + ", ".join(admins[:20])]
        if p.pii:
            L += ["", "**Sensitive data (categories/counts only):** "
                  + ", ".join(f"{k}={v}" for k, v in sorted(p.pii.items()))]
    else:
        L.append("_No host profile collected._")

    # 5. Attack surface
    L += ["", "## 5. Attack surface", ""]
    ports = posture.get("listeningPorts") or []
    if ports:
        L += ["**Listening ports:**", "", "| Port | Address | Process |", "| --- | --- | --- |"]
        for pr in ports[:50]:
            L.append(f"| {pr.get('port')} | {pr.get('address')} | {pr.get('process') or '?'} |")
    else:
        L += ["Listening ports: none detected or not collected."]
    rdp = posture.get("rdpEnabled")
    L += ["", f"- **Remote Desktop (RDP):** {'enabled' if rdp else 'disabled' if rdp is False else 'unknown'}"]
    nps = posture.get("networkProfiles") or []
    if nps:
        L.append("- **Network profiles:** " + ", ".join(f"{n.get('name')} ({n.get('category')})" for n in nps))
    L += ["- **Outbound connections / USB device policy:**", _na("live connection + USB policy capture")]

    # 6. Findings
    L += [""] + _findings_section(report, "Findings (host-level)", "Proof")

    # 7. Patch and update status
    L += ["", "## 7. Patch and update status", ""]
    hotfixes = posture.get("hotfixes") or []
    if hotfixes:
        L += ["| Hotfix | Installed |", "| --- | --- |"]
        for h in hotfixes[:15]:
            L.append(f"| {h.get('id')} | {h.get('installedOn') or '?'} |")
    else:
        L.append("OS hotfix history not available.")
    L += ["", "- **Driver / firmware status:**", _na("driver + firmware inventory")]

    # 8. Security controls
    L += ["", "## 8. Security controls", "", "| Control | State |", "| --- | --- |"]
    fw = posture.get("firewall") or []
    fw_state = ", ".join(f"{f.get('name')}={'on' if f.get('enabled') else 'off'}" for f in fw) or "unknown"
    d = posture.get("defender")
    defender_state = ("off" if d and (d.get("realtime") is False) else
                      "on" if d and d.get("realtime") else "unknown")
    L += [
        f"| Disk encryption (per volume) | see Asset inventory |",
        f"| Host firewall | {fw_state} |",
        f"| UAC | {'enabled' if posture.get('uacEnabled') == 1 else 'disabled' if posture.get('uacEnabled') == 0 else 'unknown'} |",
        f"| Windows Defender / EDR real-time | {defender_state} |",
        f"| PowerShell script-block logging | {'on' if posture.get('psScriptBlockLogging') in (1, '1') else 'off/unknown'} |",
        f"| Screen-lock timeout | {(str(posture.get('screenLockSecs')) + 's') if posture.get('screenLockSecs') else 'not set/unknown'} |",
    ]

    # 9. Identity and access
    L += ["", "## 9. Identity and access", ""]
    admins = posture.get("localAdmins") or []
    L.append(f"- **Local administrators:** {len(admins) if admins else 'not collected'}"
             + (" — " + ", ".join(admins[:20]) if admins else ""))
    L += ["- **Sign-in method (password/PIN/Windows Hello):**", _na("sign-in method enumeration"),
          "- **Stored/cached credentials:**", _na("credential-store inspection (requires admin)")]

    # 10. Configuration baseline
    L += ["", "## 10. Configuration baseline", "",
          "Partial mapping to CIS Windows 11 / Microsoft Security Baseline from the "
          "controls above (firewall, UAC, encryption, Defender, logging). A full "
          "baseline comparison is not yet automated:",
          _na("full CIS Windows 11 / MS Security Baseline check")]

    L += [""] + _risk_prioritization(report)
    L += [""] + _remediation(report)
    L += [""] + _signoff(report)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Application-server profile
# --------------------------------------------------------------------------- #
_STACK_KEYWORDS = {
    "web server": ["nginx", "apache", "httpd", "iis", "caddy", "tomcat"],
    "runtime": ["python", "node", "node.js", "java", "jdk", "jre", "php", ".net",
                "dotnet", "ruby", "golang"],
    "database": ["mysql", "mariadb", "postgresql", "postgres", "sql server",
                 "mssql", "redis", "mongodb", "oracle database"],
    "container": ["docker", "containerd", "kubernetes", "kubelet", "podman"],
}


def _kw_match(keyword: str, name: str) -> bool:
    """Whole-token match so 'redis' does not match 'redistributable', etc."""
    return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", name) is not None


def _classify_stack(software: list[dict]) -> dict:
    groups: dict[str, list[str]] = {k: [] for k in _STACK_KEYWORDS}
    for app in software:
        name = (app.get("name") or "").lower()
        label = f"{app.get('name')} {app.get('version') or ''}".strip()
        for group, kws in _STACK_KEYWORDS.items():
            if any(_kw_match(kw, name) for kw in kws):
                groups[group].append(label)
    return {k: sorted(set(v)) for k, v in groups.items() if v}


def render_appserver(report: RunReport) -> str:
    p = report.host_profiles[0] if report.host_profiles else None
    posture = (p.posture if p else {}) or {}
    software = p.software if p else []
    L = _header(report, "Application Server")

    L += ["", "## 2. Scope, methodology and coverage", "",
          f"Server host **{p.hostname if p else '?'}** assessed from host inventory "
          "+ dependency analysis. **Active web-application testing (endpoints, TLS, "
          "OWASP Top 10) is not part of this profile** — run `aegis scan` against the "
          "service for that layer.",
          "", "| Area | Covered |", "| --- | --- |",
          "| App stack / dependency inventory | yes |",
          "| Dependency CVEs (with `--cve`) + runtime EOL | yes |",
          "| Listening ports / backend exposure | yes |",
          "| Web endpoints, TLS, auth, WAF, OWASP Top 10 | not assessed (needs web testing) |",
          "| Headers, CORS, rate limiting, secrets mgmt | not assessed |"]

    L += [""] + _exec_summary(report)

    # 4. Asset inventory: stack
    L += ["", "## 4. Asset inventory: stack, dependencies, hosting", ""]
    stack = _classify_stack(software)
    if stack:
        for group, items in stack.items():
            L.append(f"- **{group.title()}:** " + ", ".join(items[:15]))
    else:
        L.append("- No recognizable web/runtime/database/container components in the inventory.")
    L += [f"- **Total installed packages:** {len(software)}",
          "- **Containers / orchestration detail, hosting/cloud metadata:**",
          _na("container runtime inspection + hosting metadata")]

    # 5. Attack surface
    L += ["", "## 5. Attack surface", ""]
    ports = posture.get("listeningPorts") or []
    if ports:
        L += ["**Listening ports (backend exposure):**", "",
              "| Port | Address | Process |", "| --- | --- | --- |"]
        for pr in ports[:50]:
            L.append(f"| {pr.get('port')} | {pr.get('address')} | {pr.get('process') or '?'} |")
    else:
        L.append("Listening ports: none detected or not collected.")
    L += ["", "- **HTTP endpoints, TLS configuration, auth surface, WAF:**",
          _na("active web assessment (aegis scan / web module)")]

    # 6. Findings
    L += [""] + _findings_section(report, "Findings", "Evidence")
    L += ["> OWASP Top 10 categories with request/response proof require active web "
          "testing, which this profile does not perform.", ""]

    # 7. Dependency and patch status
    L += ["## 7. Dependency and patch status (SCA)", ""]
    cve = [sf for sf in report.scored if sf.finding.source_tool == "osv"]
    if cve:
        L += [f"OSV matched **{len(cve)}** known-vulnerable dependency finding(s). "
              "See Findings for detail."]
    else:
        L += ["No dependency CVEs matched (run with `--cve` to enable OSV matching, "
              "or the software has no OSV-ecosystem mapping)."]
    if p and p.os_name:
        from .data.os_eol import os_eol_status
        status, detail = os_eol_status(p.os_name)
        L += ["", f"- **Runtime/OS EOL:** {detail}"]

    # 8. Security controls
    fw_state = ", ".join(
        f"{fw.get('name')}={'on' if fw.get('enabled') else 'off'}"
        for fw in (posture.get("firewall") or [])
    ) or "unknown"
    L += ["", "## 8. Security controls", "", "| Control | State |", "| --- | --- |",
          "| Security headers | not assessed (web) |",
          "| CORS policy | not assessed (web) |",
          "| Rate limiting | not assessed (web) |",
          f"| Host firewall | {fw_state} |",
          "| Secrets management | not assessed |"]

    # 9. Identity and access
    L += ["", "## 9. Identity and access", "",
          "- **App roles, service accounts, default accounts:**",
          _na("application-level identity review"),
          f"- **Host local administrators:** {len(posture.get('localAdmins') or []) or 'not collected'}"]

    # 10. Configuration baseline
    L += ["", "## 10. Configuration baseline", "",
          "- **OWASP ASVS / web server hardening:**", _na("web configuration review"),
          "- **CIS Docker / Kubernetes benchmark:**", _na("container configuration inspection")]

    L += [""] + _risk_prioritization(report)
    L += [""] + _remediation(report)
    L += [""] + _signoff(report)
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
def render_report(report: RunReport) -> str:
    if report.profile == "endpoint":
        return render_endpoint(report)
    if report.profile == "appserver":
        return render_appserver(report)
    return render_markdown(report)
