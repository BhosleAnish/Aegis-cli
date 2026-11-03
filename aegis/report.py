"""Report generation — assessment-grade Markdown from a RunReport.

Markdown is the portable base format; convert to PDF/HTML downstream with pandoc
if needed. The report leads with engagement authorization details (so the output
itself documents that the work was in scope and signed off), then the risk
summary, then findings ordered by severity.
"""
from __future__ import annotations

from .models import Severity
from .pipeline import RunReport
from .risk import rate, render_remediation, render_risk_matrix

_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _tri(value) -> str:
    """Render a tri-state boolean (True/False/None) for the report."""
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _tpm_state(profile) -> str:
    if profile.tpm_present is True:
        return "present, " + ("enabled" if profile.tpm_enabled else "disabled")
    if profile.tpm_present is False:
        return "absent"
    return "unknown"


def render_markdown(report: RunReport) -> str:
    auth = report.engagement.authorization
    counts = report.severity_counts()
    lines: list[str] = []

    lines += [
        f"# VAPT Report — {auth.engagement}",
        "",
        f"**Client:** {auth.client}  ",
        f"**Assessment:** {report.mode} / intensity: {report.intensity}  ",
        f"**Overall risk:** {report.overall_risk}  ",
        f"**Scan window:** {report.started} → {report.finished}  ",
        "",
        "## Authorization",
        "",
        f"- Authorized by: **{auth.authorized_by}** ({auth.contact_email})",
        f"- Sign-off reference: `{auth.signoff_reference}`",
        f"- Validity: {auth.valid_from} → {auth.valid_until}",
    ]
    if auth.rules_of_engagement:
        lines += ["", "**Rules of engagement:**", "", f"> {auth.rules_of_engagement}"]

    # risk summary table
    lines += [
        "",
        "## Risk summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in reversed(list(Severity)):   # critical first
        lines.append(f"| {_SEV_EMOJI[sev.value]} {sev.value.title()} | {counts[sev.value]} |")

    # risk assessment: likelihood × impact matrix + prioritised remediation
    matrix = render_risk_matrix(report.scored)
    remediation = render_remediation(report.scored)
    if matrix or remediation:
        lines += ["", "## Risk assessment", ""]
        lines += matrix
        lines += remediation

    # tool coverage
    lines += ["", "## Tool coverage", "", "| Tool | Status | Findings | Time |",
              "| --- | --- | --- | --- |"]
    for res in report.tool_results:
        lines.append(f"| {res.tool} | {res.status.value} | "
                     f"{len(res.findings)} | {res.duration_s}s |")

    # findings (skip pure attack-surface INFO in the main body; list separately)
    vulns = [sf for sf in report.scored
             if sf.finding.severity.rank > Severity.INFO.rank]
    surface = [sf for sf in report.scored
               if sf.finding.severity.rank == Severity.INFO.rank]

    lines += ["", "## Findings", ""]
    if not vulns:
        lines += ["_No findings above informational severity._", ""]
    for i, sf in enumerate(vulns, 1):
        f = sf.finding
        lines += [
            f"### {i}. {_SEV_EMOJI[f.severity.value]} {f.title}",
            "",
            f"- **Severity:** {f.severity.value.upper()}"
            + (f" (CVSS {f.cvss})" if f.cvss else ""),
        ]
        r = rate(sf)
        lines.append(
            f"- **Risk:** {r.level} (likelihood {r.likelihood} × "
            f"impact {r.impact} = {r.score})")
        lines.append(
            f"- **Asset:** {f.host}" + (f":{f.port}/{f.protocol}" if f.port else ""))
        if f.location:
            lines.append(f"- **Location:** `{f.location}`")
        lines += [
            f"- **Confidence:** {sf.confidence} "
            f"(corroborated by: {', '.join(sf.corroborated_by)})",
        ]
        if f.cve:
            lines.append(f"- **CVE:** {', '.join(f.cve)}")
        if f.description:
            lines += ["", f.description]
        if f.evidence:
            lines += ["", "**Evidence:**", "", f"```\n{f.evidence}\n```"]
        if f.remediation:
            lines += ["", f"**Remediation:** {f.remediation}"]
        if f.references:
            lines += ["", "**References:**"] + [f"- {r}" for r in f.references]
        lines.append("")

    # host profile (infra module)
    if report.host_profiles:
        lines += ["## Host profile", ""]
        for p in report.host_profiles:
            lines += [
                f"### {p.hostname}",
                "",
                f"- **OS:** {p.os_name or '?'} {p.os_version or ''} "
                f"(build {p.os_build or '?'}, {p.architecture or '?'})",
                f"- **Machine:** {p.manufacturer or '?'} {p.model or ''}".rstrip(),
                f"- **Secure Boot:** {_tri(p.secure_boot)}",
                f"- **TPM:** {_tpm_state(p)}",
                f"- **Installed software:** {p.software_count}",
            ]
            if p.volumes:
                lines += ["", "| Volume | File system | Encryption |",
                          "| --- | --- | --- |"]
                for v in p.volumes:
                    label = f"{v.get('mount', '?')} {v.get('label', '')}".strip()
                    lines.append(f"| {label} | {v.get('fileSystem', '?')} | "
                                 f"{v.get('encryption') or 'unknown'} |")
            if p.pii:
                lines += ["", "**Sensitive data (categories/counts only):** "
                          + ", ".join(f"{k}={v}" for k, v in sorted(p.pii.items()))]
            lines.append("")

    # detected technology + versions (fingerprint feeding CVE matching)
    if report.components:
        lines += ["## Technology & versions", "",
                  "| Component | Version | Host | Source | CVE-matchable |",
                  "| --- | --- | --- | --- | --- |"]
        for c in report.components:
            matchable = "yes" if c.get("canonical") else "no (name only)"
            lines.append(f"| {c.get('product', '?')} | {c.get('version', '?')} "
                         f"| {c.get('host', '')} | {c.get('source', '')} "
                         f"| {matchable} |")
        lines.append("")

    # discovered endpoints (crawl + passive archives), scope-gated
    if report.endpoints:
        shown = report.endpoints[:50]
        lines += [
            "## Discovered endpoints",
            "",
            f"Endpoint discovery (crawl + passive archives) enumerated "
            f"**{len(report.endpoints)}** in-scope URL(s). "
            "These form the attack surface the vulnerability stage tested"
            + (f"; the first {len(shown)} are listed below."
               if len(report.endpoints) > len(shown) else "."),
            "",
            "```",
            *shown,
            "```",
            "",
        ]

    # attack surface appendix
    lines += ["## Appendix: attack surface", ""]
    if surface:
        lines += ["| Asset | Detail |", "| --- | --- |"]
        for sf in surface:
            f = sf.finding
            asset = f.host + (f":{f.port}/{f.protocol}" if f.port else "")
            lines.append(f"| {asset} | {f.evidence or f.description} |")
    else:
        lines.append("_No services enumerated._")

    lines += ["", "---", "",
              "_Generated by Aegis. Scope and authorization enforced at scan time; "
              "see the Authorization section above._"]
    return "\n".join(lines)
