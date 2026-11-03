"""Trivy adapter — dependency (SCA), IaC misconfiguration, and secret scanning.

One `trivy fs` pass over a source tree covers three classes at once:
  * Vulnerabilities  — known-vuln dependencies from lockfiles/manifests (SCA)
  * Misconfigurations — IaC / Dockerfile hardening issues
  * Secrets          — hardcoded credentials (the matched value is never stored)

Each is normalized into the shared Finding schema with a file(:line) location.
Trivy is an external binary; if it is not on PATH the SAST run skips it.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time

from ..models import Finding, Severity
from .base import ToolResult, ToolStatus

_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def _sev(label: str, default: Severity = Severity.INFO) -> Severity:
    return _SEV.get(str(label or "").upper(), default)


def _norm(target: str) -> str:
    return str(target or "").replace("\\", "/")


class TrivyAdapter:
    name = "trivy"
    binary = "trivy"

    def __init__(self, timeout: int = 1800):
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, path: str, project: str) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status=ToolStatus.UNAVAILABLE,
                              message="trivy not on PATH (install aquasecurity/trivy)")
        cmd = [self.binary, "fs", "--quiet", "--format", "json",
               "--scanners", "vuln,misconfig,secret", path]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))
        if not proc.stdout.strip():
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=proc.stderr.strip()[:200] or "no trivy output")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        findings = self._parse(data, path, project)
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2),
                          message=f"{len(findings)} finding(s)")

    # -- parsing (pure) ---------------------------------------------------- #
    def _parse(self, data: dict, root: str, project: str) -> list[Finding]:
        out: list[Finding] = []
        for res in data.get("Results") or []:
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities") or []:
                out.append(self._vuln_finding(v, target, root, project))
            for m in res.get("Misconfigurations") or []:
                out.append(self._misconfig_finding(m, target, root, project))
            for s in res.get("Secrets") or []:
                out.append(self._secret_finding(s, target, root, project))
        return out

    def _vuln_finding(self, v: dict, target: str, root: str, project: str) -> Finding:
        vid = v.get("VulnerabilityID", "")
        pkg = v.get("PkgName", "?")
        ver = v.get("InstalledVersion", "?")
        fixed = v.get("FixedVersion")
        cves = [vid] if vid.upper().startswith("CVE-") else []
        refs = v.get("References") or ([v["PrimaryURL"]] if v.get("PrimaryURL") else [])
        return Finding(
            title=f"Vulnerable dependency: {pkg} {ver} ({vid})",
            severity=_sev(v.get("Severity", "UNKNOWN")),
            source_tool=self.name,
            host=project,
            location=_norm(target),
            description=(v.get("Title") or v.get("Description") or "")[:300],
            cve=cves,
            references=refs[:5],
            evidence=f"{pkg} {ver}" + (f" (fixed in {fixed})" if fixed else ""),
            remediation=(f"Update {pkg} to {fixed}." if fixed
                         else "Update the dependency to a fixed version."),
            tags=["sast", "sca", "dependency", vid],
            raw={"vuln_id": vid, "pkg": pkg},
        )

    def _misconfig_finding(self, m: dict, target: str, root: str, project: str) -> Finding:
        mid = m.get("ID") or m.get("AVDID") or "misconfig"
        line = (m.get("CauseMetadata") or {}).get("StartLine")
        loc = f"{_norm(target)}:{line}" if line else _norm(target)
        refs = m.get("References") or ([m["PrimaryURL"]] if m.get("PrimaryURL") else [])
        return Finding(
            title=f"IaC misconfiguration: {m.get('Title', mid)}",
            severity=_sev(m.get("Severity", "UNKNOWN")),
            source_tool=self.name,
            host=project,
            location=loc,
            description=f"{mid}: {m.get('Message', '')}".strip()[:300],
            references=refs[:5],
            evidence=(m.get("Message") or "")[:400],
            remediation=m.get("Resolution") or "Apply the recommended secure configuration.",
            tags=["sast", "iac", "misconfig", mid],
            raw={"id": mid},
        )

    def _secret_finding(self, s: dict, target: str, root: str, project: str) -> Finding:
        rule = s.get("RuleID", "secret")
        line = s.get("StartLine", "")
        return Finding(
            title=f"Hardcoded secret: {s.get('Title', rule)}",
            severity=_sev(s.get("Severity", "HIGH"), Severity.HIGH),
            source_tool=self.name,
            host=project,
            location=f"{_norm(target)}:{line}",
            description="A secret matching a known pattern was found in the source. "
                        "The value is not included in this report.",
            evidence=f"rule: {rule}",   # never the matched secret itself
            remediation="Remove the secret from source, rotate it, and load it from a "
                        "secret manager / environment variable.",
            tags=["sast", "secret", rule],
            raw={"rule": rule},
        )
