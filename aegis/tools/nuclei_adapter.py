"""Nuclei adapter: template-based vulnerability matching.

Feeds discovered URLs (from httpx) or raw targets into nuclei with JSONL output
and normalizes each match into a Finding, mapping nuclei's severity strings onto
our Severity enum and carrying through CVE / CVSS metadata when present.
"""
from __future__ import annotations

import json
import time

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


class NucleiAdapter(Adapter):
    name = "nuclei"
    binary = "nuclei"

    def run(self, targets, services=None, gate=None, urls=None) -> ToolResult:
        if not self.available():
            return self._unavailable()

        scan_targets = urls or list(targets)
        if not scan_targets:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no targets/urls for nuclei")

        cmd = [self.binary, "-jsonl", "-silent", "-no-color"]
        if gate is not None and gate.engagement.scope.max_rate:
            cmd += ["-rate-limit", str(gate.engagement.scope.max_rate)]
        cmd += self.extra_args

        started = time.time()
        try:
            import subprocess
            proc = subprocess.run(
                cmd, input="\n".join(scan_targets),
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=str(exc), command=" ".join(cmd))

        findings = self._parse(proc.stdout)
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            findings=findings,
            command=" ".join(cmd),
            duration_s=round(time.time() - started, 2),
        )

    def _parse(self, jsonl: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in jsonl.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = rec.get("info", {})
            classification = info.get("classification", {}) or {}
            cves = classification.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            cvss = classification.get("cvss-score")

            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            if cvss:
                # trust an explicit CVSS band over the template's label if higher
                sev = max(sev, Severity.from_cvss(float(cvss)), key=lambda s: s.rank)

            host = rec.get("host") or rec.get("ip") or rec.get("matched-at", "")
            findings.append(
                Finding(
                    title=info.get("name", rec.get("template-id", "nuclei match")),
                    severity=sev,
                    source_tool=self.name,
                    host=host,
                    port=rec.get("port"),
                    description=info.get("description", ""),
                    cve=list(cves),
                    cvss=float(cvss) if cvss else None,
                    references=info.get("reference") or [],
                    evidence=rec.get("matched-at", ""),
                    remediation=info.get("remediation", ""),
                    tags=(info.get("tags") or []) + ["vuln"],
                    raw=rec,
                )
            )
        return findings
