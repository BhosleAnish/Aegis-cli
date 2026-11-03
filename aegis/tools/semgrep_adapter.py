"""Semgrep adapter — multi-language static analysis.

Runs semgrep with a security ruleset and normalizes matches into Findings with a
`file:line` location, CWE/OWASP metadata and references. Semgrep is not supported
on native Windows (use WSL/Linux/CI); the adapter reports unavailable there and
the SAST run continues with the other tools.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

from ..models import Finding, Severity
from .base import ToolResult, ToolStatus

# semgrep severities -> ours
_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


class SemgrepAdapter:
    name = "semgrep"
    binary = "semgrep"

    def __init__(self, config: str = "auto", timeout: int = 1800):
        self.config = config
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, path: str, project: str) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status=ToolStatus.UNAVAILABLE,
                              message="semgrep not on PATH (unsupported on native Windows)")
        cmd = [self.binary, "--json", "--quiet", "--disable-version-check",
               "--config", self.config, path]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))
        if not proc.stdout.strip():
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=proc.stderr.strip()[:200] or "no semgrep output")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        findings = [self._finding(r, path, project) for r in data.get("results", [])]
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2),
                          message=f"{len(findings)} finding(s)")

    def _finding(self, r: dict, root: str, project: str) -> Finding:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        rel = _rel(r.get("path", ""), root)
        line = (r.get("start") or {}).get("line", "")
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        return Finding(
            title=extra.get("message", r.get("check_id", "semgrep finding"))[:200],
            severity=_SEV.get(str(extra.get("severity", "INFO")).upper(), Severity.LOW),
            source_tool=self.name,
            host=project,
            location=f"{rel}:{line}",
            description=f"{r.get('check_id', '')}"
                        + (f" | OWASP: {meta.get('owasp')}" if meta.get("owasp") else ""),
            references=(meta.get("references") or [])[:5],
            evidence=(extra.get("lines") or "").strip()[:400],
            remediation=extra.get("fix") or "Review and remediate per the rule guidance.",
            tags=["sast"] + [str(c) for c in cwe][:3],
            raw={"check_id": r.get("check_id")},
        )


def _rel(filename: str, root: str) -> str:
    try:
        return os.path.relpath(filename, root).replace("\\", "/")
    except ValueError:
        return filename.replace("\\", "/")
