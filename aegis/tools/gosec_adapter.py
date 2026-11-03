"""Gosec adapter — Go static security analysis.

Runs `gosec` over a Go module (the Go parallel to Bandit for Python) and
normalizes each issue into a Finding with a `file:line` location. Gosec is an
external binary and must run from the module root, so the scan uses `cwd=path`
and the `./...` package pattern. A tree with no Go module is SKIPPED, not an error.
"""
from __future__ import annotations

import json
import os
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
}


class GosecAdapter:
    name = "gosec"
    binary = "gosec"

    def __init__(self, timeout: int = 900):
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, path: str, project: str) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status=ToolStatus.UNAVAILABLE,
                              message="gosec not on PATH (install securego/gosec)")
        cmd = [self.binary, "-fmt=json", "-quiet", "-no-fail", "./..."]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False, cwd=path)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))
        if not proc.stdout.strip():
            # No Go packages / not a module -> nothing to analyze, not a failure.
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no Go module found to scan",
                              duration_s=round(time.time() - started, 2))
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        findings = [self._finding(r, path, project) for r in data.get("Issues", [])]
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2),
                          message=f"{len(findings)} issue(s)")

    def _finding(self, r: dict, root: str, project: str) -> Finding:
        rel = _rel(r.get("file", ""), root)
        line = r.get("line", "")
        rule = r.get("rule_id", "")
        cwe = r.get("cwe") or {}
        refs = [cwe["url"]] if cwe.get("url") else []
        return Finding(
            title=r.get("details", "gosec issue")[:200],
            severity=_SEV.get(str(r.get("severity", "LOW")).upper(), Severity.LOW),
            source_tool=self.name,
            host=project,
            location=f"{rel}:{line}",
            description=f"{rule} (confidence: {r.get('confidence', '?')})".strip(),
            references=refs,
            evidence=(r.get("code") or "").strip()[:400],
            remediation="Review and fix the flagged Go code per the rule / CWE guidance.",
            tags=["sast", "go", rule],
            raw={"rule_id": rule, "cwe": cwe.get("id")},
        )


def _rel(filename: str, root: str) -> str:
    try:
        return os.path.relpath(filename, root).replace("\\", "/")
    except ValueError:
        return str(filename).replace("\\", "/")
