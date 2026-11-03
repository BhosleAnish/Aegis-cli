"""Gitleaks adapter — hardcoded-secret detection.

Scans a directory tree for committed secrets (API keys, tokens, credentials).
The matched secret value itself is NEVER stored or reported — only the rule, the
file and the line — so the finding is safe to put in a report or share.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..models import Finding, Severity
from .base import ToolResult, ToolStatus


class GitleaksAdapter:
    name = "gitleaks"
    binary = "gitleaks"

    def __init__(self, timeout: int = 900):
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, path: str, project: str) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status=ToolStatus.UNAVAILABLE,
                              message="gitleaks not on PATH (install Gitleaks.Gitleaks)")
        tmp = Path(tempfile.mkdtemp()) / "gitleaks.json"
        cmd = [self.binary, "dir", path, "--report-format", "json",
               "--report-path", str(tmp), "--exit-code", "0", "--no-banner"]
        started = time.time()
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        if not tmp.exists():
            return ToolResult(tool=self.name, status=ToolStatus.OK, findings=[],
                              message="no report produced (0 leaks)",
                              duration_s=round(time.time() - started, 2))
        try:
            data = json.loads(tmp.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        findings = [self._finding(r, project) for r in data]
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2),
                          message=f"{len(findings)} secret(s)")

    def _finding(self, r: dict, project: str) -> Finding:
        rule = r.get("RuleID", "secret")
        file = str(r.get("File", "")).replace("\\", "/")
        line = r.get("StartLine", "")
        return Finding(
            title=f"Hardcoded secret: {r.get('Description', rule)}",
            severity=Severity.HIGH,
            source_tool=self.name,
            host=project,
            location=f"{file}:{line}",
            description="A secret matching a known pattern was found in the source. "
                        "The value is not included in this report.",
            evidence=f"rule: {rule}",   # never the secret itself
            remediation="Remove the secret from source, rotate it, and load it from a "
                        "secret manager / environment variable.",
            tags=["sast", "secret", rule],
            raw={"rule": rule},
        )
