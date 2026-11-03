"""Bandit adapter — Python static security analysis.

Runs bandit via the current interpreter (`python -m bandit`) so it needs no PATH
entry, just the installed package. Normalizes each result into a Finding with a
`file:line` location.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

from ..models import Finding, Severity
from .base import ToolResult, ToolStatus

_SEV = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
_EXCLUDE = ".venv,venv,node_modules,.git,build,dist,.tox"


class BanditAdapter:
    name = "bandit"

    def __init__(self, timeout: int = 900):
        self.timeout = timeout

    def available(self) -> bool:
        try:
            import bandit  # noqa: F401
            return True
        except ImportError:
            return False

    def scan(self, path: str, project: str) -> ToolResult:
        if not self.available():
            return ToolResult(tool=self.name, status=ToolStatus.UNAVAILABLE,
                              message="bandit not installed (pip install bandit)")
        cmd = [sys.executable, "-m", "bandit", "-r", path, "-f", "json", "-q",
               "--exclude", _EXCLUDE]
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))
        if not proc.stdout.strip():
            # bandit prints JSON even with no issues; empty means a run error
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=proc.stderr.strip()[:200] or "no bandit output")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))

        findings = [self._finding(r, path, project) for r in data.get("results", [])]
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2),
                          message=f"{len(findings)} issue(s)")

    def _finding(self, r: dict, root: str, project: str) -> Finding:
        rel = _rel(r.get("filename", ""), root)
        line = r.get("line_number", "")
        return Finding(
            title=r.get("issue_text", r.get("test_name", "bandit issue")),
            severity=_SEV.get(str(r.get("issue_severity", "LOW")).upper(), Severity.LOW),
            source_tool=self.name,
            host=project,
            location=f"{rel}:{line}",
            description=f"{r.get('test_id', '')} {r.get('test_name', '')} "
                        f"(confidence: {r.get('issue_confidence', '?')})".strip(),
            references=[r["more_info"]] if r.get("more_info") else [],
            evidence=(r.get("code") or "").strip()[:400],
            remediation="Review and fix the flagged code per the linked guidance.",
            tags=["sast", "python", str(r.get("test_id", ""))],
            raw={"test_id": r.get("test_id")},
        )


def _rel(filename: str, root: str) -> str:
    try:
        return os.path.relpath(filename, root).replace("\\", "/")
    except ValueError:
        return filename.replace("\\", "/")
