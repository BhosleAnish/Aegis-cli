"""Adapter base class and shared subprocess plumbing.

Every adapter:
  * declares the external binary it needs,
  * reports availability (so the pipeline can skip gracefully),
  * runs the binary as a child process with a timeout,
  * normalizes native output into Service / Finding objects.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..models import Finding, Service


class ToolStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"   # binary not installed
    ERROR = "error"              # binary failed / timed out
    SKIPPED = "skipped"          # nothing to do


@dataclass
class ToolResult:
    tool: str
    status: ToolStatus
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    command: str = ""
    duration_s: float = 0.0


class Adapter:
    """Base adapter. Subclasses set `name`/`binary` and implement `run`."""

    name: str = "adapter"
    binary: str = ""

    def __init__(self, extra_args: Optional[list[str]] = None, timeout: int = 1800):
        self.extra_args = extra_args or []
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def run(self, targets, services=None, gate=None) -> ToolResult:  # pragma: no cover
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------- #
    def _unavailable(self) -> ToolResult:
        return ToolResult(
            tool=self.name,
            status=ToolStatus.UNAVAILABLE,
            message=f"'{self.binary}' not found on PATH — install it to enable {self.name}",
        )

    def _exec(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Run a command with a timeout. stdout/stderr captured as text."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )
