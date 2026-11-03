"""httpx adapter: probe discovered services for live HTTP(S) endpoints.

Takes the services found by nmap, builds host:port candidates, and asks httpx
(ProjectDiscovery) which speak HTTP. The resulting URLs feed the nuclei web
templates. Emits INFO findings capturing server banners / tech where available.
"""
from __future__ import annotations

import json
import time

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus


class HttpxAdapter(Adapter):
    name = "httpx"
    binary = "httpx"

    def run(self, targets, services=None, gate=None) -> ToolResult:
        if not self.available():
            return self._unavailable()

        candidates = self._candidates(targets, services)
        if not candidates:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no HTTP-like services to probe")

        cmd = [self.binary, "-json", "-silent", "-no-color",
               "-tech-detect", "-status-code", "-title"]
        cmd += self.extra_args
        started = time.time()
        try:
            proc = subprocess_input(self, cmd, "\n".join(candidates))
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=str(exc), command=" ".join(cmd))

        findings: list[Finding] = []
        urls: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = rec.get("url") or rec.get("input", "")
            if url:
                urls.append(url)
            host = rec.get("host") or rec.get("input", "")
            tech = rec.get("tech") or rec.get("technologies") or []
            findings.append(
                Finding(
                    title=f"Live HTTP endpoint: {url}",
                    severity=Severity.INFO,
                    source_tool=self.name,
                    host=host,
                    port=rec.get("port"),
                    description=f"HTTP {rec.get('status_code', '?')} "
                    f"{rec.get('title', '')}".strip(),
                    evidence=", ".join(tech) if isinstance(tech, list) else str(tech),
                    tags=["web", "attack-surface"],
                    raw=rec,
                )
            )

        result = ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            findings=findings,
            command=" ".join(cmd),
            duration_s=round(time.time() - started, 2),
        )
        # stash discovered URLs for the nuclei stage
        result.urls = urls  # type: ignore[attr-defined]
        return result

    @staticmethod
    def _candidates(targets, services):
        out: list[str] = []
        http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        if services:
            for svc in services:
                name = (svc.name or "").lower()
                if "http" in name or svc.port in http_ports:
                    scheme = "https" if ("https" in name or svc.port in {443, 8443}) else "http"
                    out.append(f"{scheme}://{svc.host}:{svc.port}")
        if not out:
            out = list(targets)
        return sorted(set(out))


def subprocess_input(adapter: Adapter, cmd, stdin_text: str):
    """Run a command feeding stdin_text to the process stdin."""
    import subprocess
    return subprocess.run(
        cmd, input=stdin_text, capture_output=True, text=True,
        timeout=adapter.timeout, check=False,
    )
