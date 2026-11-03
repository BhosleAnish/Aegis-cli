"""gau adapter: passive URL discovery from public archives.

gau ("get all urls") pulls URLs a host is already known to expose from public
datasets — the Wayback Machine, Common Crawl, Open Threat Exchange, URLScan.
It sends NO traffic to the target: it queries third-party archives by hostname,
so it surfaces historical and hidden endpoints (old admin paths, API routes,
parameterized URLs) without touching the client's systems.

Because the archives are keyed by hostname, gau is driven by the scope
hostnames (not raw IPs). Output is one URL per line (plain text). The pipeline
scope-gates every URL before any of them is handed to an active scanner.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus


class GauAdapter(Adapter):
    name = "gau"
    binary = "gau"

    def run(self, hostnames, gate=None) -> ToolResult:
        if not self.available():
            return self._unavailable()

        hosts = [h for h in (hostnames or []) if h]
        if not hosts:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no hostnames for passive URL discovery")

        # gau reads domains from stdin; --threads bounded; --subs off by default
        # so results stay within the exact hosts we pass (scope stays tight).
        cmd = [self.binary, "--threads", "5"]
        cmd += self.extra_args

        started = time.time()
        try:
            import subprocess
            proc = subprocess.run(
                cmd, input="\n".join(hosts),
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=str(exc), command=" ".join(cmd))

        endpoints = self._parse(proc.stdout)
        findings: list[Finding] = []
        if endpoints:
            found_hosts = sorted({urlparse(u).netloc for u in endpoints if u})
            findings.append(
                Finding(
                    title=f"Discovered {len(endpoints)} archived URL(s) for "
                          f"{len(found_hosts)} host(s)",
                    severity=Severity.INFO,
                    source_tool=self.name,
                    host=found_hosts[0] if found_hosts else hosts[0],
                    description="URLs known to public archives (Wayback, Common "
                                "Crawl, OTX, URLScan). No traffic sent to the target.",
                    evidence="; ".join(endpoints[:15])
                    + (" ..." if len(endpoints) > 15 else ""),
                    tags=["web", "attack-surface", "endpoint", "discovery", "passive"],
                )
            )

        result = ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            findings=findings,
            command=" ".join(cmd),
            duration_s=round(time.time() - started, 2),
        )
        result.endpoints = endpoints  # type: ignore[attr-defined]
        return result

    @staticmethod
    def _parse(text: str) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for line in text.splitlines():
            url = line.strip()
            if url.startswith(("http://", "https://")) and url not in seen:
                seen.add(url)
                out.append(url)
        return out
