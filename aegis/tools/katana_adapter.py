"""Katana adapter: active crawler for endpoint/URL discovery.

Katana (ProjectDiscovery) spiders a live web app and enumerates its reachable
endpoints — pages, scripts, API paths, parameterized URLs — which become the
attack surface the vuln stage (nuclei) actually tests. Crawling is read-only
(GET-style navigation); it fetches pages, it does not submit or mutate data.

The adapter normalizes katana's JSONL into a deduped list of endpoint URLs
(stashed on the result as `.endpoints`) plus one INFO finding summarizing what
was discovered. Every discovered endpoint is scope-gated by the pipeline before
anything is scanned.
"""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus


class KatanaAdapter(Adapter):
    name = "katana"
    binary = "katana"

    def run(self, seeds, gate=None, host_header=None) -> ToolResult:
        if not self.available():
            return self._unavailable()

        seeds = [s for s in (seeds or []) if s]
        if not seeds:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no seed URLs to crawl")

        # -jsonl: structured output; -silent: no banner; -nc: no color.
        # Depth and concurrency kept conservative so crawling stays light.
        cmd = [self.binary, "-jsonl", "-silent", "-nc", "-d", "2"]
        if gate is not None and gate.engagement.scope.max_rate:
            cmd += ["-rl", str(gate.engagement.scope.max_rate)]
        if host_header:
            cmd += ["-H", f"Host: {host_header}"]
        cmd += self.extra_args

        started = time.time()
        try:
            import subprocess
            proc = subprocess.run(
                cmd, input="\n".join(seeds),
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=str(exc), command=" ".join(cmd))

        endpoints = self._parse(proc.stdout)
        findings: list[Finding] = []
        if endpoints:
            hosts = sorted({urlparse(u).netloc for u in endpoints if u})
            findings.append(
                Finding(
                    title=f"Crawled {len(endpoints)} endpoint(s) across "
                          f"{len(hosts)} host(s)",
                    severity=Severity.INFO,
                    source_tool=self.name,
                    host=hosts[0] if hosts else (host_header or ""),
                    description="Endpoints enumerated by crawling the live "
                                "application (read-only navigation).",
                    evidence="; ".join(endpoints[:15])
                    + (" ..." if len(endpoints) > 15 else ""),
                    tags=["web", "attack-surface", "endpoint", "discovery"],
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
    def _parse(jsonl: str) -> list[str]:
        """Pull endpoint URLs from katana JSONL (handles both output shapes)."""
        out: list[str] = []
        for line in jsonl.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # newer katana: {"timestamp":..,"request":{"endpoint":"..","method":..}}
            # older/-field url: {"endpoint":".."} or {"url":".."}
            url = ""
            req = rec.get("request")
            if isinstance(req, dict):
                url = req.get("endpoint") or req.get("url") or ""
            if not url:
                url = rec.get("endpoint") or rec.get("url") or ""
            if url.startswith(("http://", "https://")):
                out.append(url)
        # dedup, keep order stable
        seen: set[str] = set()
        deduped = []
        for u in out:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped
