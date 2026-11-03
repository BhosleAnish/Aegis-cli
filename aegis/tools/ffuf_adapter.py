"""ffuf adapter: content discovery (directory/file brute-force).

ffuf requests candidate paths from a wordlist against a live root and reports
which exist. It is **active but non-destructive** — plain GET requests for paths
that may or may not be there, the same traffic a browser makes; it never submits
or mutates data. Because it generates real traffic it is gated behind
`--intensity standard|aggressive` (off by default).

Output is parsed from ffuf's JSON report: discovered URLs become attack-surface
endpoints (scope-gated by the pipeline, then scannable) plus a summary finding.
A wordlist is required; without one the stage is skipped.
"""
from __future__ import annotations

import json
import os
import tempfile
import time

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus

# Codes that indicate a path exists (incl. protected ones worth noting).
_MATCH_CODES = "200,204,301,302,307,401,403,405"


class FfufAdapter(Adapter):
    name = "ffuf"
    binary = "ffuf"

    def run(self, roots, wordlist=None, gate=None, host_header=None) -> ToolResult:
        if not self.available():
            return self._unavailable()
        roots = [r for r in (roots or []) if r]
        if not roots:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no live roots to fuzz")
        if not wordlist or not os.path.isfile(wordlist):
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no wordlist provided (--wordlist) — skipping")

        all_results: list[dict] = []
        endpoints: list[str] = []
        started = time.time()
        for root in roots:
            target = root.rstrip("/") + "/FUZZ"
            tmp = tempfile.NamedTemporaryFile(
                prefix="aegis-ffuf-", suffix=".json", delete=False)
            tmp.close()
            cmd = [self.binary, "-u", target, "-w", wordlist,
                   "-of", "json", "-o", tmp.name, "-s", "-mc", _MATCH_CODES]
            if gate is not None and gate.engagement.scope.max_rate:
                cmd += ["-rate", str(gate.engagement.scope.max_rate)]
            if host_header:
                cmd += ["-H", f"Host: {host_header}"]
            cmd += self.extra_args
            try:
                import subprocess
                subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout, check=False)
                with open(tmp.name, "r", encoding="utf-8") as fh:
                    results, urls = self._parse(fh.read())
            except Exception as exc:  # noqa: BLE001
                return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                                  message=str(exc), command=" ".join(cmd))
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
            all_results += results
            endpoints += urls

        findings: list[Finding] = []
        if endpoints:
            findings.append(Finding(
                title=f"Content discovery: {len(endpoints)} path(s) found",
                severity=Severity.INFO, source_tool=self.name,
                host=roots[0],
                description="Paths confirmed present by wordlist brute-force "
                            "(non-destructive GET requests).",
                evidence="; ".join(endpoints[:15])
                + (" ..." if len(endpoints) > 15 else ""),
                tags=["web", "attack-surface", "content-discovery", "active"]))

        result = ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                            duration_s=round(time.time() - started, 2))
        result.endpoints = endpoints  # type: ignore[attr-defined]
        return result

    @staticmethod
    def _parse(json_text: str) -> tuple[list[dict], list[str]]:
        try:
            data = json.loads(json_text or "{}")
        except json.JSONDecodeError:
            return [], []
        results = data.get("results") or []
        urls: list[str] = []
        seen: set[str] = set()
        for r in results:
            url = r.get("url", "")
            if url.startswith(("http://", "https://")) and url not in seen:
                seen.add(url)
                urls.append(url)
        return results, urls
