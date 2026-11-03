"""dalfox adapter: reflected / DOM XSS testing (non-destructive proof).

dalfox probes parameterized URLs with benign marker payloads and reports where
input is reflected into a response in an exploitable way. It is **active but
non-destructive** in the EICAR sense: it *proves* an XSS is possible with a safe
marker (it does not weaponize it, exfiltrate data, or alter server state). It is
gated behind `--intensity standard|aggressive`.

Only parameterized URLs (those with a query string) are worth testing; the
pipeline feeds dalfox the scope-gated endpoints that carry `?param=` values.
Output is dalfox's JSON PoC list, normalized into XSS findings that correlate
and risk-rate as actively-confirmed (high likelihood).
"""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from ..models import Finding, Severity
from .base import Adapter, ToolResult, ToolStatus

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class DalfoxAdapter(Adapter):
    name = "dalfox"
    binary = "dalfox"

    def run(self, urls, gate=None, host_header=None) -> ToolResult:
        if not self.available():
            return self._unavailable()
        # only parameterized URLs are testable for reflected XSS
        targets = [u for u in (urls or []) if "=" in (urlparse(u).query or "")]
        if not targets:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no parameterized URLs to test")

        cmd = [self.binary, "pipe", "--format", "json", "--silence", "--no-color"]
        if host_header:
            cmd += ["-H", f"Host: {host_header}"]
        if gate is not None and gate.engagement.scope.max_rate:
            # translate a packets/sec cap into a conservative worker count
            cmd += ["--worker", str(max(1, min(10, gate.engagement.scope.max_rate)))]
        cmd += self.extra_args

        started = time.time()
        try:
            import subprocess
            proc = subprocess.run(cmd, input="\n".join(targets),
                                  capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except Exception as exc:  # noqa: BLE001
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=str(exc), command=" ".join(cmd))

        findings = self._parse(proc.stdout)
        return ToolResult(tool=self.name, status=ToolStatus.OK, findings=findings,
                          duration_s=round(time.time() - started, 2))

    @staticmethod
    def _parse(json_text: str) -> list[Finding]:
        text = (json_text or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        items = data if isinstance(data, list) else data.get("pocs") or []
        findings: list[Finding] = []
        for p in items:
            url = p.get("data") or p.get("evidence") or ""
            host = urlparse(url).netloc if url.startswith("http") else ""
            sev = _SEV.get(str(p.get("severity", "high")).lower(), Severity.HIGH)
            param = p.get("param", "")
            cwe = p.get("cwe", "")
            tags = ["xss", "vuln", "active", "web"]
            if cwe:
                tags.append(cwe if cwe.upper().startswith("CWE") else f"CWE-{cwe}")
            findings.append(Finding(
                title=f"Reflected XSS via parameter '{param}'" if param
                      else "Reflected XSS",
                severity=sev,
                source_tool="dalfox",
                host=host,
                description=p.get("message_str")
                or "Input is reflected into the response and is exploitable as XSS.",
                evidence=url,
                remediation="Context-encode output and set a Content-Security-Policy; "
                            "validate/escape user input.",
                tags=tags,
                raw=p))
        return findings
