"""Nmap adapter: host discovery + port/service/version detection.

Runs nmap with XML output to stdout (`-oX -`) and parses it into Service
objects. Open ports are also surfaced as INFO findings so they appear in the
report's attack surface section.
"""
from __future__ import annotations

import time

try:
    # defusedxml guards against XXE and billion-laughs entity-expansion attacks.
    import defusedxml.ElementTree as ET
    from defusedxml.common import DefusedXmlException
    _XML_ERRORS: tuple = (ET.ParseError, DefusedXmlException)
except ImportError:  # pragma: no cover - defusedxml is a declared dependency
    import xml.etree.ElementTree as ET  # type: ignore
    _XML_ERRORS = (ET.ParseError,)

from ..models import Finding, Service, Severity
from .base import Adapter, ToolResult, ToolStatus


class NmapAdapter(Adapter):
    name = "nmap"
    binary = "nmap"

    def __init__(self, extra_args=None, timeout=1800, service_detection=True,
                 retries=1, retry_backoff=3.0):
        super().__init__(extra_args, timeout)
        self.service_detection = service_detection
        # An nmap run can exit 0 with valid XML yet zero open ports when the
        # host transiently drops or rate-limits the probes (observed against a
        # cloud origin). Re-running usually recovers the real ports, so an empty
        # result — no output, a parse failure, or 0 open ports — is retried a
        # bounded number of times. A host that is genuinely closed just costs
        # one extra scan.
        self.retries = max(0, retries)
        self.retry_backoff = max(0.0, retry_backoff)

    def run(self, targets, services=None, gate=None) -> ToolResult:
        if not self.available():
            return self._unavailable()
        if not targets:
            return ToolResult(tool=self.name, status=ToolStatus.SKIPPED,
                              message="no in-scope targets")

        cmd = [self.binary, "-oX", "-", "-Pn"]
        if self.service_detection:
            cmd += ["-sV"]
        if gate is not None and gate.engagement.scope.max_rate:
            cmd += ["--max-rate", str(gate.engagement.scope.max_rate)]
        if gate is not None and gate.engagement.scope.allowed_ports:
            ports = ",".join(str(p) for p in gate.engagement.scope.allowed_ports)
            cmd += ["-p", ports]
        cmd += self.extra_args
        cmd += list(targets)

        started = time.time()
        attempts = self.retries + 1
        last_error = ""
        for attempt in range(1, attempts + 1):
            last_error = ""  # only the final attempt's outcome decides the status
            try:
                proc = self._exec(cmd)
            except Exception as exc:  # noqa: BLE001 - any exec failure is retryable
                last_error = str(exc)
                services, findings = [], []
            else:
                if proc.stdout.strip():
                    try:
                        services, findings = self._parse(proc.stdout)
                    except ValueError as exc:
                        last_error = str(exc)
                        services, findings = [], []
                else:
                    last_error = proc.stderr.strip() or "nmap produced no output"
                    services, findings = [], []

            if services:
                message = (f"recovered {len(services)} open port(s) on attempt "
                           f"{attempt}") if attempt > 1 else ""
                return ToolResult(
                    tool=self.name,
                    status=ToolStatus.OK,
                    services=services,
                    findings=findings,
                    command=" ".join(cmd),
                    duration_s=round(time.time() - started, 2),
                    message=message,
                )
            if attempt < attempts and self.retry_backoff:
                time.sleep(self.retry_backoff)

        # Exhausted retries with nothing open. A clean parse (no output/parse
        # error cleared last_error only on failure) with zero ports is a valid
        # OK result; a genuine failure is surfaced as ERROR.
        if last_error:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR,
                              message=last_error, command=" ".join(cmd))
        return ToolResult(
            tool=self.name,
            status=ToolStatus.OK,
            services=[],
            findings=[],
            command=" ".join(cmd),
            duration_s=round(time.time() - started, 2),
            message=f"no open ports after {attempts} attempt(s)"
                    if attempts > 1 else "",
        )

    def _parse(self, xml_text: str):
        services: list[Service] = []
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_text)
        except _XML_ERRORS as exc:
            # return nothing but let caller see we tried; parse errors are rare
            raise ValueError(f"could not parse nmap XML: {exc}") from exc

        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            host_addr = addr_el.get("addr", "")
            for port in host.findall("./ports/port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portid = int(port.get("portid", "0"))
                proto = port.get("protocol", "tcp")
                svc_el = port.find("service")
                svc = Service(
                    host=host_addr,
                    port=portid,
                    protocol=proto,
                    name=svc_el.get("name") if svc_el is not None else None,
                    product=svc_el.get("product") if svc_el is not None else None,
                    version=svc_el.get("version") if svc_el is not None else None,
                )
                services.append(svc)

                descr = f"Open {proto} port {portid}"
                if svc.product:
                    descr += f" running {svc.product}"
                    if svc.version:
                        descr += f" {svc.version}"
                findings.append(
                    Finding(
                        title=f"Open port {portid}/{proto}"
                        + (f" ({svc.name})" if svc.name else ""),
                        severity=Severity.INFO,
                        source_tool=self.name,
                        host=host_addr,
                        port=portid,
                        protocol=proto,
                        description=descr,
                        evidence=f"{svc.name or '?'} {svc.product or ''} {svc.version or ''}".strip(),
                        tags=["attack-surface"],
                        raw={"service": svc.__dict__},
                    )
                )
        return services, findings
