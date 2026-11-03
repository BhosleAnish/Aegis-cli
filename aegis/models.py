"""Core data models shared across the whole pipeline.

Everything is a stdlib dataclass so the core has no runtime dependency beyond
PyYAML (used only for config loading). Every tool adapter normalizes its native
output into the `Finding` shape defined here, so correlation, scoring and
reporting never need to know which tool produced a result.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict, fields
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Ordered severity. `.rank` gives a sortable integer (higher = worse)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS base score (0.0-10.0) to a severity band (CVSS v3 bands)."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


@dataclass
class Service:
    """A network service discovered on a host."""

    host: str
    port: int
    protocol: str = "tcp"          # tcp | udp
    name: Optional[str] = None     # e.g. "http", "ssh"
    product: Optional[str] = None  # e.g. "nginx"
    version: Optional[str] = None
    state: str = "open"

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}/{self.protocol}"


@dataclass
class Finding:
    """A single normalized finding from any tool.

    `fingerprint` deterministically identifies the finding so the correlator
    can dedup results that different tools (or repeat runs) report for the same
    issue on the same asset.
    """

    title: str
    severity: Severity
    source_tool: str                       # which adapter produced this
    host: str
    port: Optional[int] = None
    protocol: str = "tcp"
    location: str = ""                      # code findings: "path/to/file:line"
    description: str = ""
    cve: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    references: list[str] = field(default_factory=list)
    evidence: str = ""                     # raw snippet backing the claim
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)  # original tool record
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def fingerprint(self) -> str:
        basis = "|".join(
            [
                self.host,
                self.location,
                str(self.port or ""),
                self.protocol,
                self.title.strip().lower(),
                ",".join(sorted(self.cve)),
            ]
        )
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        """Rebuild a Finding from a to_dict() record (e.g. an ingested
        findings.json). Unknown/derived keys (fingerprint, risk, confidence) are
        ignored so a scan can re-ingest a prior SAST run."""
        known = {f.name for f in fields(cls)}
        data = {k: v for k, v in d.items() if k in known}
        sev = data.get("severity", "info")
        data["severity"] = sev if isinstance(sev, Severity) else Severity(str(sev))
        return cls(**data)


@dataclass
class Credentials:
    """Runtime authentication for white/grey-box scanning. Never persisted to
    config or reports — supplied per run (CLI/env) and injected as HTTP headers
    so the scanners reach authenticated surface.
    """

    headers: list[str] = field(default_factory=list)  # raw "Name: value" lines
    cookie: str = ""                                   # Cookie header value
    basic: str = ""                                    # "user:pass" -> Basic auth

    def is_set(self) -> bool:
        return bool(self.headers or self.cookie or self.basic)

    def header_args(self) -> list[str]:
        """Expand to repeated `-H <header>` CLI args for httpx/nuclei/katana."""
        import base64

        out: list[str] = []
        for h in self.headers:
            out += ["-H", h]
        if self.cookie:
            out += ["-H", f"Cookie: {self.cookie}"]
        if self.basic:
            token = base64.b64encode(self.basic.encode()).decode()
            out += ["-H", f"Authorization: Basic {token}"]
        return out


@dataclass
class Authorization:
    """Proof that a scan is permitted. The gate refuses to run without a valid one.

    This is deliberately strict: an authorization that is unsigned, undated, or
    outside its validity window is treated as *no* authorization.
    """

    engagement: str            # engagement / project name
    client: str                # organization that owns the targets
    authorized_by: str         # named person who signed off (client side)
    contact_email: str
    valid_from: date
    valid_until: date
    signoff_reference: str     # ticket / contract / SoW reference
    rules_of_engagement: str = ""

    def is_active(self, on: Optional[date] = None) -> tuple[bool, str]:
        today = on or datetime.now(timezone.utc).date()
        if not self.signoff_reference.strip():
            return False, "authorization has no sign-off reference"
        if not self.authorized_by.strip():
            return False, "authorization has no named approver"
        if today < self.valid_from:
            return False, f"authorization not yet valid (starts {self.valid_from})"
        if today > self.valid_until:
            return False, f"authorization expired on {self.valid_until}"
        return True, "ok"


@dataclass
class Scope:
    """What is in bounds. Targets are matched against include minus exclude.

    Supports IPv4 addresses, CIDR ranges, and exact hostnames/domains. Anything
    not explicitly inside `include` (or explicitly in `exclude`) is out of scope
    and the gate will block it.
    """

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    allowed_ports: Optional[list[int]] = None   # None = any port in scope
    max_rate: Optional[int] = None               # packets/sec cap passed to tools
    notes: str = ""


@dataclass
class Engagement:
    """The full configuration for one run: scope + authorization bound together."""

    authorization: Authorization
    scope: Scope


@dataclass
class HostProfile:
    """Inventory of a single host, normalized from the MonitoringAgent collectors.

    Carries the descriptive facts (OS, hardware, security posture, software,
    optional PII-category summary) that the infra module turns into findings and
    the report renders as an asset profile.
    """

    hostname: str
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_build: Optional[str] = None
    architecture: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    secure_boot: Optional[bool] = None
    tpm_present: Optional[bool] = None
    tpm_enabled: Optional[bool] = None
    volumes: list[dict] = field(default_factory=list)   # {mount,label,encryption,...}
    software_count: int = 0
    software: list[dict] = field(default_factory=list)  # {name,version,publisher,...}
    pii: dict = field(default_factory=dict)             # {category: count}, metadata only
    posture: dict = field(default_factory=dict)         # endpoint security posture (ports, firewall, ...)
    source: str = "infra-agent"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
