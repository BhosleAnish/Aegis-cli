"""Scope + authorization enforcement — the gate every active action passes.

The design principle for authorized engagements is *fail closed*: if scope or
authorization cannot be positively confirmed, the target is blocked. There is no
"scan everything" mode and no way to disable the gate from a scan command.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

from .models import Authorization, Engagement, Scope


class AuthorizationError(Exception):
    """Raised when authorization is missing, invalid, or expired."""


class OutOfScopeError(Exception):
    """Raised when a target is not within the authorized scope."""


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #
def load_engagement(scope_path: str | Path, auth_path: str | Path) -> Engagement:
    """Load and validate scope + authorization from YAML into an Engagement."""
    scope = _load_scope(scope_path)
    auth = _load_authorization(auth_path)
    return Engagement(authorization=auth, scope=scope)


def _load_scope(path: str | Path) -> Scope:
    data = _read_yaml(path, "scope")
    include = [str(x).strip() for x in data.get("include", []) if str(x).strip()]
    if not include:
        raise ValueError(f"scope file {path} has an empty 'include' list")
    ports = data.get("allowed_ports")
    return Scope(
        include=include,
        exclude=[str(x).strip() for x in data.get("exclude", []) if str(x).strip()],
        allowed_ports=[int(p) for p in ports] if ports else None,
        max_rate=int(data["max_rate"]) if data.get("max_rate") else None,
        notes=str(data.get("notes", "")),
    )


def _load_authorization(path: str | Path) -> Authorization:
    data = _read_yaml(path, "authorization")
    required = [
        "engagement",
        "client",
        "authorized_by",
        "contact_email",
        "valid_from",
        "valid_until",
        "signoff_reference",
    ]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing:
        raise AuthorizationError(
            f"authorization file {path} missing required fields: {', '.join(missing)}"
        )
    return Authorization(
        engagement=str(data["engagement"]),
        client=str(data["client"]),
        authorized_by=str(data["authorized_by"]),
        contact_email=str(data["contact_email"]),
        valid_from=_as_date(data["valid_from"]),
        valid_until=_as_date(data["valid_until"]),
        signoff_reference=str(data["signoff_reference"]),
        rules_of_engagement=str(data.get("rules_of_engagement", "")),
    )


def _read_yaml(path: str | Path, label: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{label} file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{label} file {p} must contain a YAML mapping")
    return data


def _as_date(value) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #
@dataclass
class ScopeDecision:
    target: str
    allowed: bool
    reason: str


class ScopeGate:
    """Validates targets against an Engagement. Fails closed.

    Usage::

        gate = ScopeGate(engagement)
        gate.assert_authorized()          # once, before the pipeline starts
        targets = gate.filter(candidate_targets)   # drops out-of-scope, logs why
    """

    def __init__(self, engagement: Engagement, today: Optional[date] = None):
        self.engagement = engagement
        self._today = today
        self._include = [self._parse(t) for t in engagement.scope.include]
        self._exclude = [self._parse(t) for t in engagement.scope.exclude]
        self.audit: list[ScopeDecision] = []

    # -- authorization ----------------------------------------------------- #
    def assert_authorized(self) -> None:
        active, reason = self.engagement.authorization.is_active(self._today)
        if not active:
            raise AuthorizationError(f"refusing to scan: {reason}")

    # -- scope ------------------------------------------------------------- #
    def is_in_scope(self, target: str) -> ScopeDecision:
        target = target.strip()
        parsed = self._parse(target)

        for exc_raw, exc in zip(self.engagement.scope.exclude, self._exclude):
            if self._matches(parsed, exc):
                return self._record(target, False, f"explicitly excluded by '{exc_raw}'")

        for inc_raw, inc in zip(self.engagement.scope.include, self._include):
            if self._matches(parsed, inc):
                return self._record(target, True, f"in scope via '{inc_raw}'")

        return self._record(target, False, "not listed in scope include")

    def filter(self, targets: list[str]) -> list[str]:
        """Return only in-scope targets; every decision is appended to the audit log."""
        return [t for t in targets if self.is_in_scope(t).allowed]

    def assert_in_scope(self, target: str) -> None:
        decision = self.is_in_scope(target)
        if not decision.allowed:
            raise OutOfScopeError(f"{target}: {decision.reason}")

    def port_allowed(self, port: int) -> bool:
        allowed = self.engagement.scope.allowed_ports
        return allowed is None or port in allowed

    # -- internals --------------------------------------------------------- #
    def _record(self, target: str, allowed: bool, reason: str) -> ScopeDecision:
        decision = ScopeDecision(target=target, allowed=allowed, reason=reason)
        self.audit.append(decision)
        return decision

    @staticmethod
    def _parse(entry: str):
        """Parse a scope entry or target into a comparable form.

        Returns an ip_network for addresses/CIDRs, or a lowercased hostname str.
        """
        entry = entry.strip().lower()
        # strip a :port if present on a bare host:port target
        host = entry.split("/")[0]
        try:
            if "/" in entry:   # CIDR
                return ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_network(host, strict=False)  # single address -> /32
        except ValueError:
            return host  # hostname / domain

    @staticmethod
    def _matches(target, rule) -> bool:
        # both IP-based: subnet containment
        if isinstance(target, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and isinstance(
            rule, (ipaddress.IPv4Network, ipaddress.IPv6Network)
        ):
            return target.version == rule.version and target.subnet_of(rule)
        # both hostname-based: exact or domain suffix match
        if isinstance(target, str) and isinstance(rule, str):
            return target == rule or target.endswith("." + rule)
        return False
