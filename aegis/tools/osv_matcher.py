"""Software -> known-vulnerability matching via the OSV.dev API.

Takes the installed-software inventory (from the infra module) and asks OSV
(https://osv.dev) which packages+versions have known vulnerabilities, then
normalizes each advisory into a Finding with CVE ids and a CVSS-derived severity.

Scope/coverage, stated honestly:
  * Works where a package maps to an OSV ecosystem: Debian, Ubuntu, Alpine
    (resolved from the host OS + the collector's `source`), or an explicit
    `ecosystem` field on an inventory item.
  * Windows desktop apps have no package ecosystem in OSV, so they are reported
    as "unmatchable" rather than silently passing. CPE/NVD matching for those is
    a separate, later source.

Privacy: this sends package NAMES and VERSIONS (not file contents or data) to a
third party, api.osv.dev. It is therefore opt-in at the CLI (`--cve`).
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from ..data.cvss import base_score
from ..models import Finding, Severity

OSV_API = "https://api.osv.dev"

# OSV ecosystems we resolve confidently. Conservative on purpose: a wrong
# ecosystem yields wrong matches, so unknowns are left unmatched.
_LINUX_ECOSYSTEM = [
    ("ubuntu", "Ubuntu"),
    ("debian", "Debian"),
    ("alpine", "Alpine"),
]
_LINUX_SOURCES = {"dpkg", "deb", "apt", "apk"}

_LABEL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OSVUnavailable(Exception):
    """Raised when the OSV API cannot be reached."""


@dataclass
class MatchStats:
    total: int = 0
    queried: int = 0            # had a resolvable ecosystem + version
    unmatchable: int = 0        # no ecosystem (e.g. Windows desktop apps)
    vulnerable: int = 0         # packages with >= 1 advisory
    advisories: int = 0


def resolve_ecosystem(os_name: Optional[str], source: Optional[str],
                      explicit: Optional[str] = None) -> Optional[str]:
    """Map a software item to an OSV ecosystem, or None if not confidently known."""
    if explicit:
        return explicit
    src = (source or "").lower()
    # Linux package managers -> distro ecosystem from the OS caption.
    if src in _LINUX_SOURCES:
        name = (os_name or "").lower()
        for needle, eco in _LINUX_ECOSYSTEM:
            if needle in name:
                return eco
    return None


def _severity_from_vuln(vuln: dict) -> tuple[Optional[float], Severity]:
    """Return (cvss_score|None, Severity) from an OSV advisory."""
    for sev in vuln.get("severity", []) or []:
        if str(sev.get("type", "")).upper().startswith("CVSS_V3"):
            score = base_score(sev.get("score", ""))
            if score is not None:
                return score, Severity.from_cvss(score)
    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if label in _LABEL_SEVERITY:
        return None, _LABEL_SEVERITY[label]
    # A confirmed-known vuln with no score is not informational.
    return None, Severity.MEDIUM


def _fixed_versions(vuln: dict) -> list[str]:
    out: list[str] = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    out.append(str(ev["fixed"]))
    return sorted(set(out))


def parse_vuln(vuln: dict, app: dict, ecosystem: str, host: str) -> Finding:
    """Normalize one OSV advisory for one package into a Finding (pure, testable)."""
    vid = vuln.get("id", "OSV")
    aliases = vuln.get("aliases", []) or []
    cves = [a for a in aliases if a.upper().startswith("CVE-")]
    primary = cves[0] if cves else vid
    cvss, severity = _severity_from_vuln(vuln)
    fixed = _fixed_versions(vuln)
    name = app.get("name", "?")
    version = app.get("version") or "?"

    remediation = "Update to a fixed version."
    if fixed:
        remediation = f"Update to a fixed version ({', '.join(fixed[:5])})."

    summary = vuln.get("summary") or (vuln.get("details") or "")[:300]
    return Finding(
        title=f"Vulnerable software: {name} {version} ({primary})",
        severity=severity,
        source_tool="osv",
        host=host,
        description=summary,
        cve=cves,
        cvss=cvss,
        references=[r.get("url") for r in (vuln.get("references") or []) if r.get("url")][:5],
        evidence=f"{ecosystem}: {name} {version}  [{vid}]",
        remediation=remediation,
        tags=["cve", "software", "sca", "infra"],
        raw={"osv_id": vid},
    )


class OSVMatcher:
    def __init__(self, timeout: int = 20, api_base: str = OSV_API,
                 max_queries: int = 1000, max_detail_fetch: int = 300):
        self.timeout = timeout
        self.api_base = api_base.rstrip("/")
        self.max_queries = max_queries
        self.max_detail_fetch = max_detail_fetch

    # -- HTTP (overridable in tests) -------------------------------------- #
    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.api_base + path,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(self.api_base + path, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    # -- matching --------------------------------------------------------- #
    def match(self, software: list[dict], os_name: Optional[str],
              host: str) -> tuple[list[Finding], MatchStats]:
        stats = MatchStats(total=len(software))
        queries: list[dict] = []
        q_apps: list[tuple[dict, str]] = []  # aligned with queries

        for app in software:
            version = app.get("version")
            eco = resolve_ecosystem(os_name, app.get("source"), app.get("ecosystem"))
            if not eco or not version:
                stats.unmatchable += 1
                continue
            queries.append({"package": {"name": app["name"], "ecosystem": eco},
                            "version": str(version)})
            q_apps.append((app, eco))
            if len(queries) >= self.max_queries:
                break
        stats.queried = len(queries)
        if not queries:
            return [], stats

        try:
            resp = self._post("/v1/querybatch", {"queries": queries})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise OSVUnavailable(str(exc)) from exc

        results = resp.get("results", [])
        findings: list[Finding] = []
        detail_cache: dict[str, dict] = {}
        fetched = 0

        for (app, eco), result in zip(q_apps, results):
            vulns = (result or {}).get("vulns") or []
            if not vulns:
                continue
            stats.vulnerable += 1
            for v in vulns:
                vid = v.get("id")
                if not vid:
                    continue
                if vid not in detail_cache:
                    if fetched >= self.max_detail_fetch:
                        detail_cache[vid] = v  # fall back to the stub (id only)
                    else:
                        try:
                            detail_cache[vid] = self._get(f"/v1/vulns/{vid}")
                            fetched += 1
                        except (urllib.error.URLError, OSError, ValueError):
                            detail_cache[vid] = v
                findings.append(parse_vuln(detail_cache[vid], app, eco, host))
                stats.advisories += 1
        return findings, stats
