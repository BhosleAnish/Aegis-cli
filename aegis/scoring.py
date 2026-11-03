"""Correlation, de-duplication and risk scoring.

Different tools frequently report the same underlying issue (nmap sees an open
port, httpx confirms it's HTTP, nuclei flags a CVE on it). The correlator merges
findings by fingerprint, keeping the richest record and recording corroboration
(a finding confirmed by two tools is higher-confidence).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding, Severity


@dataclass
class ScoredFinding:
    finding: Finding
    confidence: str            # "confirmed" (multi-tool) | "single"
    corroborated_by: list[str] = field(default_factory=list)


def correlate(findings: list[Finding]) -> list[ScoredFinding]:
    """Merge findings by fingerprint; track which tools corroborate each."""
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(f.fingerprint, []).append(f)

    scored: list[ScoredFinding] = []
    for group in buckets.values():
        # keep the finding carrying the most context (CVSS, then CVE, then evidence)
        primary = max(
            group,
            key=lambda f: (
                f.cvss or 0.0,
                len(f.cve),
                len(f.evidence),
                f.severity.rank,
            ),
        )
        tools = sorted({f.source_tool for f in group})
        scored.append(
            ScoredFinding(
                finding=primary,
                confidence="confirmed" if len(tools) > 1 else "single",
                corroborated_by=tools,
            )
        )

    scored.sort(
        key=lambda sf: (sf.finding.severity.rank, sf.finding.cvss or 0.0),
        reverse=True,
    )
    return scored


def risk_summary(scored: list[ScoredFinding]) -> dict[str, int]:
    """Count findings per severity band (excluding pure INFO attack-surface noise
    is left to the report layer; here we count everything)."""
    counts = {s.value: 0 for s in Severity}
    for sf in scored:
        counts[sf.finding.severity.value] += 1
    return counts


def overall_risk(scored: list[ScoredFinding]) -> str:
    """A single headline risk rating for the engagement."""
    counts = risk_summary(scored)
    if counts[Severity.CRITICAL.value]:
        return "CRITICAL"
    if counts[Severity.HIGH.value]:
        return "HIGH"
    if counts[Severity.MEDIUM.value]:
        return "MEDIUM"
    if counts[Severity.LOW.value]:
        return "LOW"
    return "INFORMATIONAL"
