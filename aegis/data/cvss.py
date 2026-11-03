"""CVSS v3.0/3.1 base-score computation from a vector string.

Self-contained (no deps). OSV advisories often carry a CVSS_V3 vector but not a
numeric score; this turns the vector into the base score so findings get an
accurate severity instead of a guess. Returns None for anything it cannot parse.

Reference: FIRST CVSS v3.1 specification, section 7.1 (Base score).
"""
from __future__ import annotations

import math
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope (unchanged / changed).
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    """CVSS 'Roundup': smallest number, to 1 decimal, >= value (spec Appendix A)."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.x base score from a vector string, or None if unparseable.

    Example: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8
    """
    if not vector:
        return None
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" not in part:
            continue
        key, _, val = part.partition(":")
        metrics[key.upper()] = val.upper()

    try:
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_C if scope_changed else _PR_U
        pr = pr_table[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))
