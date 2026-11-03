"""Offline operating-system end-of-life (EOL) reference.

A deliberately small, conservative table of well-known EOL milestones so the
infra module can flag an unsupported OS with no network lookup. "Unknown" is
returned rather than guessing when nothing matches — we never flag an OS we
cannot positively place as EOL.

Dates are the end of standard/mainstream support (or extended, where that is the
practically relevant date for a security review). Update as releases age.
"""
from __future__ import annotations

import re
from datetime import date

# (compiled pattern over the OS name, human label, eol date). Order matters:
# more specific patterns first.
_EOL_RULES: list[tuple[re.Pattern, str, date]] = [
    (re.compile(r"windows\s*7", re.I), "Windows 7", date(2020, 1, 14)),
    (re.compile(r"windows\s*8(\.1)?", re.I), "Windows 8/8.1", date(2023, 1, 10)),
    (re.compile(r"windows\s*(10)\b", re.I), "Windows 10", date(2025, 10, 14)),
    (re.compile(r"windows\s*server\s*2008", re.I), "Windows Server 2008", date(2020, 1, 14)),
    (re.compile(r"windows\s*server\s*2012", re.I), "Windows Server 2012/R2", date(2023, 10, 10)),
    (re.compile(r"windows\s*server\s*2016", re.I), "Windows Server 2016", date(2027, 1, 12)),
    (re.compile(r"ubuntu\s*16\.04", re.I), "Ubuntu 16.04 LTS", date(2021, 4, 30)),
    (re.compile(r"ubuntu\s*18\.04", re.I), "Ubuntu 18.04 LTS", date(2023, 5, 31)),
    (re.compile(r"ubuntu\s*20\.04", re.I), "Ubuntu 20.04 LTS", date(2025, 5, 31)),
    (re.compile(r"(centos|rhel|red\s*hat).*\b6\b", re.I), "CentOS/RHEL 6", date(2020, 11, 30)),
    (re.compile(r"centos.*\b8\b", re.I), "CentOS 8", date(2021, 12, 31)),
    (re.compile(r"centos.*\b7\b", re.I), "CentOS 7", date(2024, 6, 30)),
    (re.compile(r"debian.*\b9\b", re.I), "Debian 9", date(2022, 6, 30)),
    (re.compile(r"debian.*\b10\b", re.I), "Debian 10", date(2024, 6, 30)),
]


def os_eol_status(os_name: str | None, on: date | None = None) -> tuple[str, str]:
    """Return (status, detail) where status is 'eol' | 'supported' | 'unknown'.

    `os_name` is the OS caption as reported by the agent (e.g.
    "Microsoft Windows 10 Pro", "Ubuntu 20.04.6 LTS").
    """
    if not os_name:
        return "unknown", "no OS name reported"
    today = on or date.today()
    for pattern, label, eol in _EOL_RULES:
        if pattern.search(os_name):
            if today > eol:
                return "eol", f"{label} reached end of support on {eol.isoformat()}"
            return "supported", f"{label} supported until {eol.isoformat()}"
    return "unknown", f"no EOL record for '{os_name}'"
