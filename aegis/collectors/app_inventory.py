"""
app_inventory.py - the software installed on this device, for the device page.

Reads what the operating system already records about installed programs:
  Windows  the Uninstall registry keys (machine-wide, 32-bit, and per-user for signed-in users)
  Linux    dpkg or rpm packages, plus snap and flatpak apps when those are present

Only the program name, version, publisher, install date and where it was found are reported.
Nothing is read from inside the programs or the user's files.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess

log = logging.getLogger("monitoringtool_agent")

MAX_APPS = 4000          # matches the API's limit; a desktop has a few hundred, a Linux server ~2000
COMMAND_TIMEOUT = 60

_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_UNINSTALL_32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


def _app(name, version=None, publisher=None, installed_on=None, source=None) -> dict | None:
    name = (name or "").strip()
    if not name:
        return None
    return {"name": name[:200], "version": (version or "").strip()[:100] or None,
            "publisher": (publisher or "").strip()[:200] or None,
            "installedOn": installed_on, "source": source}


def _install_date(raw) -> str | None:
    """Uninstall keys store InstallDate as YYYYMMDD (sometimes with separators)."""
    digits = re.sub(r"\D", "", str(raw or ""))
    if len(digits) != 8:
        return None
    y, m, d = digits[:4], digits[4:6], digits[6:]
    if not ("1990" <= y <= "2100" and "01" <= m <= "12" and "01" <= d <= "31"):
        return None
    return f"{y}-{m}-{d}"


def _windows_apps() -> list[dict]:
    import winreg

    def read_key(hive, path: str, source: str, out: list[dict]) -> None:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            return
        with root:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub) as k:
                        def val(n):
                            try:
                                return winreg.QueryValueEx(k, n)[0]
                            except OSError:
                                return None
                        # Same rules as Settings > Apps: hide components, updates and patches.
                        if val("SystemComponent") == 1 or val("ParentKeyName") or \
                                str(val("ReleaseType") or "").lower() in ("update", "hotfix", "security update"):
                            continue
                        a = _app(val("DisplayName"), val("DisplayVersion"), val("Publisher"),
                                 _install_date(val("InstallDate")), source)
                        if a:
                            out.append(a)
                except OSError:
                    continue

    apps: list[dict] = []
    read_key(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL, "system", apps)
    read_key(winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_32, "system", apps)
    # The agent runs as SYSTEM, so per-user installs are read from the hives of signed-in users.
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "") as users:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(users, i)
                except OSError:
                    break
                i += 1
                if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
                    read_key(winreg.HKEY_USERS, sid + "\\" + _UNINSTALL, "user", apps)
    except OSError:
        pass
    return apps


def _run(cmd: list[str]) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("%s failed: %s", cmd[0], e)
        return ""


def _linux_apps() -> list[dict]:
    apps: list[dict] = []
    out = _run(["dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${Maintainer}\n"])
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0].startswith("ii"):
            apps.append(_app(parts[1], parts[2], parts[3], None, "dpkg"))
    if not out:
        out = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                apps.append(_app(parts[0], parts[1], None if parts[2] == "(none)" else parts[2], None, "rpm"))
    for line in _run(["snap", "list"]).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            apps.append(_app(parts[0], parts[1], parts[4], None, "snap"))
    for line in _run(["flatpak", "list", "--app", "--columns=name,version,origin"]).splitlines():
        parts = line.split("\t")
        if parts and parts[0]:
            apps.append(_app(parts[0], parts[1] if len(parts) > 1 else None, None, None, "flatpak"))
    return [a for a in apps if a]


def installed_apps() -> list[dict]:
    """Installed programs, de-duplicated and sorted by name. Never raises: an empty list on failure."""
    try:
        apps = _windows_apps() if os.name == "nt" else _linux_apps()
    except Exception as e:                   # an inventory problem must never stop scanning
        log.warning("could not list installed apps: %s", e)
        return []
    seen, out = set(), []
    for a in sorted(apps, key=lambda a: (a["name"].lower(), a["version"] or "", a["publisher"] or "")):
        k = (a["name"].lower(), a["version"], a["publisher"])
        if k not in seen:
            seen.add(k)
            out.append(a)
    return out[:MAX_APPS]


def fingerprint(apps: list[dict]) -> str:
    return hashlib.sha256(json.dumps(apps, sort_keys=True).encode()).hexdigest()
