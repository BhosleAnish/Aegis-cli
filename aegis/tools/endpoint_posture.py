"""Aegis-native endpoint security-posture collection.

Complements the MonitoringAgent inventory with the host-security detail a pentest
endpoint report needs — listening ports, local administrators, firewall/UAC
state, Windows Defender status, remote-access exposure, patch recency, logging.
Runs locally (PowerShell on Windows, best-effort shell on Linux); every section
is independent so one failure never loses the rest, and anything unreadable is
left out (surfaced as "not assessed") rather than guessed.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess

from ..models import Finding, Severity

COMMAND_TIMEOUT = 90

# Each section wrapped in Safe{} so a missing cmdlet / lack of admin never aborts
# the whole collection. Emitted as one compact JSON object on stdout.
_PS_POSTURE = r"""
$ErrorActionPreference = 'Stop'
function Safe($f) { try { & $f } catch { $null } }
$procs = @{}; Safe { Get-Process } | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
$out = [ordered]@{}
$out.listeningPorts = @(Safe { Get-NetTCPConnection -State Listen } | ForEach-Object {
    [ordered]@{ port = [int]$_.LocalPort; address = $_.LocalAddress;
                process = $procs[[int]$_.OwningProcess] } })
$out.localAdmins = @(Safe { Get-LocalGroupMember -Group 'Administrators' } |
    ForEach-Object { $_.Name })
$out.firewall = @(Safe { Get-NetFirewallProfile } | ForEach-Object {
    [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled } })
$out.uacEnabled = Safe { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
$d = Safe { Get-MpComputerStatus }
$out.defender = if ($d) { [ordered]@{ realtime = [bool]$d.RealTimeProtectionEnabled;
    antivirus = [bool]$d.AntivirusEnabled; amService = [bool]$d.AMServiceEnabled;
    signatureAgeDays = [int]$d.AntivirusSignatureAge } } else { $null }
$rdp = Safe { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
$out.rdpEnabled = if ($rdp -ne $null) { [int]$rdp -eq 0 } else { $null }
$out.networkProfiles = @(Safe { Get-NetConnectionProfile } | ForEach-Object {
    [ordered]@{ name = $_.Name; category = "$($_.NetworkCategory)" } })
$out.hotfixes = @(Safe { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 } |
    ForEach-Object { [ordered]@{ id = $_.HotFixID;
        installedOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null } } })
$out.psScriptBlockLogging = Safe { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging').EnableScriptBlockLogging }
$out.screenLockSecs = Safe { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').InactivityTimeoutSecs }
$out | ConvertTo-Json -Depth 6 -Compress
"""


def collect_posture(timeout: int = COMMAND_TIMEOUT) -> dict:
    """Collect endpoint posture for the local host. Returns {} if unsupported/failed."""
    system = platform.system()
    if system == "Windows":
        return _collect_windows(timeout)
    if system == "Linux":
        return _collect_linux(timeout)
    return {}


def _collect_windows(timeout: int) -> dict:
    exe = shutil.which("powershell") or os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        r"System32\WindowsPowerShell\v1.0\powershell.exe")
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _PS_POSTURE],
            capture_output=True, text=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    out = proc.stdout.strip()
    if not out:
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    # dedup listening ports by (port, address)
    seen = set()
    ports = []
    for p in data.get("listeningPorts") or []:
        key = (p.get("port"), p.get("address"))
        if key not in seen:
            seen.add(key)
            ports.append(p)
    data["listeningPorts"] = sorted(ports, key=lambda x: x.get("port", 0))
    return data


def _collect_linux(timeout: int) -> dict:
    def run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, check=False)
            return r.stdout if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    out: dict = {}
    ports = []
    for line in run(["ss", "-tlnH"]).splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addr = parts[3]
            port = addr.rsplit(":", 1)[-1]
            if port.isdigit():
                ports.append({"port": int(port), "address": addr, "process": None})
    out["listeningPorts"] = sorted({(p["port"], p["address"]): p for p in ports}.values(),
                                   key=lambda x: x["port"])
    admins = [l for l in run(["getent", "group", "sudo"]).strip().split(":")[-1].split(",") if l]
    out["localAdmins"] = admins
    # firewall / defender / uac are Windows concepts; left unset on Linux.
    return out


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
# Ports that are notable attack surface if listening.
_RISKY_PORTS = {
    23: (Severity.HIGH, "Telnet (cleartext remote shell)"),
    21: (Severity.MEDIUM, "FTP (often cleartext)"),
    3389: (Severity.MEDIUM, "RDP (remote desktop)"),
    5985: (Severity.LOW, "WinRM HTTP"),
    139: (Severity.LOW, "NetBIOS/SMB"),
}


def posture_findings(posture: dict, host: str) -> list[Finding]:
    if not posture:
        return []
    out: list[Finding] = []

    def add(title, sev, desc, remediation, tags, evidence=""):
        out.append(Finding(
            title=title, severity=sev, source_tool="endpoint-posture", host=host,
            description=desc, remediation=remediation,
            tags=tags + ["infra", "endpoint"], evidence=evidence))

    # Firewall
    for fw in posture.get("firewall") or []:
        if fw.get("enabled") is False:
            add(f"Windows Firewall disabled ({fw.get('name')} profile) on {host}",
                Severity.MEDIUM,
                f"The host firewall is off for the {fw.get('name')} profile.",
                "Enable Windows Firewall for all profiles.", ["firewall"])

    # UAC
    if posture.get("uacEnabled") == 0:
        add(f"User Account Control (UAC) disabled on {host}", Severity.HIGH,
            "UAC is disabled; code can elevate without a consent prompt.",
            "Set EnableLUA=1 and reboot.", ["uac", "privilege"])

    # Defender / AV
    d = posture.get("defender")
    if d is None:
        add(f"Antivirus/EDR status not determinable on {host}", Severity.LOW,
            "Windows Defender status could not be read (third-party EDR or no rights).",
            "Confirm an endpoint protection product is active.", ["edr"])
    else:
        if d.get("realtime") is False or d.get("antivirus") is False:
            add(f"Endpoint protection not active on {host}", Severity.HIGH,
                "Windows Defender real-time/antivirus protection is off and no other "
                "AV was confirmed.",
                "Enable Defender real-time protection or a supported EDR.", ["edr"],
                evidence=json.dumps(d))
        elif isinstance(d.get("signatureAgeDays"), int) and d["signatureAgeDays"] > 7:
            add(f"Antivirus signatures stale on {host}", Severity.MEDIUM,
                f"AV signatures are {d['signatureAgeDays']} days old.",
                "Update antivirus definitions.", ["edr"])

    # Remote access
    if posture.get("rdpEnabled") is True:
        add(f"Remote Desktop (RDP) enabled on {host}", Severity.MEDIUM,
            "RDP is enabled, increasing remote attack surface.",
            "Disable RDP if unused; otherwise restrict to VPN/NLA and MFA.",
            ["remote-access", "attack-surface"])

    # Risky listening ports
    for p in posture.get("listeningPorts") or []:
        port = p.get("port")
        if port in _RISKY_PORTS and str(p.get("address", "")) not in ("127.0.0.1", "::1"):
            sev, label = _RISKY_PORTS[port]
            add(f"Listening service on port {port} ({label}) on {host}", sev,
                f"Port {port} is listening on {p.get('address')} "
                f"(process: {p.get('process') or '?'}).",
                "Close the service or restrict it to trusted networks.",
                ["attack-surface", "port"], evidence=json.dumps(p))

    # Patch recency
    hotfixes = posture.get("hotfixes") or []
    dates = [h.get("installedOn") for h in hotfixes if h.get("installedOn")]
    if dates:
        from datetime import date
        latest = max(dates)
        try:
            days = (date.today() - date.fromisoformat(latest)).days
            if days > 45:
                add(f"OS updates appear overdue on {host}", Severity.MEDIUM,
                    f"The most recent OS update was {latest} ({days} days ago).",
                    "Apply pending OS security updates.", ["patch"], evidence=latest)
        except ValueError:
            pass

    # PowerShell logging
    if posture.get("psScriptBlockLogging") not in (1, "1"):
        add(f"PowerShell script-block logging not enabled on {host}", Severity.LOW,
            "Script-block logging is off, reducing visibility into malicious scripts.",
            "Enable PowerShell script-block logging via policy.", ["logging"])

    # Screen lock
    sls = posture.get("screenLockSecs")
    if sls in (None, 0, "0"):
        add(f"No screen-lock inactivity timeout on {host}", Severity.LOW,
            "No automatic screen lock timeout is configured.",
            "Set an inactivity lock (e.g. 15 minutes) via policy.", ["lock"])

    # Local admins (context)
    admins = posture.get("localAdmins") or []
    if admins:
        add(f"Local administrators on {host}: {len(admins)}", Severity.INFO,
            "Members of the local Administrators group.",
            "Review for unnecessary or stale admin accounts (least privilege).",
            ["identity", "privilege"], evidence=", ".join(admins[:20]))

    return out
