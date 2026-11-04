"""
hardware_inventory.py - what this device is made of, for the device page.

  Windows  one PowerShell call reading CIM/WMI classes (no extra modules): the machine, BIOS,
           operating system, CPU, memory modules, graphics, physical disks, fixed volumes, and
           the security basics a compliance review asks about (BitLocker, TPM, Secure Boot)
  Linux    /proc, /sys, /etc/os-release, lsblk and lspci when present

Only descriptive facts about the hardware are reported: no IP addresses, MAC addresses, user
names or file contents. Anything that cannot be read (some classes need administrator rights,
some machines lack a TPM) is left out rather than guessed.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess

log = logging.getLogger("monitoringtool_agent")

COMMAND_TIMEOUT = 90

# Each section is read separately so one failing class (no TPM, no admin rights) never loses the rest.
_PS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
function Safe($f) { try { & $f } catch { $null } }
$cs   = Safe { Get-CimInstance Win32_ComputerSystem }
$bios = Safe { Get-CimInstance Win32_BIOS }
$os   = Safe { Get-CimInstance Win32_OperatingSystem }
$vram = @(Safe { Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' } |
          ForEach-Object { $p = Safe { Get-ItemProperty $_.PSPath }
                           if ($p -and $p.DriverDesc -and $p.'HardwareInformation.qwMemorySize') {
                             [pscustomobject]@{ desc = $p.DriverDesc; bytes = $p.'HardwareInformation.qwMemorySize' } } })
$out = [ordered]@{
  system = if ($cs) { [ordered]@{ manufacturer = $cs.Manufacturer; model = $cs.Model; type = $cs.SystemType;
                                  serialNumber = $bios.SerialNumber; biosVersion = $bios.SMBIOSBIOSVersion;
                                  biosDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') } else { $null } } } else { $null }
  os = if ($os) { [ordered]@{ name = $os.Caption; version = $os.Version; build = $os.BuildNumber; architecture = $os.OSArchitecture;
                              installedOn = $os.InstallDate.ToString('yyyy-MM-dd'); lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o') } } else { $null }
  cpus = @(Safe { Get-CimInstance Win32_Processor } | Where-Object { $_ } | ForEach-Object { [ordered]@{
           name = $_.Name.Trim(); manufacturer = $_.Manufacturer; cores = $_.NumberOfCores; threads = $_.NumberOfLogicalProcessors; maxMhz = $_.MaxClockSpeed } })
  memory = [ordered]@{
    totalBytes = if ($cs) { [int64]$cs.TotalPhysicalMemory } else { $null }
    modules = @(Safe { Get-CimInstance Win32_PhysicalMemory } | Where-Object { $_ } | ForEach-Object { [ordered]@{
                capacityBytes = [int64]$_.Capacity; speedMhz = $_.Speed; manufacturer = $_.Manufacturer; slot = $_.DeviceLocator } })
  }
  gpus = @(Safe { Get-CimInstance Win32_VideoController } | Where-Object { $_ } | ForEach-Object { $g = $_; [ordered]@{
           name = $g.Name; driverVersion = $g.DriverVersion;
           # AdapterRAM is a 32-bit field (wrong above 4 GB); the driver's registry entry has the real size.
           memoryBytes = $(
             $q = $vram | Where-Object { $_.desc -eq $g.Name } | Select-Object -First 1
             if ($q) { [int64]$q.bytes } elseif ($g.AdapterRAM) { [int64]$g.AdapterRAM } else { $null });
           resolution = if ($_.CurrentHorizontalResolution) { "$($_.CurrentHorizontalResolution) x $($_.CurrentVerticalResolution)" } else { $null } } })
  disks = @(Safe { Get-CimInstance -Namespace root/Microsoft/Windows/Storage MSFT_PhysicalDisk } | Where-Object { $_ } | ForEach-Object { [ordered]@{
            model = $_.FriendlyName; sizeBytes = [int64]$_.Size;
            mediaType = switch ([int]$_.MediaType) { 3 { 'HDD' } 4 { 'SSD' } 5 { 'SCM' } default { $null } };
            busType = switch ([int]$_.BusType) { 7 { 'USB' } 11 { 'SATA' } 17 { 'NVMe' } 8 { 'RAID' } 10 { 'SAS' } 15 { 'Virtual' } default { $null } };
            health = switch ([int]$_.HealthStatus) { 0 { 'Healthy' } 1 { 'Warning' } 2 { 'Unhealthy' } default { $null } } } })
  volumes = @(Safe { Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' } | Where-Object { $_ } | ForEach-Object { [ordered]@{
              mount = $_.DeviceID; label = $_.VolumeName; fileSystem = $_.FileSystem; sizeBytes = [int64]$_.Size; freeBytes = [int64]$_.FreeSpace; encryption = $null } })
  security = [ordered]@{ tpm = $null; secureBoot = $null }
}
foreach ($g in $out.gpus) { $g.active = $true }
# Hybrid-graphics laptops switch the discrete GPU off in power-saving modes and Windows then drops
# it from the list above. It is still part of the machine: list it as not active right now.
$known = @($out.gpus | ForEach-Object { $_.name })
foreach ($d in @(Safe { Get-PnpDevice -Class Display } | Where-Object { $_ -and -not $_.Present -and $_.FriendlyName -notlike 'Microsoft Basic*' })) {
  if ($known -notcontains $d.FriendlyName) {
    $q = $vram | Where-Object { $_.desc -eq $d.FriendlyName } | Select-Object -First 1
    $out.gpus += [ordered]@{ name = $d.FriendlyName; driverVersion = $null; memoryBytes = if ($q) { [int64]$q.bytes } else { $null }; resolution = $null; active = $false }
    $known += $d.FriendlyName
  }
}
$bl = Safe { Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption Win32_EncryptableVolume }
foreach ($v in $out.volumes) {
  $m = $bl | Where-Object { $_.DriveLetter -eq $v.mount } | Select-Object -First 1
  if ($m) { $v.encryption = switch ([int]$m.ProtectionStatus) { 1 { 'BitLocker on' } 0 { 'Off' } default { $null } } }
}
$tpm = Safe { Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm Win32_Tpm }
if ($tpm) { $out.security.tpm = [ordered]@{ present = $true; enabled = [bool]$tpm.IsEnabled_InitialValue; version = ($tpm.SpecVersion -split ',')[0].Trim() } }
elseif ($bl -ne $null -or $os) { $out.security.tpm = $null }
$sb = Safe { Confirm-SecureBootUEFI }
if ($sb -ne $null) { $out.security.secureBoot = [bool]$sb }
$out | ConvertTo-Json -Depth 6 -Compress
"""


def _windows() -> dict:
    exe = shutil.which("powershell") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                                     r"System32\WindowsPowerShell\v1.0\powershell.exe")
    r = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PS_SCRIPT],
                       capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError((r.stderr or "no output").strip()[:200])
    return json.loads(r.stdout)


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _run(cmd: list[str]) -> str:
    if not shutil.which(cmd[0]):
        return ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _linux() -> dict:
    out: dict = {}
    dmi = lambda k: _read(f"/sys/class/dmi/id/{k}")          # noqa: E731
    out["system"] = {"manufacturer": dmi("sys_vendor"), "model": dmi("product_name"),
                     "serialNumber": dmi("product_serial"), "biosVersion": dmi("bios_version"),
                     "biosDate": dmi("bios_date"), "type": platform.machine()}
    rel = {}
    for line in (_read("/etc/os-release") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            rel[k] = v.strip().strip('"')
    uptime = _read("/proc/uptime")
    boot = None
    if uptime:
        import datetime as dt
        boot = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=float(uptime.split()[0]))).isoformat()
    out["os"] = {"name": rel.get("PRETTY_NAME") or "Linux", "version": platform.release(), "build": rel.get("VERSION_ID"),
                 "architecture": platform.machine(), "installedOn": None, "lastBoot": boot}

    info = _read("/proc/cpuinfo") or ""
    models = re.findall(r"^model name\s*:\s*(.+)$", info, re.M)
    sockets = {s for s in re.findall(r"^physical id\s*:\s*(\d+)$", info, re.M)} or {"0"}
    cores = re.findall(r"^cpu cores\s*:\s*(\d+)$", info, re.M)
    mhz = re.findall(r"^cpu MHz\s*:\s*([\d.]+)$", info, re.M)
    if models:
        out["cpus"] = [{"name": models[0].strip(), "manufacturer": (re.findall(r"^vendor_id\s*:\s*(.+)$", info, re.M) or [None])[0],
                        "cores": int(cores[0]) * len(sockets) if cores else None, "threads": len(models),
                        "maxMhz": int(float(mhz[0])) if mhz else None}]
    m = re.search(r"^MemTotal:\s*(\d+) kB", _read("/proc/meminfo") or "", re.M)
    out["memory"] = {"totalBytes": int(m.group(1)) * 1024 if m else None, "modules": []}

    gpus = []
    for line in _run(["lspci", "-mm"]).splitlines():
        if re.search(r'"(VGA compatible controller|3D controller|Display controller)"', line):
            parts = re.findall(r'"([^"]*)"', line)
            if len(parts) >= 3:
                gpus.append({"name": f"{parts[1]} {parts[2]}".strip(), "driverVersion": None, "memoryBytes": None, "resolution": None, "active": True})
    out["gpus"] = gpus

    disks, volumes = [], []
    try:
        tree = json.loads(_run(["lsblk", "-J", "-b", "-o", "NAME,TYPE,MODEL,SIZE,ROTA,TRAN,FSTYPE,MOUNTPOINT,LABEL"]) or "{}")
    except ValueError:
        tree = {}

    def walk(nodes, encrypted=False):
        for n in nodes or []:
            enc = encrypted or n.get("fstype") == "crypto_LUKS" or n.get("type") == "crypt"
            if n.get("mountpoint") and n.get("fstype") not in (None, "swap") and not str(n["mountpoint"]).startswith(("/snap", "/boot/efi")):
                try:
                    st = os.statvfs(n["mountpoint"])
                    free = st.f_bavail * st.f_frsize
                except OSError:
                    free = None
                volumes.append({"mount": n["mountpoint"], "label": n.get("label"), "fileSystem": n.get("fstype"),
                                "sizeBytes": int(n["size"]) if n.get("size") else None, "freeBytes": free,
                                "encryption": "LUKS" if enc else "Off"})
            walk(n.get("children"), enc)

    for d in tree.get("blockdevices", []):
        if d.get("type") == "disk" and not str(d.get("name", "")).startswith(("loop", "ram", "zram")):
            disks.append({"model": (d.get("model") or d.get("name") or "").strip(), "sizeBytes": int(d["size"]) if d.get("size") else None,
                          "mediaType": None if d.get("rota") is None else ("HDD" if str(d.get("rota")) in ("1", "True", "true") else "SSD"),
                          "busType": (d.get("tran") or "").upper() or None, "health": None})
        walk([d])
    out["disks"], out["volumes"] = disks, volumes
    tpm = os.path.exists("/sys/class/tpm/tpm0")
    sb = None
    for p in ("/sys/firmware/efi/efivars",):
        if os.path.isdir(p):
            for name in os.listdir(p):
                if name.startswith("SecureBoot-"):
                    raw = open(os.path.join(p, name), "rb").read()
                    sb = bool(raw[-1]) if raw else None
    out["security"] = {"tpm": {"present": True, "enabled": True, "version": _read("/sys/class/tpm/tpm0/tpm_version_major")} if tpm else None,
                       "secureBoot": sb}
    return out


def hardware() -> dict | None:
    """This device's hardware. Never raises: None when nothing could be read."""
    try:
        return _windows() if os.name == "nt" else _linux()
    except Exception as e:                   # an inventory problem must never stop scanning
        log.warning("could not read hardware info: %s", e)
        return None

