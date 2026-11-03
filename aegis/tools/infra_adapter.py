"""Infrastructure analysis via the MonitoringAgent (Prism) collectors.

Reuses the agent's existing inventory collectors — no Prism server required:

  * app_inventory.installed_apps()  -> installed software (name/version/publisher)
  * hardware_inventory.hardware()   -> machine, OS, disks, volumes + security posture
                                       (BitLocker, TPM, Secure Boot)

Two input modes, same normalization:
  * `collect_via_agent(agent_dir)` runs the collectors on the local host and
    returns their JSON (standalone, on-demand — the engagement model).
  * `load_inventory_json(path)` ingests inventory already produced elsewhere
    (a deployed agent, or an export from the Prism/MonitoringTool server).

From the normalized HostProfile it derives deterministic configuration/hardening
findings (unencrypted volumes, Secure Boot off, TPM missing/disabled, end-of-life
OS). Software-version -> CVE matching is intentionally a later step; here the
software list is carried as asset context only.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from ..data.os_eol import os_eol_status
from ..models import Finding, HostProfile, Severity
from .base import ToolResult, ToolStatus
from .endpoint_posture import collect_posture

# Script run in a child process to pull inventory using the agent's own modules.
# The agent dir is passed as argv[1] so there are no quoting pitfalls.
_COLLECT_SCRIPT = (
    "import sys, json, platform\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import app_inventory, hardware_inventory\n"
    "apps = app_inventory.installed_apps()\n"
    "hw = hardware_inventory.hardware()\n"
    "print(json.dumps({'hostname': platform.node(), 'apps': apps, 'hardware': hw}))\n"
)


class InfraError(Exception):
    """Raised when inventory cannot be collected or parsed."""


# --------------------------------------------------------------------------- #
# Inventory acquisition
# --------------------------------------------------------------------------- #
def collect_via_agent(agent_dir: str | Path, python_exe: Optional[str] = None,
                      timeout: int = 180) -> dict:
    """Run the MonitoringAgent collectors on THIS host and return their JSON."""
    agent_dir = Path(agent_dir)
    if not (agent_dir / "app_inventory.py").exists():
        raise InfraError(f"agent collectors not found in {agent_dir} "
                         "(expected app_inventory.py / hardware_inventory.py)")
    exe = python_exe or sys.executable
    try:
        proc = subprocess.run(
            [exe, "-c", _COLLECT_SCRIPT, str(agent_dir)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InfraError(f"failed to run collectors: {exc}") from exc
    if proc.returncode != 0 or not proc.stdout.strip():
        raise InfraError(proc.stderr.strip() or "collectors produced no output")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise InfraError(f"collector output was not valid JSON: {exc}") from exc
    # Aegis-native endpoint security posture (local host), alongside the inventory.
    try:
        data["posture"] = collect_posture()
    except Exception:  # noqa: BLE001 - posture is best-effort, never fatal
        data["posture"] = {}
    return data


def load_inventory_json(path: str | Path) -> dict:
    """Ingest an inventory JSON produced by a deployed agent or server export."""
    p = Path(path)
    if not p.exists():
        raise InfraError(f"inventory file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InfraError(f"inventory file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise InfraError("inventory JSON must be an object with apps/hardware")
    return data


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #
def normalize(inventory: dict) -> HostProfile:
    hw = inventory.get("hardware") or {}
    osd = hw.get("os") or {}
    system = hw.get("system") or {}
    security = hw.get("security") or {}
    tpm = security.get("tpm")  # {present,enabled,version} | None
    apps = inventory.get("apps") or []

    hostname = (
        inventory.get("hostname")
        or system.get("serialNumber")
        or osd.get("name")
        or "unknown-host"
    )
    return HostProfile(
        hostname=str(hostname),
        os_name=osd.get("name"),
        os_version=osd.get("version"),
        os_build=osd.get("build"),
        architecture=osd.get("architecture"),
        manufacturer=system.get("manufacturer"),
        model=system.get("model"),
        secure_boot=security.get("secureBoot"),
        tpm_present=(tpm.get("present") if isinstance(tpm, dict) else None),
        tpm_enabled=(tpm.get("enabled") if isinstance(tpm, dict) else None),
        volumes=hw.get("volumes") or [],
        software_count=len(apps),
        software=apps,
        pii=inventory.get("pii") or {},
        posture=inventory.get("posture") or {},
    )


# --------------------------------------------------------------------------- #
# Deterministic hardening checks
# --------------------------------------------------------------------------- #
def hardening_findings(profile: HostProfile) -> list[Finding]:
    host = profile.hostname
    out: list[Finding] = []

    def add(title, sev, desc, remediation, tags, evidence=""):
        out.append(Finding(
            title=title, severity=sev, source_tool="infra-agent", host=host,
            description=desc, remediation=remediation,
            tags=tags + ["infra", "hardening"], evidence=evidence,
        ))

    # 1. End-of-life OS
    status, detail = os_eol_status(profile.os_name)
    if status == "eol":
        add(f"End-of-life operating system on {host}", Severity.HIGH,
            f"The host runs an OS past its end of support: {detail}. It no longer "
            "receives security updates.",
            "Upgrade to a supported OS release.", ["os", "patch"],
            evidence=profile.os_name or "")

    # 2. Disk/volume encryption
    for vol in profile.volumes:
        enc = (vol.get("encryption") or "").strip()
        mount = vol.get("mount") or vol.get("label") or "volume"
        if enc.lower() == "off":
            add(f"Unencrypted fixed volume {mount} on {host}", Severity.HIGH,
                f"Fixed volume {mount} has disk encryption disabled; data at rest "
                "is exposed if the device is lost or stolen.",
                "Enable BitLocker (Windows) or LUKS/equivalent full-disk encryption.",
                ["encryption", "data-at-rest"], evidence=json.dumps(vol))
        elif not enc:
            add(f"Encryption status unknown for {mount} on {host}", Severity.LOW,
                f"Could not confirm encryption state of fixed volume {mount}.",
                "Verify full-disk encryption is enabled on this volume.",
                ["encryption"], evidence=json.dumps(vol))

    # 3. Secure Boot
    if profile.secure_boot is False:
        add(f"Secure Boot disabled on {host}", Severity.MEDIUM,
            "Secure Boot is disabled, weakening protection against boot-level and "
            "firmware tampering (bootkits).",
            "Enable Secure Boot in UEFI firmware settings.", ["boot", "firmware"])

    # 4. TPM
    if profile.tpm_present is True and profile.tpm_enabled is False:
        add(f"TPM present but disabled on {host}", Severity.MEDIUM,
            "A TPM is present but not enabled; features that depend on it "
            "(measured boot, key protection, BitLocker) cannot be used.",
            "Enable the TPM in UEFI firmware settings.", ["tpm", "firmware"])
    elif profile.tpm_present is not True:
        add(f"No TPM detected on {host}", Severity.LOW,
            "No TPM was detected (it may be absent or could not be read). Hardware-"
            "backed key protection and measured boot are unavailable without one.",
            "Confirm whether a TPM is available and enable it if so.", ["tpm"])

    # 5. Data sensitivity (context for risk scoring; metadata only, never values)
    if profile.pii:
        cats = ", ".join(f"{k} ({v})" for k, v in sorted(profile.pii.items()))
        add(f"Sensitive data present on {host}", Severity.INFO,
            f"The host stores personal/sensitive data (categories and counts only): "
            f"{cats}. Raises the asset's impact rating for risk assessment.",
            "Confirm this host is in scope for data-handling controls.",
            ["data-sensitivity", "grc"], evidence=cats)

    return out


# --------------------------------------------------------------------------- #
# Adapter
# --------------------------------------------------------------------------- #
class InfraAdapter:
    """Produces infra findings + a HostProfile from agent inventory."""

    name = "infra-agent"

    def __init__(self, agent_dir: Optional[str] = None,
                 inventory_json: Optional[str] = None, timeout: int = 180):
        self.agent_dir = agent_dir
        self.inventory_json = inventory_json
        self.timeout = timeout
        self.profile: Optional[HostProfile] = None

    def acquire(self) -> dict:
        if self.inventory_json:
            return load_inventory_json(self.inventory_json)
        if self.agent_dir:
            return collect_via_agent(self.agent_dir, timeout=self.timeout)
        raise InfraError("no inventory source: pass agent_dir or inventory_json")

    def run(self) -> ToolResult:
        started = time.time()
        try:
            inventory = self.acquire()
        except InfraError as exc:
            return ToolResult(tool=self.name, status=ToolStatus.ERROR, message=str(exc))
        self.profile = normalize(inventory)
        findings = hardening_findings(self.profile)
        res = ToolResult(
            tool=self.name, status=ToolStatus.OK, findings=findings,
            duration_s=round(time.time() - started, 2),
            message=f"{self.profile.software_count} apps, "
                    f"{len(self.profile.volumes)} volume(s)",
        )
        res.profile = self.profile  # type: ignore[attr-defined]
        return res
