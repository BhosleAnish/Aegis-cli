"""Bundled inventory collectors for the infra module.

These are the MonitoringAgent's own cross-platform collectors, vendored here so
`aegis infra` runs standalone — no external agent directory required. They are
imported by path (not as a package) inside a child process, so the CLI can run
them on whatever Python it is invoked with.

  * app_inventory.installed_apps()  -> installed software (Windows registry; Linux dpkg/rpm/snap/flatpak)
  * hardware_inventory.hardware()   -> machine/OS/disks/volumes + security posture
"""
from __future__ import annotations

from pathlib import Path

COLLECTORS_DIR: Path = Path(__file__).resolve().parent
