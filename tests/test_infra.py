"""Tests for the infra module: OS EOL table, normalization, hardening checks."""
from datetime import date

from aegis.data.os_eol import os_eol_status
from aegis.models import Severity
from aegis.tools.infra_adapter import hardening_findings, normalize

# A deliberately weak host: EOL OS, unencrypted C:, Secure Boot off, TPM disabled.
WIN10_BAD = {
    "hostname": "WS-001",
    "apps": [{"name": "7-Zip", "version": "19.0"}],
    "hardware": {
        "os": {"name": "Microsoft Windows 10 Pro", "version": "10.0.19045",
               "build": "19045", "architecture": "64-bit"},
        "system": {"manufacturer": "Dell", "model": "Latitude 7490"},
        "volumes": [{"mount": "C:", "fileSystem": "NTFS", "encryption": "Off"}],
        "security": {"secureBoot": False,
                     "tpm": {"present": True, "enabled": False, "version": "2.0"}},
    },
}

# A hardened host: supported OS, BitLocker on, Secure Boot on, TPM enabled.
WIN11_CLEAN = {
    "hostname": "WS-CLEAN",
    "apps": [],
    "hardware": {
        "os": {"name": "Microsoft Windows 11 Pro", "build": "22631"},
        "volumes": [{"mount": "C:", "encryption": "BitLocker on"}],
        "security": {"secureBoot": True,
                     "tpm": {"present": True, "enabled": True, "version": "2.0"}},
    },
}


# --- EOL table ------------------------------------------------------------- #
def test_windows10_is_eol_after_milestone():
    status, _ = os_eol_status("Microsoft Windows 10 Pro", on=date(2026, 1, 1))
    assert status == "eol"


def test_windows10_not_eol_before_milestone():
    status, _ = os_eol_status("Microsoft Windows 10 Pro", on=date(2024, 1, 1))
    assert status == "supported"


def test_windows11_not_flagged_eol():
    status, _ = os_eol_status("Microsoft Windows 11 Pro", on=date(2026, 1, 1))
    assert status != "eol"


def test_unknown_os_not_flagged():
    status, _ = os_eol_status("SomeCustom OS 1.0")
    assert status == "unknown"


# --- normalization --------------------------------------------------------- #
def test_normalize_maps_fields():
    p = normalize(WIN10_BAD)
    assert p.hostname == "WS-001"
    assert p.os_build == "19045"
    assert p.secure_boot is False
    assert p.tpm_present is True and p.tpm_enabled is False
    assert p.software_count == 1


# --- hardening checks ------------------------------------------------------ #
def test_weak_host_raises_expected_findings():
    titles = {f.title: f for f in hardening_findings(normalize(WIN10_BAD))}
    assert any("End-of-life" in t for t in titles)
    assert any("Unencrypted" in t and f.severity == Severity.HIGH
               for t, f in titles.items())
    assert any("Secure Boot disabled" in t for t in titles)
    assert any("TPM present but disabled" in t for t in titles)


def test_clean_host_has_no_medium_or_higher():
    findings = hardening_findings(normalize(WIN11_CLEAN))
    elevated = [f for f in findings if f.severity.rank >= Severity.MEDIUM.rank]
    assert elevated == []


def test_pii_summary_becomes_info_context():
    inv = {**WIN10_BAD, "pii": {"Aadhaar": 12, "PAN": 3}}
    findings = hardening_findings(normalize(inv))
    pii = [f for f in findings if "Sensitive data" in f.title]
    assert pii and pii[0].severity == Severity.INFO
    assert "grc" in pii[0].tags
