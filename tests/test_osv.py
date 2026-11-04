"""Tests for OSV CVE matching: CVSS scoring, ecosystem resolution, parsing, match."""
import urllib.error

import pytest

from aegis.data.cvss import base_score
from aegis.models import Severity
from aegis.tools.osv_matcher import (
    OSVMatcher,
    OSVUnavailable,
    parse_vuln,
    resolve_ecosystem,
)

# A representative OSV advisory (critical RCE, fixed in 1.2.3).
VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2021-1234", "PYSEC-2021-1"],
    "summary": "Remote code execution in libfoo",
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [{"type": "ADVISORY", "url": "https://example.test/CVE-2021-1234"}],
    "affected": [{"ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
}


# --- CVSS scoring ---------------------------------------------------------- #
def test_cvss_critical_vector():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_high_availability_only():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5


def test_cvss_unparseable_returns_none():
    assert base_score("not-a-vector") is None
    assert base_score("") is None


# --- ecosystem resolution -------------------------------------------------- #
def test_ecosystem_from_dpkg_and_os():
    assert resolve_ecosystem("Ubuntu 20.04.6 LTS", "dpkg") == "Ubuntu"
    assert resolve_ecosystem("Debian GNU/Linux 11", "dpkg") == "Debian"


def test_ecosystem_explicit_wins():
    assert resolve_ecosystem("whatever", "system", explicit="PyPI") == "PyPI"


def test_windows_app_not_resolvable():
    assert resolve_ecosystem("Microsoft Windows 11 Pro", "system") is None
    assert resolve_ecosystem("Microsoft Windows 11 Pro", "user") is None


def test_ecosystem_recognizes_kali_as_debian():
    # Kali is Debian-based (dpkg) but its OS name contains neither "debian"
    # nor "ubuntu" — it must still resolve to the Debian OSV ecosystem.
    assert resolve_ecosystem("Kali GNU/Linux Rolling", "dpkg") == "Debian"


def test_ecosystem_recognizes_debian_derivatives():
    assert resolve_ecosystem("Parrot Security 6.0", "dpkg") == "Debian"
    assert resolve_ecosystem("Raspbian GNU/Linux 12 (bookworm)", "dpkg") == "Debian"


def test_ecosystem_recognizes_ubuntu_derivatives():
    assert resolve_ecosystem("Linux Mint 21.3", "dpkg") == "Ubuntu"
    assert resolve_ecosystem("Pop!_OS 22.04 LTS", "dpkg") == "Ubuntu"


def test_derivative_still_requires_a_linux_source():
    # a Windows-sourced app on a Kali host is still not a dpkg package
    assert resolve_ecosystem("Kali GNU/Linux Rolling", "system") is None


def test_match_queries_a_kali_dpkg_package(monkeypatch):
    m = OSVMatcher()
    m._post = lambda path, payload: {"results": [{"vulns": [{"id": VULN["id"]}]}]}
    m._get = lambda path: VULN
    findings, stats = m.match(
        [{"name": "curl", "version": "7.88.1-10", "source": "dpkg"}],
        "Kali GNU/Linux Rolling", "kali")
    assert stats.queried == 1 and stats.unmatchable == 0
    assert findings[0].cve == ["CVE-2021-1234"]


# --- advisory parsing ------------------------------------------------------ #
def test_parse_vuln_builds_finding():
    app = {"name": "libfoo", "version": "1.0.0", "source": "dpkg"}
    f = parse_vuln(VULN, app, "Ubuntu", "HOST1")
    assert f.cve == ["CVE-2021-1234"]
    assert f.cvss == 9.8
    assert f.severity == Severity.CRITICAL
    assert f.host == "HOST1"
    assert "1.2.3" in f.remediation
    assert f.references == ["https://example.test/CVE-2021-1234"]
    assert "sca" in f.tags


# --- matcher (HTTP mocked) ------------------------------------------------- #
def test_match_queries_linux_skips_windows(monkeypatch):
    soft = [
        {"name": "libfoo", "version": "1.0.0", "source": "dpkg"},   # queried
        {"name": "7-Zip", "version": "19.0", "source": "system"},   # unmatchable
    ]
    m = OSVMatcher()
    m._post = lambda path, payload: {"results": [{"vulns": [{"id": VULN["id"]}]}]}
    m._get = lambda path: VULN

    findings, stats = m.match(soft, "Ubuntu 20.04", "HOST1")
    assert stats.total == 2
    assert stats.queried == 1
    assert stats.unmatchable == 1
    assert stats.vulnerable == 1
    assert stats.advisories == 1
    assert findings[0].cve == ["CVE-2021-1234"]
    assert findings[0].severity == Severity.CRITICAL


def test_match_raises_when_osv_down(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")

    m = OSVMatcher()
    m._post = boom
    with pytest.raises(OSVUnavailable):
        m.match([{"name": "libfoo", "version": "1.0.0", "source": "dpkg"}],
                "Ubuntu 20.04", "HOST1")


def test_no_queryable_software_returns_empty():
    m = OSVMatcher()
    findings, stats = m.match(
        [{"name": "7-Zip", "version": "19.0", "source": "system"}],
        "Microsoft Windows 11 Pro", "HOST1")
    assert findings == []
    assert stats.queried == 0 and stats.unmatchable == 1
