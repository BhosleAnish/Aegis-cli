"""Slice 2 Task 2: CPE match engine — resolution, version range, confidence tier.

Builds a tiny fixture mirror (reusing the Task 1 schema helper) and drives the
matcher against it. No network.
"""
import pytest

from aegis.tools import cpe_matcher, nvd_mirror


@pytest.fixture
def mirror(tmp_path):
    """A tiny populated mirror:  acme:widget [1.0,2.0)  (CVE-X),
    acme:gadget ==3.1 (CVE-Y); cpe_dict holds widget, gadget, firefox."""
    import sqlite3
    path = str(tmp_path / "m.sqlite")
    conn = sqlite3.connect(path)
    nvd_mirror.create_schema(conn)
    conn.executemany(
        "INSERT INTO cve (id, cvss, severity, summary, refs, last_modified) VALUES (?,?,?,?,?,?)",
        [("CVE-X", 7.5, "HIGH", "widget flaw", "[]", "2024-01-01"),
         ("CVE-Y", 9.1, "CRITICAL", "gadget flaw", "[]", "2024-01-01"),
         ("CVE-Z", 8.1, "HIGH", "reader flaw", "[]", "2024-01-01")])
    conn.executemany(
        "INSERT INTO cpe_match (cve_id, vendor, product, version_start, start_incl, "
        "version_end, end_incl, exact_version) VALUES (?,?,?,?,?,?,?,?)",
        [("CVE-X", "acme", "widget", "1.0", 1, "2.0", 0, None),
         ("CVE-Y", "acme", "gadget", None, None, None, None, "3.1"),
         ("CVE-Z", "acme", "acrobat_reader", "1.0", 1, "2.0", 0, None)])
    conn.executemany(
        "INSERT INTO cpe_dict (vendor, product, title) VALUES (?,?,?)",
        [("acme", "widget", "Acme Widget"),
         ("acme", "gadget", "Acme Gadget"),
         ("acme", "acrobat_reader", "Acme Acrobat Reader"),
         ("mozilla", "firefox", "Mozilla Firefox")])
    conn.commit()
    conn.close()
    conn = nvd_mirror.open_mirror(path)
    yield conn
    conn.close()


def test_vercmp_boundaries():
    assert cpe_matcher.vercmp((1, 0), (1, 0)) == 0
    assert cpe_matcher.vercmp((1, 2), (1, 10)) < 0          # numeric, not lexical
    assert cpe_matcher.vercmp((2, 0), (1, 9)) > 0
    assert cpe_matcher.vercmp((1,), (1, 0)) == 0            # zero-padded


def _match_one(conn, name, vendor, version, kind="software"):
    item = {"name": name, "vendor": vendor, "version": version, "kind": kind}
    return cpe_matcher.CPEMatcher(conn).match([item], "edge01")[0]


def test_in_range_inclusive_exclusive(mirror):
    assert len(_match_one(mirror, "Acme Widget", "Acme Inc", "1.5")) == 1   # in range -> hit
    assert _match_one(mirror, "Acme Widget", "Acme Inc", "2.0") == []       # end excluding
    assert _match_one(mirror, "Acme Widget", "Acme Inc", "0.9") == []       # below start incl


def test_unparseable_version_caps_low(mirror):
    findings = _match_one(mirror, "Acme Widget", "Acme Inc", "weird-build")
    assert len(findings) == 1
    assert findings[0].raw["confidence"] == "low"
    assert "cpe-low-confidence" in findings[0].tags


def test_resolution_tiers(mirror):
    assert cpe_matcher.resolve_cpe(mirror, "Acme Widget", "Acme Inc")[2] == "high"
    assert cpe_matcher.resolve_cpe(mirror, "Widget", None)[2] == "low"
    assert cpe_matcher.resolve_cpe(mirror, "Totally Unknown App", "Nobody") is None


def test_alias_resolves_vendor(mirror):
    assert cpe_matcher.resolve_cpe(mirror, "Firefox", "Mozilla Firefox")[0] == "mozilla"


def test_multiword_product_resolves(mirror):
    # a multi-token CPE product (acrobat_reader) must resolve from a multi-word name,
    # not only via the alias map — the common Windows-app case.
    r = cpe_matcher.resolve_cpe(mirror, "Acme Acrobat Reader", "Acme Inc")
    assert r == ("acme", "acrobat_reader", "high")
    findings = _match_one(mirror, "Acme Acrobat Reader", "Acme Inc", "1.5")
    assert findings and findings[0].cve == ["CVE-Z"]


def test_match_builds_findings(mirror):
    findings = _match_one(mirror, "Acme Widget", "Acme Inc", "1.5")
    f = findings[0]
    assert f.cve == ["CVE-X"] and f.source_tool == "nvd"
    assert f.raw["nvd_id"] == "CVE-X" and f.raw["confidence"] == "high"
    assert f.raw["cpe"] == "acme:widget"
    assert "cpe-low-confidence" not in f.tags
    assert f.cvss == 7.5


def test_low_tier_tagged(mirror):
    findings = _match_one(mirror, "Widget", None, "1.5")    # product-only -> low
    assert len(findings) == 1
    assert "cpe-low-confidence" in findings[0].tags
    assert findings[0].raw["confidence"] == "low"


def test_hardware_low_dropped(mirror):
    # low-confidence hardware -> dropped this slice
    assert _match_one(mirror, "Widget", None, "1.5", kind="hardware") == []
    # high-confidence hardware -> persisted, tagged "hardware"
    hi = _match_one(mirror, "Acme Widget", "Acme Inc", "1.5", kind="hardware")
    assert len(hi) == 1 and "hardware" in hi[0].tags
