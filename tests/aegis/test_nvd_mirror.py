"""Slice 2 Task 1: local NVD mirror store + sync (stdlib SQLite, HTTP stubbed).

No network: a FakeSync subclass overrides the `_get` HTTP seam to return canned
NVD REST API 2.0 pages from an in-test fixture.
"""
import pytest

from aegis.tools import nvd_mirror


# -- canned NVD API 2.0 payloads -------------------------------------------- #
def _vuln(cve_id, cpe_matches, *, score=7.5, sev="HIGH", last_mod="2024-06-01T00:00:00.000"):
    return {"cve": {
        "id": cve_id,
        "lastModified": last_mod,
        "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": score, "baseSeverity": sev,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }}]},
        "references": [{"url": f"https://nvd/{cve_id}"}],
        "configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}],
    }}


# a product affected over a version range
_RANGE_MATCH = {
    "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "1.0", "versionEndExcluding": "2.0", "vulnerable": True,
}
# a product pinned to one exact version
_EXACT_MATCH = {
    "criteria": "cpe:2.3:a:acme:gadget:3.1:*:*:*:*:*:*:*", "vulnerable": True,
}


def _start_index(url):
    import urllib.parse as up
    q = up.parse_qs(up.urlparse(url).query)
    return int(q.get("startIndex", ["0"])[0])


class FakeSync(nvd_mirror.NVDSync):
    """Serves canned pages keyed by startIndex; no sleeps, no network."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._page_delay = 0
        self.pages = {}

    def _get(self, url):
        return self.pages[_start_index(url)]


def test_first_sync_populates_tables(tmp_path):
    path = str(tmp_path / "m.sqlite")
    s = FakeSync(path)
    s.pages = {0: {
        "resultsPerPage": 2, "startIndex": 0, "totalResults": 2,
        "vulnerabilities": [
            _vuln("CVE-2024-AAAA", [_RANGE_MATCH]),
            _vuln("CVE-2024-BBBB", [_EXACT_MATCH], score=9.8, sev="CRITICAL"),
        ],
    }}
    r = s.run(full=True)
    assert r.ok and r.cves == 2 and r.matches >= 2

    conn = nvd_mirror.open_mirror(path)
    assert conn is not None and nvd_mirror.is_populated(conn)

    # cve rows carry score + severity
    rows = dict((cid, (cvss, sev)) for cid, cvss, sev in
                conn.execute("SELECT id, cvss, severity FROM cve"))
    assert rows["CVE-2024-AAAA"][0] == 7.5 and rows["CVE-2024-AAAA"][1] == "HIGH"
    assert rows["CVE-2024-BBBB"][1] == "CRITICAL"

    # cpe_match rows carry parsed vendor/product/version bounds
    m = conn.execute(
        "SELECT vendor, product, version_start, start_incl, version_end, end_incl, exact_version "
        "FROM cpe_match WHERE cve_id='CVE-2024-AAAA'").fetchall()
    assert m == [("acme", "widget", "1.0", 1, "2.0", 0, None)]
    g = conn.execute(
        "SELECT vendor, product, exact_version FROM cpe_match WHERE cve_id='CVE-2024-BBBB'"
    ).fetchall()
    assert g == [("acme", "gadget", "3.1")]

    # cpe_dict seeded for name->CPE resolution
    prods = {p for (p,) in conn.execute("SELECT product FROM cpe_dict")}
    assert {"widget", "gadget"} <= prods


def test_incremental_sync_upserts_changed_cve(tmp_path):
    path = str(tmp_path / "m.sqlite")
    s = FakeSync(path)
    s.pages = {0: {
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
        "vulnerabilities": [_vuln("CVE-2024-AAAA", [_RANGE_MATCH])],
    }}
    s.run(full=True)

    conn = nvd_mirror.open_mirror(path)
    assert conn.execute("SELECT COUNT(*) FROM cpe_match WHERE cve_id='CVE-2024-AAAA'").fetchone()[0] == 1
    conn.close()

    # second run re-sends CVE-AAAA (modified) with a DIFFERENT single match row
    changed = {
        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "1.5", "versionEndIncluding": "3.0", "vulnerable": True,
    }
    s.pages = {0: {
        "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
        "vulnerabilities": [_vuln("CVE-2024-AAAA", [changed], last_mod="2024-09-01T00:00:00.000")],
    }}
    s.run(full=False)

    conn = nvd_mirror.open_mirror(path)
    # replaced, not duplicated: still one CVE row, still one match row, new bounds
    assert conn.execute("SELECT COUNT(*) FROM cve WHERE id='CVE-2024-AAAA'").fetchone()[0] == 1
    rows = conn.execute(
        "SELECT version_start, start_incl, version_end, end_incl FROM cpe_match "
        "WHERE cve_id='CVE-2024-AAAA'").fetchall()
    assert rows == [("1.5", 1, "3.0", 1)]


class FailingSync(nvd_mirror.NVDSync):
    """Serves page 0, then raises on page 2 of a 2-page full build."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._page_delay = 0

    def _get(self, url):
        if _start_index(url) == 0:
            return {
                "resultsPerPage": 2, "startIndex": 0, "totalResults": 3,
                "vulnerabilities": [
                    _vuln("CVE-2024-AAAA", [_RANGE_MATCH]),
                    _vuln("CVE-2024-BBBB", [_EXACT_MATCH]),
                ],
            }
        raise RuntimeError("boom on page 2")


def test_partial_first_sync_leaves_no_readable_mirror(tmp_path):
    path = str(tmp_path / "m.sqlite")
    with pytest.raises(RuntimeError):
        FailingSync(path).run(full=True)
    # temp build discarded on failure — no mirror file at the target path
    assert nvd_mirror.open_mirror(path) is None


def test_open_mirror_absent_returns_none(tmp_path):
    assert nvd_mirror.open_mirror(str(tmp_path / "nope.sqlite")) is None
