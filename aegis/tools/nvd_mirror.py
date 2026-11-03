"""Local NVD mirror: a standalone SQLite store of the NVD corpus, synced from the
NVD REST API 2.0, that the CPE matcher reads offline and in-process.

Pure stdlib (``sqlite3``, ``urllib``). The HTTP layer is a single overridable
seam (``NVDSync._get``) so tests stub it — no network in tests. CVSS scores are
derived with :func:`aegis.data.cvss.base_score` when NVD omits the numeric score,
consistent with the OSV matcher.

The store is its own file (not the portal DB): path from
``Settings.nvd_mirror_path``. A full build writes to a temp file and atomically
renames into place, so a sync that fails mid-stream never leaves a half-corpus
the matcher would read.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..data.cvss import base_score
from ..models import Severity

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RESULTS_PER_PAGE = 2000  # NVD's documented maximum page size

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    id            TEXT PRIMARY KEY,
    cvss          REAL,
    severity      TEXT,
    summary       TEXT,
    refs          TEXT,
    last_modified TEXT
);
CREATE TABLE IF NOT EXISTS cpe_match (
    cve_id         TEXT,
    vendor         TEXT,
    product        TEXT,
    version_start  TEXT,
    start_incl     INTEGER,
    version_end    TEXT,
    end_incl       INTEGER,
    exact_version  TEXT
);
CREATE INDEX IF NOT EXISTS ix_cpe_match_vp ON cpe_match(vendor, product);
CREATE TABLE IF NOT EXISTS cpe_dict (
    vendor   TEXT,
    product  TEXT,
    title    TEXT
);
CREATE INDEX IF NOT EXISTS ix_cpe_dict_product ON cpe_dict(product);
CREATE TABLE IF NOT EXISTS sync_meta (key TEXT PRIMARY KEY, value TEXT);
"""


@dataclass
class SyncResult:
    ok: bool
    cves: int = 0
    matches: int = 0
    error: Optional[str] = None


def create_schema(conn: sqlite3.Connection) -> None:
    """Create the mirror's tables/indexes (idempotent). Shared by the sync and
    by test fixtures that build a tiny mirror."""
    conn.executescript(_SCHEMA)


def open_mirror(path: str) -> Optional[sqlite3.Connection]:
    """Return a read-only connection to the mirror, or ``None`` if the file is absent."""
    if not os.path.exists(path):
        return None
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def is_populated(conn: sqlite3.Connection) -> bool:
    """True iff the ``cve`` table exists and has at least one row (graceful on an
    empty/half-built file: a missing table reads as not populated)."""
    try:
        return conn.execute("SELECT 1 FROM cve LIMIT 1").fetchone() is not None
    except sqlite3.OperationalError:
        return False


# -- CVE parsing ------------------------------------------------------------ #
def _score_and_severity(cve: dict) -> tuple[Optional[float], Optional[str]]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                score = base_score(data.get("vectorString", ""))
            if score is None:
                continue
            sev = data.get("baseSeverity") or Severity.from_cvss(float(score)).value.upper()
            return float(score), str(sev).upper()
    return None, None


def _parse_cpe_uri(criteria: str) -> Optional[tuple[str, str, Optional[str]]]:
    """(vendor, product, exact_version|None) from a CPE 2.3 URI, or None if unusable.

    exact_version is set only when the URI pins a concrete version (not ``*``/``-``).
    """
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if not vendor or not product:
        return None
    exact = version if version not in ("*", "-", "") else None
    return vendor, product, exact


def _match_rows(cve_id: str, cve: dict) -> list[tuple]:
    rows: list[tuple] = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for cm in node.get("cpeMatch", []) or []:
                parsed = _parse_cpe_uri(cm.get("criteria", ""))
                if parsed is None:
                    continue
                vendor, product, exact = parsed
                vstart = cm.get("versionStartIncluding") or cm.get("versionStartExcluding")
                start_incl = 1 if "versionStartIncluding" in cm else (0 if "versionStartExcluding" in cm else None)
                vend = cm.get("versionEndIncluding") or cm.get("versionEndExcluding")
                end_incl = 1 if "versionEndIncluding" in cm else (0 if "versionEndExcluding" in cm else None)
                rows.append((cve_id, vendor, product, vstart, start_incl, vend, end_incl, exact))
    return rows


def _dict_rows(cve: dict, matches: list[tuple]) -> list[tuple]:
    seen: set[tuple[str, str]] = set()
    rows: list[tuple] = []
    for (_cid, vendor, product, *_rest) in matches:
        key = (vendor, product)
        if key in seen:
            continue
        seen.add(key)
        rows.append((vendor, product, f"{vendor} {product}"))
    return rows


def _parse_cve(item: dict) -> tuple[tuple, list[tuple], list[tuple]]:
    """One NVD ``vulnerabilities[]`` entry -> (cve_row, match_rows, dict_rows)."""
    cve = item.get("cve") or {}
    cve_id = cve.get("id", "")
    score, severity = _score_and_severity(cve)
    summary = ""
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            summary = d.get("value", "")
            break
    refs = [r.get("url") for r in (cve.get("references") or []) if r.get("url")][:10]
    cve_row = (cve_id, score, severity, summary, json.dumps(refs), cve.get("lastModified"))
    matches = _match_rows(cve_id, cve)
    return cve_row, matches, _dict_rows(cve, matches)


class NVDSync:
    def __init__(self, path: str, *, timeout: int = 30, api_key: Optional[str] = None):
        self.path = path
        self.timeout = timeout
        self.api_key = api_key
        # NVD asks for a pause between pages; an API key raises the rate limit.
        self._page_delay = 0.6 if api_key else 6.0

    # -- HTTP (overridable in tests) -------------------------------------- #
    def _get(self, url: str) -> dict:
        req = urllib.request.Request(url, method="GET")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def _page_url(self, start_index: int, *, last_synced: Optional[str] = None) -> str:
        params = {"startIndex": start_index, "resultsPerPage": _RESULTS_PER_PAGE}
        if last_synced:
            params["lastModStartDate"] = last_synced
            params["lastModEndDate"] = datetime.now(timezone.utc).isoformat()
        return NVD_API + "?" + urllib.parse.urlencode(params)

    # -- sync ------------------------------------------------------------- #
    def run(self, *, full: bool = False) -> SyncResult:
        if full or not os.path.exists(self.path):
            return self._full_build()
        return self._incremental()

    def _iterate(self, conn: sqlite3.Connection, *, last_synced: Optional[str]) -> tuple[int, int]:
        """Page the API, writing CVEs into ``conn``; return (cves, matches)."""
        cves = matches = 0
        start = 0
        while True:
            page = self._get(self._page_url(start, last_synced=last_synced))
            vulns = page.get("vulnerabilities", []) or []
            for item in vulns:
                cve_row, match_rows, dict_rows = _parse_cve(item)
                cve_id = cve_row[0]
                # delete-then-insert so an upsert replaces a CVE's rows, never duplicates
                conn.execute("DELETE FROM cve WHERE id=?", (cve_id,))
                conn.execute("DELETE FROM cpe_match WHERE cve_id=?", (cve_id,))
                conn.execute(
                    "INSERT INTO cve (id, cvss, severity, summary, refs, last_modified) "
                    "VALUES (?,?,?,?,?,?)", cve_row)
                conn.executemany(
                    "INSERT INTO cpe_match (cve_id, vendor, product, version_start, "
                    "start_incl, version_end, end_incl, exact_version) VALUES (?,?,?,?,?,?,?,?)",
                    match_rows)
                for d in dict_rows:
                    if conn.execute("SELECT 1 FROM cpe_dict WHERE vendor=? AND product=?",
                                    (d[0], d[1])).fetchone() is None:
                        conn.execute("INSERT INTO cpe_dict (vendor, product, title) VALUES (?,?,?)", d)
                cves += 1
                matches += len(match_rows)
            total = page.get("totalResults", 0)
            per = page.get("resultsPerPage") or len(vulns)
            start += per
            if per == 0 or not vulns or start >= total:
                break
            time.sleep(self._page_delay)
        return cves, matches

    def _write_meta(self, conn: sqlite3.Connection, cves: int, matches: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        for k, v in (("last_synced_at", now), ("cves", str(cves)), ("matches", str(matches))):
            conn.execute(
                "INSERT INTO sync_meta (key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, v))

    def _full_build(self) -> SyncResult:
        # Build into a temp file in the target directory, then atomically rename,
        # so a partial build never leaves a readable half-mirror at the target.
        target_dir = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(target_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".nvd-", suffix=".sqlite", dir=target_dir)
        os.close(fd)
        conn = sqlite3.connect(tmp)
        try:
            create_schema(conn)
            cves, matches = self._iterate(conn, last_synced=None)
            self._write_meta(conn, cves, matches)
            conn.commit()
            conn.close()
            os.replace(tmp, self.path)
        except BaseException:
            conn.close()
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return SyncResult(ok=True, cves=cves, matches=matches)

    def _incremental(self) -> SyncResult:
        conn = sqlite3.connect(self.path)
        try:
            create_schema(conn)
            row = conn.execute("SELECT value FROM sync_meta WHERE key='last_synced_at'").fetchone()
            last_synced = row[0] if row else None
            cves, matches = self._iterate(conn, last_synced=last_synced)
            self._write_meta(conn, cves, matches)
            conn.commit()
        finally:
            conn.close()
        return SyncResult(ok=True, cves=cves, matches=matches)
