"""CPE match engine: resolve an installed item (name + vendor) to a CPE product,
match its version against the local NVD mirror's known-affected ranges, and emit
CVE findings with a high/low confidence tier.

Reads an injected read-only mirror connection (from
:func:`aegis.tools.nvd_mirror.open_mirror`), so it is offline and testable with a
tiny fixture DB. Resolution is normalized exact-match plus a small curated alias
map — no fuzzy guessing into findings (spec §5.2). Match confidence lives in the
finding's ``tags`` + ``raw``, never in ``Finding.confidence`` (which is about
exploitability).
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Optional

from ..models import Finding, Severity

# Vendor suffixes stripped during normalization.
_SUFFIX_WORDS = {"inc", "corp", "corporation", "ltd", "llc", "co", "gmbh"}

# Curated vendor/product aliases (data, not code). Keys are the "loose" form
# (lowercased, suffix-stripped, space-separated). A str value is a vendor; a
# 2-tuple is (vendor, product).
ALIASES: dict[str, object] = {
    "microsoft corporation": "microsoft",
    "microsoft": "microsoft",
    "mozilla firefox": ("mozilla", "firefox"),
    "mozilla": "mozilla",
    "google": "google",
    "google llc": "google",
    "oracle corporation": "oracle",
    "the document foundation": "libreoffice",
}


def _raw_tokens(s: Optional[str]) -> list[str]:
    if not s:
        return []
    s = s.lower().replace("®", "").replace("™", "")  # ® ™
    toks = re.split(r"[^a-z0-9]+", s)
    return [t for t in toks if t and t not in _SUFFIX_WORDS]


def normalize(s: Optional[str]) -> str:
    """Lowercase, strip corporate suffixes/®/™ and trailing version noise, and
    render the remainder in the CPE underscore form."""
    toks = _raw_tokens(s)
    while toks and re.fullmatch(r"[0-9][0-9._]*", toks[-1]):  # drop trailing version tokens
        toks.pop()
    return "_".join(toks)


def _loose(s: Optional[str]) -> str:
    """Space-separated normalized form used for alias lookup."""
    return " ".join(_raw_tokens(s))


def _tokens(normalized: str) -> set[str]:
    return {t for t in normalized.split("_") if t}


def _apply_aliases(name: Optional[str], vendor: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    vend_hint: Optional[str] = None
    prod_hint: Optional[str] = None
    for src in (vendor, name):
        val = ALIASES.get(_loose(src))
        if val is None:
            continue
        if isinstance(val, tuple):
            vend_hint, prod_hint = val
        else:
            vend_hint = val
    return vend_hint, prod_hint


def resolve_cpe(conn: sqlite3.Connection, name: str,
                vendor: Optional[str]) -> Optional[tuple[str, str, str]]:
    """Resolve (name, vendor) to ``(vendor, product, confidence)`` or ``None``.

    confidence is ``"high"`` when both vendor and product agree, ``"low"`` when
    only the product agrees; no product agreement returns ``None`` (dropped).
    """
    vend_hint, prod_hint = _apply_aliases(name, vendor)
    name_tokens = _tokens(normalize(name))
    norm_vendor = normalize(vendor) if vendor else ""
    vendor_tokens = _tokens(norm_vendor)
    norm_hint_vendor = normalize(vend_hint) if vend_hint else ""
    norm_hint_product = normalize(prod_hint) if prod_hint else ""

    best: Optional[tuple[str, str, str]] = None
    for dv, dp, _title in conn.execute("SELECT vendor, product, title FROM cpe_dict"):
        ndp, ndv = normalize(dp), normalize(dv)
        # product agrees when every token of the (possibly multi-word) CPE product
        # appears in the installed name — "Acme Acrobat Reader" -> acme:acrobat_reader —
        # or when an alias resolved the product directly.
        product_tokens = _tokens(ndp)
        product_ok = bool(
            (product_tokens and product_tokens <= name_tokens)
            or (norm_hint_product and norm_hint_product == ndp)
        )
        if not product_ok:
            continue
        vendor_ok = bool(
            (norm_hint_vendor and norm_hint_vendor == ndv)
            or (ndv and ndv in vendor_tokens)
            or (ndv and ndv in name_tokens)
        )
        conf = "high" if vendor_ok else "low"
        if best is None or (conf == "high" and best[2] == "low"):
            best = (dv, dp, conf)
    return best


# -- version comparison ----------------------------------------------------- #
def parse_version(v: Optional[str]) -> Optional[tuple[int, ...]]:
    """Leading dotted/dashed numeric components, or ``None`` if none parse."""
    if not v:
        return None
    parts: list[int] = []
    for chunk in re.split(r"[.\-]", str(v)):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts) if parts else None


def vercmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Numeric component compare (zero-padded): -1 / 0 / 1."""
    n = max(len(a), len(b))
    a = tuple(a) + (0,) * (n - len(a))
    b = tuple(b) + (0,) * (n - len(b))
    return (a > b) - (a < b)


@dataclass
class CPEMatchStats:
    total: int = 0
    resolved_high: int = 0
    resolved_low: int = 0
    unresolved: int = 0
    vulnerable: int = 0
    advisories: int = 0


def _applicable(installed: Optional[tuple[int, ...]], row) -> Optional[bool]:
    """Is ``installed`` in this cpe_match row's affected set?

    Returns True/False, or ``None`` when the installed version cannot be parsed
    (caller treats that as applicable-but-low-confidence).
    """
    (_cve_id, _vendor, _product, vstart, start_incl, vend, end_incl, exact) = row
    if installed is None:
        return None
    if exact is not None:
        pe = parse_version(exact)
        return pe is not None and vercmp(installed, pe) == 0
    ok = True
    if vstart is not None:
        ps = parse_version(vstart)
        if ps is not None:
            c = vercmp(installed, ps)
            ok = ok and (c >= 0 if start_incl else c > 0)
    if vend is not None:
        pe = parse_version(vend)
        if pe is not None:
            c = vercmp(installed, pe)
            ok = ok and (c <= 0 if end_incl else c < 0)
    return ok


class CPEMatcher:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _severity(self, cvss: Optional[float], label: Optional[str]) -> Severity:
        if label:
            try:
                return Severity(str(label).lower())
            except ValueError:
                pass
        return Severity.from_cvss(cvss) if cvss is not None else Severity.MEDIUM

    def match(self, items: list[dict], host: str) -> tuple[list[Finding], CPEMatchStats]:
        stats = CPEMatchStats(total=len(items))
        findings: list[Finding] = []

        for item in items:
            name = item.get("name") or ""
            vendor = item.get("vendor")
            version = item.get("version")
            kind = item.get("kind", "software")

            resolved = resolve_cpe(self.conn, name, vendor)
            if resolved is None:
                stats.unresolved += 1
                continue
            rv, rp, res_conf = resolved
            if res_conf == "high":
                stats.resolved_high += 1
            else:
                stats.resolved_low += 1

            installed = parse_version(version)
            rows = self.conn.execute(
                "SELECT cve_id, vendor, product, version_start, start_incl, version_end, "
                "end_incl, exact_version FROM cpe_match WHERE vendor=? AND product=?",
                (rv, rp)).fetchall()

            seen: set[str] = set()
            item_findings: list[Finding] = []
            for row in rows:
                cve_id = row[0]
                if cve_id in seen:
                    continue
                verdict = _applicable(installed, row)
                if verdict is False:
                    continue
                # verdict True (clean hit) or None (unparseable -> cap low)
                tier = "high" if (res_conf == "high" and verdict is True) else "low"
                if kind == "hardware" and tier == "low":
                    continue  # spec §1: hardware is high-confidence-only this slice
                seen.add(cve_id)
                item_findings.append(self._build(cve_id, name, version, rv, rp, tier, kind, host))

            if item_findings:
                stats.vulnerable += 1
                stats.advisories += len(item_findings)
                findings.extend(item_findings)

        return findings, stats

    def _build(self, cve_id: str, name: str, version: Optional[str], vendor: str,
               product: str, tier: str, kind: str, host: str) -> Finding:
        row = self.conn.execute(
            "SELECT cvss, severity FROM cve WHERE id=?", (cve_id,)).fetchone()
        cvss, sev_label = (row[0], row[1]) if row else (None, None)
        kind_word = "hardware" if kind == "hardware" else "software"
        ver = version or "?"
        tags = ["cve", "software", "cpe"]
        if tier == "low":
            tags.append("cpe-low-confidence")
        if kind == "hardware":
            tags.append("hardware")
        return Finding(
            title=f"Vulnerable {kind_word}: {name} {ver} ({cve_id})",
            severity=self._severity(cvss, sev_label),
            source_tool="nvd",
            host=host,
            cve=[cve_id],
            cvss=cvss,
            evidence=f"cpe:2.3:a:{vendor}:{product}:{ver}  [{cve_id}]",
            tags=tags,
            raw={"nvd_id": cve_id, "cpe": f"{vendor}:{product}", "confidence": tier},
        )
