"""Web technology/version fingerprint -> known-CVE matching.

The discovery + probing stages reveal *what software a target runs* — the web
server from the HTTP `Server` header, the service/version banners nmap detects.
This module turns those (product, version) pairs into known-vulnerability
findings:

  * **NVD / CPE** (default engine): each versioned component is mapped to its CPE
    (a curated vendor:product table) and matched against the free NVD 2.0 API by
    exact version. This is the right source for web servers, SSH, databases, etc.
  * **OSV** (for language libraries): recognised JS/library components are routed
    to OSV.dev (npm ecosystem), reusing the infra module's `OSVMatcher`.

Only components that carry a real version are matched — a tech name with no
version (e.g. bare "nginx") cannot be matched precisely, so it is reported as
"detected, not matched" rather than guessed at.

Privacy: matching sends product NAMES and VERSIONS (never page content or data)
to third parties (services.nvd.nist.gov, api.osv.dev). It is therefore opt-in at
the CLI (`--web-cve`).
"""
from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from .data.cvss import base_score
from .models import Finding, Service, Severity
from .tools.osv_matcher import OSVMatcher, OSVUnavailable

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

Logger = Callable[[str], None]

# Canonical product key -> CPE (vendor, product). Conservative: a wrong CPE
# yields wrong CVEs, so only well-known components are mapped; the rest are
# reported as not-matched. Order of _CANON below disambiguates overlaps.
_CPE: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "tomcat": ("apache", "tomcat"),
    "iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "jquery": ("jquery", "jquery"),
    "bootstrap": ("getbootstrap", "bootstrap"),
}

# Substring -> canonical key. Checked in order; more specific first so
# "apache tomcat" resolves to tomcat, not apache.
_CANON: list[tuple[str, str]] = [
    ("tomcat", "tomcat"),
    ("microsoft-iis", "iis"),
    ("iis", "iis"),
    ("openssh", "openssh"),
    ("openssl", "openssl"),
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("lighttpd", "lighttpd"),
    ("wordpress", "wordpress"),
    ("mariadb", "mariadb"),
    ("mysql", "mysql"),
    ("postgresql", "postgresql"),
    ("postgres", "postgresql"),
    ("exim", "exim"),
    ("postfix", "postfix"),
    ("jquery", "jquery"),
    ("bootstrap", "bootstrap"),
    ("php", "php"),
]

# Components better served by OSV's library data (npm ecosystem).
_OSV_NPM = {"jquery": "jquery", "bootstrap": "bootstrap"}

# OS-distro source-package names. When a component ships from a distro archive
# (Ubuntu/Debian) the distro backports security fixes while keeping the upstream
# version string, so NVD/CPE matching on that upstream version over-reports
# (it lists every CVE ever fixed upstream, including ones already patched in the
# backport). These are instead matched against OSV's distro data, which is
# backport-aware. The value is the distro *source* package name.
_DISTRO_PKG: dict[str, str] = {
    "openssh": "openssh",
    "nginx": "nginx",
    "apache": "apache2",
    "openssl": "openssl",
    "exim": "exim4",
    "postfix": "postfix",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "lighttpd": "lighttpd",
}

# Best-effort package epoch hints. Some distro packages carry a version epoch
# (Ubuntu's openssh is "1:9.6p1-...") that the banner never shows; OSV compares
# distro versions with the epoch, so we prepend the hint. A wrong/missing epoch
# only makes OSV return empty — which we treat conservatively (fall back to the
# flagged NVD path) — so it never manufactures a false "clean".
_DISTRO_EPOCH: dict[tuple[str, str], str] = {
    ("ubuntu", "openssh"): "1",
}

# Distro markers found in a version banner, mapped to the OSV ecosystem name.
_DISTRO_MARKERS: list[tuple[str, str]] = [
    ("ubuntu", "Ubuntu"),
    ("debian", "Debian"),
    ("+deb", "Debian"),
    ("~deb", "Debian"),
    ("raspbian", "Debian"),
]

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*[a-z]?\d*")


class WebCveUnavailable(Exception):
    """Raised when every requested CVE source is unreachable."""


@dataclass
class WebComponent:
    product: str          # as detected (display)
    version: str          # upstream version (cleaned), for NVD/CPE
    host: str
    source: str           # "nmap" | "http-server"
    canonical: str = ""   # normalized key into _CPE / _OSV_NPM ("" = unknown)
    distro: str = ""      # OSV distro ecosystem ("Ubuntu"/"Debian") when a
                          # distro build is detected, else ""
    pkg_version: str = "" # distro package version for OSV ("9.6p1-3ubuntu13.20"),
                          # "" when the banner names a distro but no revision

    @property
    def os_package(self) -> bool:
        """True when this component is a distro build (backports apply)."""
        return bool(self.distro)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def canonicalize(product: Optional[str]) -> str:
    """Map a raw product string to a canonical key, or '' if unrecognised."""
    p = (product or "").strip().lower()
    if not p:
        return ""
    for needle, key in _CANON:
        if needle in p:
            return key
    return ""


def _clean_version(raw: Optional[str]) -> str:
    """Keep the leading numeric version token (drop OS suffixes, p-levels kept)."""
    if not raw:
        return ""
    m = _VERSION_RE.match(raw.strip())
    return m.group(0) if m else ""


def parse_server_header(value: Optional[str]) -> list[tuple[str, str]]:
    """Parse an HTTP Server header into (product, version) pairs.

    "Apache/2.4.58 (Ubuntu)" -> [("Apache", "2.4.58")]
    "nginx/1.24.0"           -> [("nginx", "1.24.0")]
    "nginx"                  -> []   (no version -> not matchable)
    """
    out: list[tuple[str, str]] = []
    if not value:
        return out
    for token in str(value).split():
        if "/" not in token:
            continue
        product, _, ver = token.partition("/")
        version = _clean_version(ver)
        if product and version:
            out.append((product, version))
    return out


def parse_distro(raw_version: Optional[str]) -> tuple[str, str]:
    """Detect an OS-distro build from a version banner.

    Returns ``(distro, pkg_version)`` where *distro* is the OSV ecosystem name
    ("Ubuntu"/"Debian") or "", and *pkg_version* is the distro package version
    for OSV, or "" when a distro is named but no package revision is present.

    nmap banner:  "9.6p1 Ubuntu 3ubuntu13.20" -> ("Ubuntu", "9.6p1-3ubuntu13.20")
    debian banner:"9.2p1 Debian 2+deb12u3"    -> ("Debian", "9.2p1-2+deb12u3")
    bare header:  "Apache/2.4.58 (Ubuntu)"    -> ("Ubuntu", "")
    """
    raw = (raw_version or "").strip()
    if not raw:
        return "", ""
    low = raw.lower()
    distro = ""
    for needle, eco in _DISTRO_MARKERS:
        if needle in low:
            distro = eco
            break
    if not distro:
        return "", ""
    # upstream version = leading numeric token; revision = the token carrying
    # the distro marker and a digit (e.g. "3ubuntu13.20", "2+deb12u3").
    tokens = raw.replace("(", " ").replace(")", " ").split()
    upstream = _clean_version(tokens[0]) if tokens else ""
    revision = ""
    for tok in tokens[1:]:
        t = tok.lower()
        if any(m in t for m in ("ubuntu", "deb")) and any(c.isdigit() for c in tok):
            revision = tok.strip(",;")
            break
    if upstream and revision:
        return distro, f"{upstream}-{revision}"
    return distro, ""


def extract_components(services: list[Service],
                       findings: list[Finding]) -> list[WebComponent]:
    """Collect versioned components from nmap services + httpx Server headers."""
    comps: list[WebComponent] = []

    for svc in services or []:
        version = _clean_version(svc.version)
        if svc.product and version:
            distro, pkg = parse_distro(svc.version)
            comps.append(WebComponent(
                product=svc.product, version=version, host=svc.host,
                source="nmap", canonical=canonicalize(svc.product),
                distro=distro, pkg_version=pkg))

    for f in findings or []:
        if f.source_tool != "httpx":
            continue
        server = (f.raw or {}).get("webserver") or (f.raw or {}).get("server")
        # The header may name the distro ("Apache/2.4.58 (Ubuntu)") but never a
        # package revision, so a distro flag (not a pkg_version) is the most we
        # can get — enough to flag NVD matches as possibly-backported.
        distro, _pkg = parse_distro(server)
        for product, version in parse_server_header(server):
            comps.append(WebComponent(
                product=product, version=version, host=f.host or "",
                source="http-server", canonical=canonicalize(product),
                distro=distro))

    # dedup on (canonical-or-product, version, host, source)
    seen: set[tuple] = set()
    out: list[WebComponent] = []
    for c in comps:
        key = (c.canonical or c.product.lower(), c.version, c.host, c.source)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


# --------------------------------------------------------------------------- #
# NVD / CPE matcher
# --------------------------------------------------------------------------- #
@dataclass
class CveStats:
    total: int = 0
    queried: int = 0
    unmatchable: int = 0    # no CPE/OSV mapping or no version
    vulnerable: int = 0     # components with >= 1 advisory
    advisories: int = 0


def _nvd_severity(cve: dict) -> tuple[Optional[float], Severity]:
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {}) or {}
            score = data.get("baseScore")
            if score is None and data.get("vectorString"):
                score = base_score(data["vectorString"])
            if score is not None:
                return float(score), Severity.from_cvss(float(score))
    # a confirmed known vuln with no parseable score is not informational
    return None, Severity.MEDIUM


def parse_nvd_cve(item: dict, comp: WebComponent,
                  backport: bool = False) -> Optional[Finding]:
    """Normalize one NVD 2.0 `vulnerabilities[]` item into a Finding (pure).

    When *backport* is set the component is a distro build whose fix may already
    be backported; the finding is tagged ``backport-review`` (the risk model
    down-weights its likelihood) and the remediation says to verify against the
    distro tracker rather than treating it as a confirmed open vulnerability.
    """
    cve = item.get("cve", {}) or {}
    cid = cve.get("id")
    if not cid:
        return None
    descs = [d.get("value", "") for d in cve.get("descriptions", [])
             if d.get("lang") == "en"]
    summary = (descs[0] if descs else "")[:300]
    cvss, severity = _nvd_severity(cve)
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")][:5]
    tags = ["cve", "sca", "web"]
    remediation = f"Update {comp.product} to a version without {cid}."
    if backport:
        tags.append("backport-review")
        where = comp.distro or "the distro"
        summary = (f"[Affects upstream {comp.product} {comp.version}; the host "
                   f"runs a {where} package, which may already carry a backported "
                   f"fix.] " + summary)[:300]
        remediation = (f"Verify against the {where} security tracker: the fix may "
                       f"already be backported into the installed package. If "
                       f"unpatched, update {comp.product} via the distro package "
                       f"manager.")
    return Finding(
        title=f"Vulnerable component: {comp.product} {comp.version} ({cid})",
        severity=severity,
        source_tool="nvd",
        host=comp.host,
        description=summary,
        cve=[cid],
        cvss=cvss,
        references=refs,
        evidence=f"{comp.source}: {comp.product} {comp.version}",
        remediation=remediation,
        tags=tags,
        raw={"nvd_id": cid, "cpe_product": comp.canonical,
             "backport_review": backport},
    )


class NvdMatcher:
    def __init__(self, timeout: int = 20, api_base: str = NVD_API,
                 api_key: Optional[str] = None, per_component: int = 20,
                 request_delay: float = 6.0):
        self.timeout = timeout
        self.api_base = api_base
        self.api_key = api_key
        self.per_component = per_component
        # NVD allows ~5 req/30s without a key, ~50/30s with one.
        self.request_delay = request_delay if not api_key else max(request_delay / 5, 0.6)

    def _get(self, params: dict) -> dict:  # overridable in tests
        url = self.api_base + "?" + urllib.parse.urlencode(params)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            import json
            return json.loads(r.read().decode())

    def match(self, components: list[WebComponent],
              backport: bool = False) -> tuple[list[Finding], CveStats]:
        """Match components against NVD/CPE by upstream version.

        *backport* marks every finding as a distro-package candidate (see
        :func:`parse_nvd_cve`); it is set for distro builds that OSV could not
        confirm against, so their likelihood is down-weighted rather than
        presented as confirmed.
        """
        stats = CveStats(total=len(components))
        findings: list[Finding] = []
        seen_cpe: set[str] = set()
        to_query = [c for c in components if c.canonical in _CPE and c.version]
        stats.unmatchable = len(components) - len(to_query)

        for idx, comp in enumerate(to_query):
            vendor, product = _CPE[comp.canonical]
            cpe = f"cpe:2.3:a:{vendor}:{product}:{comp.version}:*:*:*:*:*:*:*"
            if cpe in seen_cpe:
                continue
            seen_cpe.add(cpe)
            stats.queried += 1
            try:
                resp = self._get({"virtualMatchString": cpe,
                                  "resultsPerPage": self.per_component})
            except (urllib.error.URLError, OSError, ValueError) as exc:
                raise WebCveUnavailable(f"NVD unavailable: {exc}") from exc
            vulns = resp.get("vulnerabilities", []) or []
            if vulns:
                stats.vulnerable += 1
            for v in vulns:
                f = parse_nvd_cve(v, comp, backport=backport)
                if f:
                    findings.append(f)
                    stats.advisories += 1
            if self.request_delay and idx < len(to_query) - 1:
                time.sleep(self.request_delay)
        return findings, stats


# --------------------------------------------------------------------------- #
# Orchestration: OSV for libraries, NVD for everything else
# --------------------------------------------------------------------------- #
def _osv_distro_version(comp: WebComponent) -> str:
    """Distro package version for an OSV query, with a best-effort epoch."""
    epoch = _DISTRO_EPOCH.get((comp.distro.lower(), comp.canonical))
    return f"{epoch}:{comp.pkg_version}" if epoch else comp.pkg_version


def _match_distro_component(comp: WebComponent, matcher: OSVMatcher,
                            log: Logger) -> tuple[list[Finding], bool]:
    """Match one distro build against OSV's backport-aware distro data.

    Returns ``(findings, trusted)``. *trusted* is True when OSV's answer can be
    relied on to represent the installed package — a non-empty result (the
    version matched), or an empty result for a package whose epoch we supplied
    (so the version was well-formed and OSV genuinely reports nothing open). An
    untrusted result (OSV empty with no epoch hint, or OSV unreachable) means
    the caller should fall back to NVD and flag the matches for review.
    """
    had_epoch = (comp.distro.lower(), comp.canonical) in _DISTRO_EPOCH
    version = _osv_distro_version(comp)
    software = [{"name": _DISTRO_PKG[comp.canonical],
                 "version": version, "ecosystem": comp.distro}]
    try:
        fs, _st = matcher.match(software, None, comp.host)
    except OSVUnavailable as exc:
        log(f"  [osv:distro] {comp.product} {comp.pkg_version} "
            f"({comp.distro}) — unavailable: {exc}")
        return [], False
    if fs:
        log(f"  [osv:distro] {comp.product} {comp.pkg_version} ({comp.distro}) "
            f"— {len(fs)} unpatched CVE(s); upstream NVD matches suppressed "
            f"(backport-aware)")
        return fs, True
    if had_epoch:
        log(f"  [osv:distro] {comp.product} {comp.pkg_version} ({comp.distro}) "
            f"— 0 unpatched; upstream NVD matches suppressed (backport-aware)")
        return [], True
    log(f"  [osv:distro] {comp.product} {comp.pkg_version} ({comp.distro}) "
        f"— no match; falling back to NVD (flagged for backport review)")
    return [], False


def match_components(components: list[WebComponent], timeout: int = 20,
                     nvd_api_key: Optional[str] = None,
                     logger: Optional[Logger] = None,
                     nvd: Optional[NvdMatcher] = None,
                     osv: Optional[OSVMatcher] = None) -> tuple[list[Finding], str]:
    """Match components against OSV (libraries + distro packages) + NVD.

    Routing:
      * language libraries (jQuery, Bootstrap) -> OSV npm data;
      * **distro builds** (Ubuntu/Debian, carrying a package revision) -> OSV's
        backport-aware distro data; when OSV confirms the installed package the
        upstream NVD matches are suppressed, otherwise they are kept but flagged
        ``backport-review`` and down-weighted;
      * everything else -> NVD/CPE by upstream version.

    Returns (findings, one-line summary). Raises WebCveUnavailable only if a
    source that had work to do was unreachable.
    """
    log: Logger = logger or (lambda m: None)
    findings: list[Finding] = []

    osv_comps = [c for c in components if c.canonical in _OSV_NPM and c.version]
    rest = [c for c in components if c not in osv_comps]
    # distro builds with enough detail to query OSV's distro data
    distro_comps = [c for c in rest if c.os_package and c.pkg_version
                    and c.canonical in _DISTRO_PKG]
    nvd_comps = [c for c in rest if c not in distro_comps]

    osv_vulnerable = 0
    osv_matcher = osv or OSVMatcher(timeout=timeout)

    if osv_comps:
        for comp in osv_comps:
            software = [{"name": _OSV_NPM[comp.canonical],
                         "version": comp.version, "ecosystem": "npm"}]
            try:
                fs, st = osv_matcher.match(software, None, comp.host)
            except OSVUnavailable as exc:
                log(f"  [osv] {comp.product} {comp.version} — unavailable: {exc}")
                continue
            findings += fs
            osv_vulnerable += st.vulnerable
        log(f"  [osv] {len(osv_comps)} library component(s) matched")

    # Distro builds: prefer OSV (backport-aware); fall back to flagged NVD.
    distro_trusted = 0
    nvd_backport_comps: list[WebComponent] = []
    for comp in distro_comps:
        fs, trusted = _match_distro_component(comp, osv_matcher, log)
        if trusted:
            findings += fs
            osv_vulnerable += 1 if fs else 0
            distro_trusted += 1
        else:
            nvd_backport_comps.append(comp)
    if distro_comps:
        log(f"  [osv:distro] {distro_trusted}/{len(distro_comps)} distro "
            f"build(s) resolved backport-aware")

    nvd_stats = CveStats()
    if nvd_comps or nvd_backport_comps:
        matcher = nvd or NvdMatcher(timeout=timeout, api_key=nvd_api_key)
        if nvd_comps:
            nvd_findings, nvd_stats = matcher.match(nvd_comps)
            findings += nvd_findings
        if nvd_backport_comps:
            bp_findings, bp_stats = matcher.match(nvd_backport_comps, backport=True)
            findings += bp_findings
            nvd_stats.queried += bp_stats.queried
            nvd_stats.vulnerable += bp_stats.vulnerable
            nvd_stats.advisories += bp_stats.advisories
            nvd_stats.unmatchable += bp_stats.unmatchable
        log(f"  [nvd] {nvd_stats.advisories} CVE(s) across {nvd_stats.vulnerable} "
            f"of {nvd_stats.queried} queried component(s); "
            f"{nvd_stats.unmatchable} not matchable "
            f"({len(nvd_backport_comps)} flagged for backport review)")

    summary = (f"{len(findings)} CVE finding(s); "
               f"NVD {nvd_stats.vulnerable}/{nvd_stats.queried} vulnerable, "
               f"{nvd_stats.unmatchable} unmatchable; "
               f"OSV {osv_vulnerable} vulnerable "
               f"({distro_trusted} distro build(s) backport-aware)")
    return findings, summary
