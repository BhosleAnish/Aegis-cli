"""Tests for web tech -> CVE matching: extraction, parsing, NVD/OSV — offline."""
from aegis.models import Finding, Service, Severity
from aegis.tools.osv_matcher import MatchStats
from aegis.web_cve import (
    CveStats,
    NvdMatcher,
    WebComponent,
    _osv_distro_version,
    canonicalize,
    extract_components,
    match_components,
    parse_distro,
    parse_nvd_cve,
    parse_server_header,
)


# --- parsing / normalization ---------------------------------------------- #
def test_parse_server_header_variants():
    assert parse_server_header("Apache/2.4.58 (Ubuntu)") == [("Apache", "2.4.58")]
    assert parse_server_header("nginx/1.24.0") == [("nginx", "1.24.0")]
    assert parse_server_header("nginx") == []          # no version -> not matchable
    assert parse_server_header("") == []


def test_canonicalize_disambiguates():
    assert canonicalize("Apache Tomcat") == "tomcat"   # tomcat before apache
    assert canonicalize("Apache httpd") == "apache"
    assert canonicalize("OpenSSH") == "openssh"
    assert canonicalize("Some-Unknown-Server") == ""


# --- extraction ----------------------------------------------------------- #
def test_extract_components_from_services_and_headers():
    services = [
        Service(host="h", port=443, name="http", product="nginx", version="1.24.0"),
        Service(host="h", port=22, name="ssh", product="OpenSSH", version="9.6p1"),
        Service(host="h", port=3306, name="mysql", product=None, version=None),  # skip
    ]
    findings = [
        Finding(title="live", severity=Severity.INFO, source_tool="httpx", host="h",
                raw={"webserver": "Apache/2.4.58 (Ubuntu)"}),
        Finding(title="noise", severity=Severity.INFO, source_tool="nuclei", host="h",
                raw={"webserver": "ignored/9.9"}),  # not httpx -> ignored
    ]
    comps = extract_components(services, findings)
    got = {(c.canonical, c.version) for c in comps}
    assert got == {("nginx", "1.24.0"), ("openssh", "9.6p1"), ("apache", "2.4.58")}


# --- NVD matcher ---------------------------------------------------------- #
_NVD_RESP = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2024-1234",
            "descriptions": [{"lang": "en", "value": "Flaw in nginx"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 7.5,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"}],
        }}
    ]
}


def test_parse_nvd_cve_maps_score_and_fields():
    comp = WebComponent(product="nginx", version="1.24.0", host="h",
                        source="nmap", canonical="nginx")
    f = parse_nvd_cve(_NVD_RESP["vulnerabilities"][0], comp)
    assert f.cve == ["CVE-2024-1234"]
    assert f.cvss == 7.5 and f.severity == Severity.HIGH
    assert f.source_tool == "nvd" and "cve" in f.tags


def test_nvd_matcher_queries_only_mappable_and_counts():
    comps = [
        WebComponent("nginx", "1.24.0", "h", "nmap", "nginx"),
        WebComponent("Weird", "1.0", "h", "nmap", ""),   # no CPE -> unmatchable
    ]
    m = NvdMatcher(request_delay=0)
    m._get = lambda params: _NVD_RESP           # type: ignore[assignment]
    findings, stats = m.match(comps)
    assert stats.queried == 1 and stats.unmatchable == 1
    assert stats.vulnerable == 1 and stats.advisories == 1
    assert findings[0].cve == ["CVE-2024-1234"]


# --- orchestration: OSV for libs, NVD for the rest ------------------------ #
class _FakeNvd:
    def __init__(self):
        self.received = None

    def match(self, components):
        self.received = components
        f = Finding(title="nginx cve", severity=Severity.HIGH, source_tool="nvd",
                    host="h", cve=["CVE-2024-1234"])
        return [f], CveStats(queried=1, vulnerable=1, advisories=1)


class _FakeOsv:
    def __init__(self):
        self.received = None

    def match(self, software, os_name, host):
        self.received = software
        f = Finding(title="jquery cve", severity=Severity.MEDIUM, source_tool="osv",
                    host=host, cve=["CVE-2020-0001"])
        from aegis.tools.osv_matcher import MatchStats
        return [f], MatchStats(vulnerable=1)


def test_match_components_routes_libs_to_osv():
    comps = [
        WebComponent("jQuery", "3.4.0", "h", "http-server", "jquery"),
        WebComponent("nginx", "1.24.0", "h", "nmap", "nginx"),
    ]
    nvd, osv = _FakeNvd(), _FakeOsv()
    findings, summary = match_components(comps, nvd=nvd, osv=osv)

    # jquery went to OSV (npm), nginx went to NVD
    assert osv.received == [{"name": "jquery", "version": "3.4.0", "ecosystem": "npm"}]
    assert [c.canonical for c in nvd.received] == ["nginx"]
    cves = {c for f in findings for c in f.cve}
    assert cves == {"CVE-2024-1234", "CVE-2020-0001"}
    assert "CVE-2024-1234" not in summary  # summary is counts, not ids
    assert "2 CVE finding(s)" in summary


# --- backport-aware distro matching --------------------------------------- #
def test_parse_distro_variants():
    assert parse_distro("9.6p1 Ubuntu 3ubuntu13.20") == ("Ubuntu", "9.6p1-3ubuntu13.20")
    assert parse_distro("9.2p1 Debian 2+deb12u3") == ("Debian", "9.2p1-2+deb12u3")
    assert parse_distro("Apache/2.4.58 (Ubuntu)") == ("Ubuntu", "")  # flag, no revision
    assert parse_distro("1.24.0") == ("", "")                        # not a distro build
    assert parse_distro("") == ("", "")


def test_extract_components_detects_distro_build():
    services = [
        Service(host="h", port=22, name="ssh", product="OpenSSH",
                version="9.6p1 Ubuntu 3ubuntu13.20"),
        Service(host="h", port=80, name="http", product="nginx", version="1.24.0"),
    ]
    comps = {c.canonical: c for c in extract_components(services, [])}
    ssh = comps["openssh"]
    assert ssh.version == "9.6p1"                 # upstream kept for NVD/CPE
    assert ssh.distro == "Ubuntu" and ssh.pkg_version == "9.6p1-3ubuntu13.20"
    assert ssh.os_package is True
    assert comps["nginx"].os_package is False


def test_osv_distro_version_prepends_known_epoch():
    ssh = WebComponent("OpenSSH", "9.6p1", "h", "nmap", "openssh",
                       distro="Ubuntu", pkg_version="9.6p1-3ubuntu13.20")
    nginx = WebComponent("nginx", "1.24.0", "h", "nmap", "nginx",
                         distro="Ubuntu", pkg_version="1.24.0-1ubuntu1")
    assert _osv_distro_version(ssh) == "1:9.6p1-3ubuntu13.20"  # Ubuntu openssh epoch
    assert _osv_distro_version(nginx) == "1.24.0-1ubuntu1"     # no hint -> bare


class _RecordingNvd:
    """Records each match() call (canonicals + backport flag)."""
    def __init__(self):
        self.calls = []

    def match(self, components, backport=False):
        self.calls.append(([c.canonical for c in components], backport))
        fs = [parse_nvd_cve(_NVD_RESP["vulnerabilities"][0], c, backport=backport)
              for c in components]
        return fs, CveStats(queried=len(components), vulnerable=len(components),
                            advisories=len(components))


class _ScriptedOsv:
    """Returns a distro finding only for configured version strings, else []."""
    def __init__(self, hit_versions=()):
        self.hit_versions = set(hit_versions)
        self.queries = []

    def match(self, software, os_name, host):
        self.queries.append(software[0])
        app = software[0]
        if app["version"] in self.hit_versions:
            f = Finding(title=f"{app['name']} distro cve", severity=Severity.MEDIUM,
                        source_tool="osv", host=host, cve=["CVE-2026-110928"],
                        tags=["cve", "software", "sca", "infra"])
            return [f], MatchStats(vulnerable=1, advisories=1)
        return [], MatchStats(vulnerable=0)


def _ssh_ubuntu():
    return WebComponent("OpenSSH", "9.6p1", "h", "nmap", "openssh",
                        distro="Ubuntu", pkg_version="9.6p1-3ubuntu13.20")


def test_distro_osv_hit_suppresses_upstream_nvd():
    nvd = _RecordingNvd()
    osv = _ScriptedOsv(hit_versions={"1:9.6p1-3ubuntu13.20"})
    findings, summary = match_components([_ssh_ubuntu()], nvd=nvd, osv=osv)

    q = osv.queries[0]
    assert q == {"name": "openssh", "version": "1:9.6p1-3ubuntu13.20",
                 "ecosystem": "Ubuntu"}
    assert nvd.calls == []                               # upstream suppressed
    assert [c for f in findings for c in f.cve] == ["CVE-2026-110928"]
    assert "backport-aware" in summary


def test_distro_osv_empty_with_epoch_is_trusted_and_suppresses_nvd():
    # correct epoch supplied -> empty means genuinely 0 unpatched, not a miss
    nvd = _RecordingNvd()
    osv = _ScriptedOsv(hit_versions=set())
    findings, _ = match_components([_ssh_ubuntu()], nvd=nvd, osv=osv)
    assert osv.queries[0]["version"] == "1:9.6p1-3ubuntu13.20"
    assert nvd.calls == [] and findings == []


def test_distro_osv_empty_without_epoch_falls_back_to_flagged_nvd():
    # nginx has no epoch hint; an empty OSV answer is ambiguous, so keep the
    # NVD candidates but flag them for backport review (down-weighted in risk).
    nginx = WebComponent("nginx", "1.24.0", "h", "nmap", "nginx",
                         distro="Ubuntu", pkg_version="1.24.0-1ubuntu1")
    nvd = _RecordingNvd()
    osv = _ScriptedOsv(hit_versions=set())
    findings, _ = match_components([nginx], nvd=nvd, osv=osv)
    assert osv.queries[0]["version"] == "1.24.0-1ubuntu1"   # bare, no epoch
    assert nvd.calls == [(["nginx"], True)]                 # backport flag set
    assert findings and "backport-review" in findings[0].tags


def test_non_distro_component_still_uses_plain_nvd():
    plain = WebComponent("nginx", "1.24.0", "h", "nmap", "nginx")  # no distro
    nvd = _RecordingNvd()
    osv = _ScriptedOsv()
    findings, _ = match_components([plain], nvd=nvd, osv=osv)
    assert osv.queries == []                 # never routed to OSV
    assert nvd.calls == [(["nginx"], False)]  # plain NVD, not flagged
    assert findings and "backport-review" not in findings[0].tags
