"""Tests for Phase 4a: modes, credentials, SAST ingestion, inventory — offline."""
from datetime import date

from aegis.models import Authorization, Credentials, Engagement, Finding, Scope, Severity
from aegis.pipeline import Pipeline
from aegis.tools.base import ToolResult, ToolStatus
from aegis.web_cve import WebComponent


# --- credentials ----------------------------------------------------------- #
def test_credentials_header_args_includes_basic_and_cookie():
    creds = Credentials(headers=["Authorization: Bearer x"], cookie="s=1", basic="u:p")
    args = creds.header_args()
    assert args[:2] == ["-H", "Authorization: Bearer x"]
    assert ["-H", "Cookie: s=1"] == args[2:4]
    assert args[4] == "-H" and args[5] == "Authorization: Basic dTpw"  # base64(u:p)


def test_credentials_empty_is_not_set():
    assert not Credentials().is_set()


# --- Finding round-trip (for SAST re-ingestion) ---------------------------- #
def test_finding_from_dict_round_trips_and_ignores_derived_keys():
    f = Finding(title="SQLi", severity=Severity.HIGH, source_tool="bandit",
                host="repo", location="app.py:42", cve=["CVE-1"])
    d = f.to_dict() | {"confidence": "single", "risk": {"level": "HIGH"}}
    back = Finding.from_dict(d)
    assert back.title == "SQLi" and back.severity == Severity.HIGH
    assert back.location == "app.py:42" and back.cve == ["CVE-1"]


# --- pipeline wiring ------------------------------------------------------- #
class _FakeNmap:
    def __init__(self):
        self.extra_args = []

    def run(self, targets, gate=None):
        return ToolResult(tool="nmap", status=ToolStatus.OK)


class _FakeHttpx:
    def __init__(self):
        self.extra_args = []

    def run(self, targets, services=None, gate=None):
        r = ToolResult(tool="httpx", status=ToolStatus.OK)
        r.urls = ["https://app.test/"]
        return r


class _FakeKatana:
    def __init__(self):
        self.extra_args = []

    def run(self, seeds, gate=None, host_header=None):
        r = ToolResult(tool="katana", status=ToolStatus.OK)
        r.endpoints = []
        return r


class _FakeGau:
    def __init__(self):
        self.extra_args = []

    def run(self, hostnames, gate=None):
        r = ToolResult(tool="gau", status=ToolStatus.OK)
        r.endpoints = []
        return r


class _FakeNuclei:
    def __init__(self):
        self.extra_args = []

    def run(self, targets, services=None, gate=None, urls=None):
        return ToolResult(tool="nuclei", status=ToolStatus.OK)


def _eng():
    auth = Authorization("E", "Acme", "J", "x@c.t",
                         date(2026, 1, 1), date(2030, 12, 31), "S1")
    return Engagement(auth, Scope(include=["app.test"]))


def _pipe(monkeypatch, **kw):
    monkeypatch.setattr(
        "aegis.pipeline.run_web_assessment",
        lambda target, host_header, logger=None: ToolResult(
            tool="web-assess", status=ToolStatus.OK))
    return Pipeline(_eng(), nmap=_FakeNmap(), httpx=_FakeHttpx(), nuclei=_FakeNuclei(),
                    katana=_FakeKatana(), gau=_FakeGau(), **kw)


def test_credentials_injected_into_http_tools(monkeypatch):
    pipe = _pipe(monkeypatch, credentials=Credentials(cookie="session=abc"))
    for adapter in (pipe.httpx, pipe.nuclei, pipe.katana):
        assert "-H" in adapter.extra_args
        assert "Cookie: session=abc" in adapter.extra_args
    assert "Cookie: session=abc" not in pipe.nmap.extra_args  # nmap not HTTP-auth


def test_mode_intensity_and_sast_ingest(monkeypatch):
    code = Finding(title="Hardcoded secret", severity=Severity.HIGH,
                   source_tool="gitleaks", host="repo", location="cfg.py:3")
    pipe = _pipe(monkeypatch, mode="whitebox", intensity="standard",
                 sast_findings=[code])
    report = pipe.run()
    assert report.mode == "whitebox" and report.intensity == "standard"
    titles = [sf.finding.title for sf in report.scored]
    assert "Hardcoded secret" in titles       # code finding folded into the scan


def test_client_inventory_added_to_components(monkeypatch):
    comp = WebComponent(product="nginx", version="1.24.0", host="app.test",
                        source="client-inventory", canonical="nginx")
    pipe = _pipe(monkeypatch, extra_components=[comp])
    report = pipe.run()
    products = {c["product"] for c in report.components}
    assert "nginx" in products
