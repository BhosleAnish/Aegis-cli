"""Tests for Phase 4b: active tools (ffuf, dalfox) + the intensity gate — offline."""
import json
from datetime import date

from aegis.models import Authorization, Engagement, Finding, Scope, Severity
from aegis.pipeline import Pipeline
from aegis.tools.base import ToolResult, ToolStatus
from aegis.tools.dalfox_adapter import DalfoxAdapter
from aegis.tools.ffuf_adapter import FfufAdapter


# --- parsing --------------------------------------------------------------- #
def test_ffuf_parse_dedups_urls():
    blob = json.dumps({"results": [
        {"url": "http://h/admin", "status": 200},
        {"url": "http://h/login", "status": 403},
        {"url": "http://h/admin", "status": 200},     # dup
        {"url": "not-a-url"},
    ]})
    results, urls = FfufAdapter._parse(blob)
    assert len(results) == 4
    assert urls == ["http://h/admin", "http://h/login"]


def test_dalfox_parse_list_and_dict_forms():
    item = {"type": "V", "severity": "high", "param": "q", "cwe": "CWE-79",
            "data": "https://app.test/s?q=<x>", "message_str": "reflected"}
    f = DalfoxAdapter._parse(json.dumps([item]))[0]
    assert f.severity == Severity.HIGH and f.source_tool == "dalfox"
    assert f.host == "app.test" and "xss" in f.tags and "CWE-79" in f.tags
    assert "parameter 'q'" in f.title
    # dict form with a "pocs" key parses the same
    assert DalfoxAdapter._parse(json.dumps({"pocs": [item]}))[0].host == "app.test"


def test_dalfox_parse_empty_is_safe():
    assert DalfoxAdapter._parse("") == []
    assert DalfoxAdapter._parse("not json") == []


# --- intensity gate (integration) ----------------------------------------- #
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
        r.urls = ["https://app.test/search?q=1"]
        return r


class _NoEndpoints:
    def __init__(self):
        self.extra_args = []

    def run(self, *a, **k):
        r = ToolResult(tool="disc", status=ToolStatus.OK)
        r.endpoints = []
        return r


class _FakeNuclei:
    def __init__(self):
        self.extra_args = []

    def run(self, targets, services=None, gate=None, urls=None):
        return ToolResult(tool="nuclei", status=ToolStatus.OK)


class _FakeFfuf:
    def __init__(self):
        self.called = False
        self.extra_args = []

    def run(self, roots, wordlist=None, gate=None, host_header=None):
        self.called = True
        r = ToolResult(tool="ffuf", status=ToolStatus.OK)
        r.endpoints = ["https://app.test/admin"]
        return r


class _FakeDalfox:
    def __init__(self):
        self.called = False
        self.received = None
        self.extra_args = []

    def run(self, urls, gate=None, host_header=None):
        self.called = True
        self.received = list(urls)
        f = Finding(title="Reflected XSS", severity=Severity.HIGH,
                    source_tool="dalfox", host="app.test",
                    tags=["xss", "vuln", "active"])
        return ToolResult(tool="dalfox", status=ToolStatus.OK, findings=[f])


def _eng():
    auth = Authorization("E", "Acme", "J", "x@c.t",
                         date(2026, 1, 1), date(2030, 12, 31), "S1")
    return Engagement(auth, Scope(include=["app.test"]))


def _pipe(monkeypatch, intensity):
    monkeypatch.setattr(
        "aegis.pipeline.run_web_assessment",
        lambda target, host_header, logger=None: ToolResult(
            tool="web-assess", status=ToolStatus.OK))
    return Pipeline(_eng(), nmap=_FakeNmap(), httpx=_FakeHttpx(), nuclei=_FakeNuclei(),
                    katana=_NoEndpoints(), gau=_NoEndpoints(),
                    ffuf=_FakeFfuf(), dalfox=_FakeDalfox(), intensity=intensity)


def test_safe_intensity_runs_no_active_tools(monkeypatch):
    pipe = _pipe(monkeypatch, "safe")
    pipe.run()
    assert pipe.ffuf.called is False
    assert pipe.dalfox.called is False


def test_standard_intensity_runs_ffuf_and_dalfox(monkeypatch):
    pipe = _pipe(monkeypatch, "standard")
    report = pipe.run()
    assert pipe.ffuf.called is True
    assert "https://app.test/admin" in report.endpoints       # ffuf paths scanned
    assert pipe.dalfox.received == ["https://app.test/search?q=1"]  # only param URL
    assert any(sf.finding.source_tool == "dalfox" for sf in report.scored)
