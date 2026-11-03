"""Tests for endpoint discovery: adapter parsing + scope-gated wiring — offline."""
import json
from datetime import date

from aegis.models import Authorization, Engagement, Scope
from aegis.pipeline import Pipeline
from aegis.tools.base import ToolResult, ToolStatus
from aegis.tools.gau_adapter import GauAdapter
from aegis.tools.katana_adapter import KatanaAdapter


# --- adapter parsing ------------------------------------------------------- #
def test_katana_parses_both_shapes_and_dedups():
    jsonl = "\n".join([
        json.dumps({"request": {"method": "GET", "endpoint": "https://a.test/x"}}),
        json.dumps({"endpoint": "https://a.test/y"}),
        json.dumps({"url": "http://a.test/z"}),
        json.dumps({"request": {"endpoint": "https://a.test/x"}}),  # dup
        json.dumps({"endpoint": "ftp://a.test/skip"}),              # non-http, skip
        "not-json",
    ])
    eps = KatanaAdapter._parse(jsonl)
    assert eps == ["https://a.test/x", "https://a.test/y", "http://a.test/z"]


def test_gau_parses_urls_and_filters_noise():
    text = "https://a.test/1\n  http://a.test/2  \njunk line\nhttps://a.test/1\n"
    eps = GauAdapter._parse(text)
    assert eps == ["https://a.test/1", "http://a.test/2"]


# --- scope gating of discovered URLs --------------------------------------- #
def _eng(include):
    auth = Authorization("Disc", "Acme", "Jane", "x@c.test",
                         date(2026, 1, 1), date(2030, 12, 31), "SOW-1")
    return Engagement(authorization=auth, scope=Scope(include=include))


def test_scope_gate_urls_drops_out_of_scope_hosts():
    pipe = Pipeline(_eng(["example.com"]))
    urls = [
        "https://example.com/a",
        "https://evil.com/steal",            # out of scope -> dropped
        "https://sub.example.com/b",         # domain suffix -> in scope
        "https://example.com/a",             # dup -> collapsed
    ]
    kept = pipe._scope_gate_urls(urls)
    assert kept == ["https://example.com/a", "https://sub.example.com/b"]


def test_gau_hostnames_skips_ips_uses_header():
    assert Pipeline(_eng(["10.0.0.1", "example.com"]))._gau_hostnames() == ["example.com"]
    p = Pipeline(_eng(["10.0.0.1"]), host_header="real.test")
    assert p._gau_hostnames() == ["real.test"]


# --- integration: discovery merges, scope-gates, feeds nuclei -------------- #
class _FakeNmap:
    def run(self, targets, gate=None):
        return ToolResult(tool="nmap", status=ToolStatus.OK)


class _FakeHttpx:
    extra_args: list = []

    def run(self, targets, services=None, gate=None):
        r = ToolResult(tool="httpx", status=ToolStatus.OK)
        r.urls = ["https://example.com/"]
        return r


class _FakeKatana:
    extra_args: list = []

    def run(self, seeds, gate=None, host_header=None):
        r = ToolResult(tool="katana", status=ToolStatus.OK)
        r.endpoints = ["https://example.com/admin", "https://evil.com/x"]
        return r


class _FakeGau:
    extra_args: list = []

    def run(self, hostnames, gate=None):
        r = ToolResult(tool="gau", status=ToolStatus.OK)
        r.endpoints = ["https://example.com/old.php?id=1"]
        return r


class _CaptureNuclei:
    extra_args: list = []

    def __init__(self):
        self.received = None

    def run(self, targets, services=None, gate=None, urls=None):
        self.received = urls
        return ToolResult(tool="nuclei", status=ToolStatus.OK)


def test_discovery_merges_scope_gates_and_feeds_nuclei(monkeypatch):
    # web-assess does real network I/O; stub it to a no-op ToolResult.
    monkeypatch.setattr(
        "aegis.pipeline.run_web_assessment",
        lambda target, host_header, logger=None: ToolResult(
            tool="web-assess", status=ToolStatus.OK),
    )
    nuclei = _CaptureNuclei()
    pipe = Pipeline(_eng(["example.com"]), nmap=_FakeNmap(), httpx=_FakeHttpx(),
                    nuclei=nuclei, katana=_FakeKatana(), gau=_FakeGau())
    report = pipe.run()

    expected = [
        "https://example.com/",
        "https://example.com/admin",
        "https://example.com/old.php?id=1",
    ]
    assert sorted(report.endpoints) == sorted(expected)
    assert "https://evil.com/x" not in report.endpoints   # scope gate held
    assert sorted(nuclei.received) == sorted(expected)     # nuclei got the set


def test_no_discovery_flag_scans_only_live_roots(monkeypatch):
    monkeypatch.setattr(
        "aegis.pipeline.run_web_assessment",
        lambda target, host_header, logger=None: ToolResult(
            tool="web-assess", status=ToolStatus.OK),
    )
    nuclei = _CaptureNuclei()
    pipe = Pipeline(_eng(["example.com"]), nmap=_FakeNmap(), httpx=_FakeHttpx(),
                    nuclei=nuclei, katana=_FakeKatana(), gau=_FakeGau(),
                    discovery=False)
    report = pipe.run()
    assert report.endpoints == ["https://example.com/"]
    assert nuclei.received == ["https://example.com/"]
