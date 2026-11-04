"""The infra module ships its own inventory collectors, so `aegis infra` works
standalone (no external MonitoringAgent dir needed).

Offline: the CLI test stubs run_infra so no collectors actually execute.
"""
from __future__ import annotations

import sys

import pytest

from aegis.collectors import COLLECTORS_DIR


# --- the collectors are bundled with the package --------------------------- #
def test_bundled_collectors_are_present():
    assert (COLLECTORS_DIR / "app_inventory.py").is_file()
    assert (COLLECTORS_DIR / "hardware_inventory.py").is_file()


def test_bundled_collectors_expose_their_api():
    sys.path.insert(0, str(COLLECTORS_DIR))
    try:
        import app_inventory
        import hardware_inventory
    finally:
        sys.path.remove(str(COLLECTORS_DIR))
    assert callable(app_inventory.installed_apps)
    assert callable(hardware_inventory.hardware)


# --- `aegis infra` defaults to the bundled collectors ---------------------- #
class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_cmd_infra_defaults_to_bundled_collectors(monkeypatch):
    from aegis import cli

    captured = {}
    monkeypatch.setattr(cli, "load_engagement", lambda scope, auth: object())
    monkeypatch.setattr(cli, "_write_outputs",
                        lambda eng, report, out, pdf=False: 0)

    def _fake_run_infra(eng, adapter, **kw):
        captured["agent_dir"] = adapter.agent_dir
        return "REPORT"

    monkeypatch.setattr(cli, "run_infra", _fake_run_infra)

    args = _Args(scope="s.yaml", auth="a.yaml", agent_dir=None, infra_json=None,
                 profile=None, cve=False, cve_timeout=20, out="runs", pdf=False,
                 timeout=180)
    rc = cli._cmd_infra(args)
    assert rc == 0
    # with no --agent-dir / --infra-json, it falls back to the bundled collectors
    assert captured["agent_dir"] == str(COLLECTORS_DIR)


def test_cmd_infra_still_honors_explicit_agent_dir(monkeypatch):
    from aegis import cli

    captured = {}
    monkeypatch.setattr(cli, "load_engagement", lambda scope, auth: object())
    monkeypatch.setattr(cli, "_write_outputs",
                        lambda eng, report, out, pdf=False: 0)
    monkeypatch.setattr(cli, "run_infra",
                        lambda eng, adapter, **kw: captured.setdefault(
                            "agent_dir", adapter.agent_dir) or "REPORT")

    args = _Args(scope="s.yaml", auth="a.yaml", agent_dir="/custom/agent",
                 infra_json=None, profile=None, cve=False, cve_timeout=20,
                 out="runs", pdf=False, timeout=180)
    rc = cli._cmd_infra(args)
    assert rc == 0
    assert captured["agent_dir"] == "/custom/agent"
