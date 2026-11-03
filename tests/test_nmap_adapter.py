"""Tests for the nmap adapter's retry-on-empty behaviour — offline, no nmap."""
from aegis.tools.base import ToolStatus
from aegis.tools.nmap_adapter import NmapAdapter

_PORT_XML = (
    '<?xml version="1.0"?>'
    '<nmaprun><host><address addr="1.2.3.4"/><ports>'
    '<port protocol="tcp" portid="22"><state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.20"/>'
    '</port></ports></host></nmaprun>'
)
_ZERO_PORTS_XML = (
    '<?xml version="1.0"?>'
    '<nmaprun><host><address addr="1.2.3.4"/><ports></ports></host></nmaprun>'
)
_BAD_XML = "<nmaprun><host><ports>"  # unterminated -> parse error


class _Proc:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr


def _adapter(script):
    """NmapAdapter whose _exec yields each item of *script* (a _Proc or an
    Exception to raise), recording how many times it was called."""
    a = NmapAdapter(retry_backoff=0)       # no real sleeping
    a.available = lambda: True             # type: ignore[assignment]
    calls = {"n": 0}

    def fake_exec(cmd):
        i = calls["n"]
        calls["n"] += 1
        item = script[i]
        if isinstance(item, Exception):
            raise item
        return item

    a._exec = fake_exec                    # type: ignore[assignment]
    return a, calls


def _run(a):
    return a.run(["1.2.3.4"], gate=None)


def test_no_retry_when_first_attempt_has_ports():
    a, calls = _adapter([_Proc(_PORT_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK
    assert calls["n"] == 1                 # did not retry a good result
    assert [s.port for s in res.services] == [22]
    assert res.message == ""               # no retry note on first-attempt success


def test_retries_empty_then_recovers_ports():
    a, calls = _adapter([_Proc(_ZERO_PORTS_XML), _Proc(_PORT_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK
    assert calls["n"] == 2                 # retried the empty scan
    assert [s.port for s in res.services] == [22]
    assert "attempt 2" in res.message


def test_genuinely_closed_host_is_ok_not_error():
    a, calls = _adapter([_Proc(_ZERO_PORTS_XML), _Proc(_ZERO_PORTS_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK     # valid scan, just nothing open
    assert calls["n"] == 2                 # exhausted the one retry
    assert res.services == []


def test_no_output_every_attempt_is_error():
    a, calls = _adapter([_Proc("", "boom"), _Proc("", "boom")])
    res = _run(a)
    assert res.status == ToolStatus.ERROR
    assert res.message == "boom"
    assert calls["n"] == 2


def test_recovers_after_no_output_clears_error():
    a, _ = _adapter([_Proc("", "transient"), _Proc(_PORT_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK     # earlier error must not leak through
    assert [s.port for s in res.services] == [22]


def test_parse_error_is_retried():
    a, calls = _adapter([_Proc(_BAD_XML), _Proc(_PORT_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK
    assert calls["n"] == 2


def test_exec_exception_is_retried():
    a, calls = _adapter([RuntimeError("spawn failed"), _Proc(_PORT_XML)])
    res = _run(a)
    assert res.status == ToolStatus.OK
    assert calls["n"] == 2


def test_retries_can_be_disabled():
    a, calls = _adapter([_Proc(_ZERO_PORTS_XML)])
    a.retries = 0
    res = _run(a)
    assert res.status == ToolStatus.OK
    assert calls["n"] == 1                 # single attempt, no retry
