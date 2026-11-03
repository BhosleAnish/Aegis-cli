"""Tests for the scope + authorization gate — the safety-critical module."""
from datetime import date

import pytest

from aegis.models import Authorization, Engagement, Scope
from aegis.scope import AuthorizationError, OutOfScopeError, ScopeGate


def _auth(valid_from="2026-01-01", valid_until="2026-12-31", **over):
    base = dict(
        engagement="Test", client="Acme", authorized_by="Jane Doe",
        contact_email="x@acme.test", valid_from=date.fromisoformat(valid_from),
        valid_until=date.fromisoformat(valid_until), signoff_reference="SOW-1",
    )
    base.update(over)
    return Authorization(**base)


def _eng(include, exclude=None, **auth_over):
    return Engagement(
        authorization=_auth(**auth_over),
        scope=Scope(include=include, exclude=exclude or []),
    )


# --- authorization --------------------------------------------------------- #
def test_valid_authorization_passes():
    gate = ScopeGate(_eng(["192.0.2.0/24"]), today=date(2026, 6, 1))
    gate.assert_authorized()  # should not raise


def test_expired_authorization_blocks():
    gate = ScopeGate(_eng(["192.0.2.0/24"]), today=date(2027, 1, 1))
    with pytest.raises(AuthorizationError):
        gate.assert_authorized()


def test_future_authorization_blocks():
    gate = ScopeGate(_eng(["192.0.2.0/24"]), today=date(2025, 1, 1))
    with pytest.raises(AuthorizationError):
        gate.assert_authorized()


def test_missing_signoff_blocks():
    gate = ScopeGate(_eng(["192.0.2.0/24"], signoff_reference=""),
                     today=date(2026, 6, 1))
    with pytest.raises(AuthorizationError):
        gate.assert_authorized()


# --- scope: CIDR / IP ------------------------------------------------------ #
def test_ip_in_cidr_is_allowed():
    gate = ScopeGate(_eng(["192.0.2.0/24"]))
    assert gate.is_in_scope("192.0.2.50").allowed


def test_ip_outside_cidr_is_blocked():
    gate = ScopeGate(_eng(["192.0.2.0/24"]))
    assert not gate.is_in_scope("198.51.100.1").allowed


def test_exclude_overrides_include():
    gate = ScopeGate(_eng(["192.0.2.0/24"], exclude=["192.0.2.1"]))
    assert not gate.is_in_scope("192.0.2.1").allowed
    assert gate.is_in_scope("192.0.2.2").allowed


def test_assert_in_scope_raises_for_out_of_scope():
    gate = ScopeGate(_eng(["192.0.2.0/24"]))
    with pytest.raises(OutOfScopeError):
        gate.assert_in_scope("10.0.0.1")


# --- scope: hostnames ------------------------------------------------------ #
def test_exact_hostname_allowed():
    gate = ScopeGate(_eng(["app.example.com"]))
    assert gate.is_in_scope("app.example.com").allowed


def test_subdomain_matches_domain_rule():
    gate = ScopeGate(_eng(["example.com"]))
    assert gate.is_in_scope("api.example.com").allowed


def test_unrelated_hostname_blocked():
    gate = ScopeGate(_eng(["example.com"]))
    assert not gate.is_in_scope("example.org").allowed
    # guard against suffix-trick: notexample.com must NOT match example.com
    assert not gate.is_in_scope("notexample.com").allowed


# --- filtering + ports ----------------------------------------------------- #
def test_filter_keeps_only_in_scope():
    gate = ScopeGate(_eng(["192.0.2.0/24"], exclude=["192.0.2.9"]))
    kept = gate.filter(["192.0.2.5", "192.0.2.9", "203.0.113.1"])
    assert kept == ["192.0.2.5"]


def test_port_allowed_respects_allowlist():
    eng = Engagement(authorization=_auth(),
                     scope=Scope(include=["192.0.2.0/24"], allowed_ports=[443]))
    gate = ScopeGate(eng)
    assert gate.port_allowed(443)
    assert not gate.port_allowed(22)
