"""Tests for the scope / authorization safety rail — the tool's core guarantee."""
from __future__ import annotations

import datetime

import pytest

from sentinel.core.scope import Scope, ScopeError


def make_scope(**over):
    base = {
        "engagement": "unit-test",
        "authorized_by": "tester",
        "authorized_until": "2999-12-31",
        "targets": ["127.0.0.1", "10.0.0.0/24", "example.test"],
        "exclude": ["10.0.0.5"],
    }
    base.update(over)
    return Scope.from_dict(base)


def test_requires_core_fields():
    with pytest.raises(ScopeError):
        Scope.from_dict({"engagement": "x"})


def test_rejects_expired_engagement():
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    with pytest.raises(ScopeError):
        make_scope(authorized_until=yesterday)


def test_authorizes_exact_ip():
    s = make_scope()
    assert s.authorize("127.0.0.1").authorized


def test_authorizes_ip_in_cidr():
    s = make_scope()
    res = s.authorize("10.0.0.42")
    assert res.authorized
    assert "within authorized scope" in res.reason


def test_exclusion_beats_inclusion():
    s = make_scope()
    res = s.authorize("10.0.0.5")  # inside /24 but excluded
    assert not res.authorized
    assert "exclude" in res.reason.lower()


def test_denies_out_of_scope_ip():
    s = make_scope()
    assert not s.authorize("8.8.8.8").authorized


def test_authorizes_literal_hostname():
    s = make_scope()
    assert s.authorize("example.test").authorized


def test_denies_unlisted_hostname():
    s = make_scope()
    assert not s.authorize("evil.example").authorized


def test_filter_partitions_targets():
    s = make_scope()
    allowed, denied = s.filter_authorized(["127.0.0.1", "8.8.8.8", "10.0.0.5"])
    assert [a.spec for a in allowed] == ["127.0.0.1"]
    assert {d.spec for d in denied} == {"8.8.8.8", "10.0.0.5"}
