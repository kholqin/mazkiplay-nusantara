import pytest

from app.sentinel.scope import Scope, ScopeError
from app.sentinel.subdomains import (
    generate_candidates,
    resolve_hostname,
)


def test_scope_root_domain():
    scope = Scope(
        "https://example.com"
    )

    assert scope.contains(
        "example.com"
    )


def test_scope_subdomain():
    scope = Scope(
        "https://example.com"
    )

    assert scope.contains(
        "api.example.com"
    )


def test_scope_rejects_external_domain():
    scope = Scope(
        "https://example.com"
    )

    assert not scope.contains(
        "example.org"
    )


def test_scope_rejects_suffix_attack():
    scope = Scope(
        "https://example.com"
    )

    assert not scope.contains(
        "example.com.attacker.test"
    )


def test_scope_validate_raises():
    scope = Scope(
        "https://example.com"
    )

    with pytest.raises(ScopeError):
        scope.validate(
            "attacker.example.org"
        )


def test_candidate_generation():
    scope = Scope(
        "https://example.com"
    )

    candidates = generate_candidates(
        scope,
        prefixes=[
            "api",
            "admin",
            "dev",
        ],
    )

    assert "example.com" in candidates
    assert "api.example.com" in candidates
    assert "admin.example.com" in candidates
    assert "dev.example.com" in candidates


def test_resolve_localhost():
    addresses = resolve_hostname(
        "localhost"
    )

    assert isinstance(
        addresses,
        list,
    )
