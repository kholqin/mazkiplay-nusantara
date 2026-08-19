import pytest
from typer import BadParameter

from app.cli import validate_target


def test_validate_https_target():
    target = validate_target(
        "https://example.com/"
    )

    assert target.hostname == "example.com"
    assert target.scheme == "https"
    assert target.port is None
    assert str(target.url) == "https://example.com/"


def test_validate_http_target():
    target = validate_target(
        "http://example.com:8080/test"
    )

    assert target.hostname == "example.com"
    assert target.scheme == "http"
    assert target.port == 8080


def test_validate_target_adds_https():
    target = validate_target(
        "example.com"
    )

    assert target.hostname == "example.com"
    assert target.scheme == "https"


def test_validate_target_strips_whitespace():
    target = validate_target(
        "  https://example.com/  "
    )

    assert target.hostname == "example.com"


def test_validate_empty_target():
    with pytest.raises(BadParameter):
        validate_target("")


def test_validate_whitespace_target():
    with pytest.raises(BadParameter):
        validate_target("   ")


def test_validate_unsupported_scheme():
    with pytest.raises(BadParameter):
        validate_target(
            "ftp://example.com/"
        )


def test_validate_missing_hostname():
    with pytest.raises(BadParameter):
        validate_target(
            "https:///path"
        )
