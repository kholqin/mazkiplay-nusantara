import httpx

from modules.headers import (
    SECURITY_HEADERS,
    _extract_max_age,
    check_header_values,
    check_security_headers,
    run_header_checks,
)


def make_response(
    headers: dict[str, str] | None = None,
    status_code: int = 200,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers=headers or {},
        request=httpx.Request(
            "GET",
            "https://example.com/",
        ),
    )


def test_missing_security_headers():
    response = make_response()

    findings = check_security_headers(response)
    ids = {finding.id for finding in findings}

    assert len(findings) == len(SECURITY_HEADERS)

    assert "missing-strict_transport_security" in ids
    assert "missing-content_security_policy" in ids
    assert "missing-x_content_type_options" in ids
    assert "missing-x_frame_options" in ids
    assert "missing-referrer_policy" in ids
    assert "missing-permissions_policy" in ids


def test_present_security_headers_are_not_reported():
    response = make_response(
        {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
    )

    findings = check_security_headers(response)

    assert findings == []


def test_csp_unsafe_values():
    response = make_response(
        {
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
            )
        }
    )

    findings = check_header_values(response)
    ids = {finding.id for finding in findings}

    assert "csp-unsafe-inline" in ids
    assert "csp-unsafe-eval" in ids


def test_hsts_short_max_age():
    response = make_response(
        {
            "Strict-Transport-Security": "max-age=1000"
        }
    )

    findings = check_header_values(response)
    ids = {finding.id for finding in findings}

    assert "hsts-short-max-age" in ids

    finding = next(
        item
        for item in findings
        if item.id == "hsts-short-max-age"
    )

    assert finding.metadata["max_age"] == 1000


def test_hsts_long_max_age_is_not_reported():
    response = make_response(
        {
            "Strict-Transport-Security": "max-age=31536000"
        }
    )

    findings = check_header_values(response)
    ids = {finding.id for finding in findings}

    assert "hsts-short-max-age" not in ids


def test_invalid_hsts_max_age_is_ignored():
    response = make_response(
        {
            "Strict-Transport-Security": "max-age=invalid"
        }
    )

    findings = check_header_values(response)

    assert "hsts-short-max-age" not in {
        finding.id for finding in findings
    }


def test_extract_max_age():
    assert _extract_max_age("max-age=31536000") == 31536000
    assert _extract_max_age(
        "includeSubDomains; max-age=12345"
    ) == 12345

    assert _extract_max_age(
        "MAX-AGE=999"
    ) == 999

    assert _extract_max_age(
        "includeSubDomains"
    ) is None

    assert _extract_max_age(
        "max-age=invalid"
    ) is None


def test_run_header_checks_combines_checks():
    response = make_response(
        {
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'unsafe-inline'"
            ),
            "Strict-Transport-Security": "max-age=100",
        }
    )

    findings = run_header_checks(response)
    ids = {finding.id for finding in findings}

    assert "csp-unsafe-inline" in ids
    assert "hsts-short-max-age" in ids

    assert "missing-content_security_policy" not in ids
    assert "missing-strict_transport_security" not in ids
