import httpx

from modules.csp import check_csp, parse_csp


def make_response(csp: str | None = None) -> httpx.Response:
    headers = {}

    if csp is not None:
        headers["content-security-policy"] = csp

    return httpx.Response(
        200,
        headers=headers,
        request=httpx.Request(
            "GET",
            "https://example.com/",
        ),
    )


def test_parse_csp():
    directives = parse_csp(
        "default-src 'self'; script-src 'self' https://cdn.example.com; "
        "object-src 'none'"
    )

    assert directives["default-src"] == ["'self'"]
    assert directives["script-src"] == [
        "'self'",
        "https://cdn.example.com",
    ]
    assert directives["object-src"] == ["'none'"]


def test_no_csp_returns_no_findings():
    response = make_response()

    assert check_csp(response) == []


def test_csp_policy_summary():
    response = make_response(
        "default-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'"
    )

    findings = check_csp(response)
    ids = {finding.id for finding in findings}

    assert "csp-policy-summary" in ids


def test_script_wildcard():
    response = make_response(
        "default-src 'self'; script-src *"
    )

    findings = check_csp(response)
    ids = {finding.id for finding in findings}

    assert "csp-script-wildcard" in ids


def test_unsafe_inline_and_eval():
    response = make_response(
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "object-src 'none'"
    )

    findings = check_csp(response)
    ids = {finding.id for finding in findings}

    assert "csp-unsafe-inline" in ids
    assert "csp-unsafe-eval" in ids


def test_missing_object_base_and_frame_ancestors():
    response = make_response(
        "default-src 'self'"
    )

    findings = check_csp(response)
    ids = {finding.id for finding in findings}

    assert "csp-object-src-missing" in ids
    assert "csp-base-uri-missing" in ids
    assert "csp-frame-ancestors-missing" in ids


def test_permissive_object_src():
    response = make_response(
        "default-src 'self'; object-src *"
    )

    findings = check_csp(response)
    ids = {finding.id for finding in findings}

    assert "csp-object-src-permissive" in ids
