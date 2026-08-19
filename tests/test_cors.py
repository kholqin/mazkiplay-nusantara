import httpx

from modules.cors import check_cors


def make_response(**headers: str) -> httpx.Response:
    return httpx.Response(
        200,
        headers=headers,
        request=httpx.Request(
            "GET",
            "https://example.com/",
        ),
    )


def test_no_cors_header_returns_no_findings():
    response = make_response()

    assert check_cors(response) == []


def test_wildcard_origin():
    response = make_response(
        **{
            "Access-Control-Allow-Origin": "*",
        }
    )

    findings = check_cors(response)
    ids = {finding.id for finding in findings}

    assert "cors-wildcard-origin" in ids


def test_wildcard_origin_with_credentials_is_high():
    response = make_response(
        **{
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    findings = check_cors(response)

    finding = next(
        finding
        for finding in findings
        if finding.id == "cors-wildcard-with-credentials"
    )

    assert finding.severity.value.lower() == "high"


def test_credentialed_explicit_origin():
    response = make_response(
        **{
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    findings = check_cors(response)
    ids = {finding.id for finding in findings}

    assert "cors-credentialed-origin" in ids


def test_sensitive_cors_methods():
    response = make_response(
        **{
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
        }
    )

    findings = check_cors(response)

    finding = next(
        finding
        for finding in findings
        if finding.id == "cors-sensitive-methods"
    )

    assert finding.metadata["sensitive_methods"] == ["DELETE", "PUT"]


def test_wildcard_cors_headers():
    response = make_response(
        **{
            "Access-Control-Allow-Origin": "https://trusted.example",
            "Access-Control-Allow-Headers": "*",
        }
    )

    findings = check_cors(response)
    ids = {finding.id for finding in findings}

    assert "cors-wildcard-headers" in ids
