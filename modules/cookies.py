from __future__ import annotations

from http.cookies import SimpleCookie

import httpx

from app.models import Finding, Severity


def check_cookies(response: httpx.Response) -> list[Finding]:
    """
    Analyze Set-Cookie headers for common security attributes.

    Passive check only: no cookie manipulation or exploitation.
    """

    findings: list[Finding] = []

    raw_cookies = response.headers.get_list("set-cookie")

    if not raw_cookies:
        return findings

    for index, raw_cookie in enumerate(raw_cookies, start=1):
        cookie = SimpleCookie()

        try:
            cookie.load(raw_cookie)
        except Exception:
            findings.append(
                Finding(
                    id=f"cookie-parse-error-{index}",
                    title="Cookie Could Not Be Parsed",
                    severity=Severity.INFO,
                    description=(
                        "A Set-Cookie header was present but could not "
                        "be parsed reliably by the scanner."
                    ),
                    evidence=raw_cookie,
                    recommendation=(
                        "Review the cookie syntax and ensure it conforms "
                        "to the expected HTTP cookie format."
                    ),
                    url=str(response.url),
                    category="cookies",
                )
            )
            continue

        for name, morsel in cookie.items():
            cookie_name = name

            secure = bool(morsel["secure"])
            httponly = bool(morsel["httponly"])
            samesite = morsel["samesite"].strip().lower()

            if not secure:
                findings.append(
                    Finding(
                        id=f"cookie-missing-secure-{index}",
                        title="Cookie Missing Secure Attribute",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Cookie '{cookie_name}' does not include "
                            "the Secure attribute."
                        ),
                        evidence=raw_cookie,
                        recommendation=(
                            "Set the Secure attribute for cookies that "
                            "should only travel over HTTPS."
                        ),
                        url=str(response.url),
                        category="cookies",
                        metadata={
                            "cookie": cookie_name,
                            "attribute": "Secure",
                        },
                    )
                )

            if not httponly:
                findings.append(
                    Finding(
                        id=f"cookie-missing-httponly-{index}",
                        title="Cookie Missing HttpOnly Attribute",
                        severity=Severity.LOW,
                        description=(
                            f"Cookie '{cookie_name}' does not include "
                            "the HttpOnly attribute."
                        ),
                        evidence=raw_cookie,
                        recommendation=(
                            "Set HttpOnly for cookies that do not need "
                            "to be accessed by client-side JavaScript."
                        ),
                        url=str(response.url),
                        category="cookies",
                        metadata={
                            "cookie": cookie_name,
                            "attribute": "HttpOnly",
                        },
                    )
                )

            if not samesite:
                findings.append(
                    Finding(
                        id=f"cookie-missing-samesite-{index}",
                        title="Cookie Missing SameSite Attribute",
                        severity=Severity.LOW,
                        description=(
                            f"Cookie '{cookie_name}' does not explicitly "
                            "define a SameSite policy."
                        ),
                        evidence=raw_cookie,
                        recommendation=(
                            "Set SameSite according to the application's "
                            "cross-site requirements, preferably "
                            "Lax or Strict where appropriate."
                        ),
                        url=str(response.url),
                        category="cookies",
                        metadata={
                            "cookie": cookie_name,
                            "attribute": "SameSite",
                        },
                    )
                )

            if samesite not in {"", "lax", "strict", "none"}:
                findings.append(
                    Finding(
                        id=f"cookie-invalid-samesite-{index}",
                        title="Unrecognized SameSite Value",
                        severity=Severity.LOW,
                        description=(
                            f"Cookie '{cookie_name}' contains an "
                            f"unrecognized SameSite value: {samesite!r}."
                        ),
                        evidence=raw_cookie,
                        recommendation=(
                            "Use a valid SameSite value: Strict, Lax, or None."
                        ),
                        url=str(response.url),
                        category="cookies",
                        metadata={
                            "cookie": cookie_name,
                            "attribute": "SameSite",
                            "value": samesite,
                        },
                    )
                )

            if samesite == "none" and not secure:
                findings.append(
                    Finding(
                        id=f"cookie-samesite-none-without-secure-{index}",
                        title="SameSite=None Without Secure",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Cookie '{cookie_name}' uses SameSite=None "
                            "without the Secure attribute."
                        ),
                        evidence=raw_cookie,
                        recommendation=(
                            "Cookies using SameSite=None should also use "
                            "the Secure attribute."
                        ),
                        url=str(response.url),
                        category="cookies",
                        metadata={
                            "cookie": cookie_name,
                            "attribute": "SameSite",
                            "value": "None",
                        },
                    )
                )

    return findings
