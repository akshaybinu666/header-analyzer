from requests.structures import CaseInsensitiveDict

from header_analyzer import checks
from header_analyzer.models import STATUS_MISSING, STATUS_PASS, STATUS_WARN

HTTPS = {"https": True}
HTTP = {"https": False}


def H(**kw):
    return CaseInsensitiveDict({k.replace("_", "-"): v for k, v in kw.items()})


# --- HSTS -------------------------------------------------------------
def test_hsts_missing():
    assert checks.check_hsts(H(), HTTPS).status == STATUS_MISSING


def test_hsts_good():
    f = checks.check_hsts(H(Strict_Transport_Security="max-age=31536000; includeSubDomains"), HTTPS)
    assert f.status == STATUS_PASS


def test_hsts_short_max_age():
    f = checks.check_hsts(H(Strict_Transport_Security="max-age=300; includeSubDomains"), HTTPS)
    assert f.status == STATUS_WARN and "too short" in f.issue


def test_hsts_over_http_is_flagged():
    assert checks.check_hsts(H(), HTTP).status == STATUS_WARN


# --- CSP --------------------------------------------------------------
def test_csp_missing():
    f = checks.check_csp(H(), HTTPS)
    assert f.status == STATUS_MISSING and f.severity == "high"


def test_csp_unsafe_inline():
    f = checks.check_csp(H(Content_Security_Policy="default-src 'self'; script-src 'unsafe-inline'"), HTTPS)
    assert f.status == STATUS_WARN and "unsafe-inline" in f.issue


def test_csp_nonce_allows_inline():
    csp = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'; "
           "object-src 'none'; base-uri 'self'; frame-ancestors 'self'")
    assert checks.check_csp(H(Content_Security_Policy=csp), HTTPS).status == STATUS_PASS


def test_csp_strong_policy_passes():
    csp = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    assert checks.check_csp(H(Content_Security_Policy=csp), HTTPS).status == STATUS_PASS


# --- Simple headers ---------------------------------------------------
def test_xcto():
    assert checks.check_xcto(H(), HTTPS).status == STATUS_MISSING
    assert checks.check_xcto(H(X_Content_Type_Options="nosniff"), HTTPS).status == STATUS_PASS
    assert checks.check_xcto(H(X_Content_Type_Options="foo"), HTTPS).status == STATUS_WARN


def test_xfo_satisfied_by_csp_frame_ancestors():
    f = checks.check_xfo(H(Content_Security_Policy="frame-ancestors 'none'"), HTTPS)
    assert f.status == STATUS_PASS


def test_xfo_invalid_value():
    assert checks.check_xfo(H(X_Frame_Options="ALLOW-FROM x"), HTTPS).status == STATUS_WARN


def test_referrer_unsafe_url():
    assert checks.check_referrer(H(Referrer_Policy="unsafe-url"), HTTPS).status == STATUS_WARN
    assert checks.check_referrer(H(Referrer_Policy="no-referrer"), HTTPS).status == STATUS_PASS


def test_xss_protection_legacy_only_flagged_when_enabled():
    assert checks.check_xss_protection(H(X_XSS_Protection="1; mode=block"), HTTPS).status == STATUS_WARN
    assert checks.check_xss_protection(H(X_XSS_Protection="0"), HTTPS) is None
    assert checks.check_xss_protection(H(), HTTPS) is None


def test_leaky_headers_only_when_version_exposed():
    assert checks.check_leaky_headers(H(Server="nginx"), HTTPS) == []
    out = checks.check_leaky_headers(H(Server="nginx/1.18.0", X_Powered_By="PHP/7.4"), HTTPS)
    assert {f.header for f in out} == {"Server", "X-Powered-By"}


def test_csp_multiple_headers_comma_joined():
    # Real-world case: two CSP headers get merged into one comma-separated string.
    csp = ("require-trusted-types-for 'script', base-uri 'self';object-src 'none';"
           "frame-ancestors 'self';script-src 'nonce-abc' 'strict-dynamic'")
    assert checks.check_csp(H(Content_Security_Policy=csp), HTTPS).status == STATUS_PASS
