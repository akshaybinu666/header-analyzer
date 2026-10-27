"""Individual security-header checks.

Each ``check_*`` function receives the response headers (a case-insensitive
mapping) and a context dict, and returns a ``Finding`` (or ``None`` if the
check does not apply).
"""

import re

from .models import (Finding, STATUS_PASS, STATUS_WARN, STATUS_MISSING, STATUS_INFO)


def check_hsts(h, ctx):
    name = "Strict-Transport-Security"
    fix = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    if not ctx["https"]:
        return Finding(name, STATUS_WARN, "high", "", 
                       "Site was reached over plain HTTP (or redirected to it); HSTS only works over HTTPS.",
                       "Serve the site over HTTPS and redirect all HTTP traffic to it, then add HSTS.")
    value = h.get(name)
    if not value:
        return Finding(name, STATUS_MISSING, "high", "",
                       "HSTS is missing, so browsers may connect over HTTP and are exposed to downgrade/MITM attacks.",
                       fix)
    problems = []
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    if not m:
        problems.append("no valid max-age directive")
    elif int(m.group(1)) < 15552000:  # 180 days
        problems.append(f"max-age={m.group(1)} is too short (recommend >= 31536000)")
    if "includesubdomains" not in value.lower():
        problems.append("missing includeSubDomains")
    if problems:
        # Only a missing includeSubDomains (max-age is fine) is a recommendation, not a flaw.
        sev = "low" if problems == ["missing includeSubDomains"] else "medium"
        return Finding(name, STATUS_WARN, sev, value, "; ".join(problems) + ".", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")
    
def check_csp(h, ctx):
    name = "Content-Security-Policy"
    fix = ("Define a policy, e.g.: Content-Security-Policy: default-src 'self'; "
           "object-src 'none'; base-uri 'self'; frame-ancestors 'self'. "
           "Use nonces/hashes instead of 'unsafe-inline'.")
    value = h.get(name)
    if not value:
        report_only = h.get("Content-Security-Policy-Report-Only")
        extra = " A Report-Only policy exists but does not enforce anything." if report_only else ""
        return Finding(name, STATUS_MISSING, "high", "",
                       "No CSP, so the browser has no second line of defence against XSS and data injection." + extra,
                       fix)
    directives = {}
    # Several CSP headers are joined with commas by HTTP clients; each is its own policy.
    for policy in value.split(","):
        for part in policy.split(";"):
            bits = part.strip().split()
            if bits:
                directives.setdefault(bits[0].lower(), bits[1:])
    problems = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src and not any(
            s.startswith("'nonce-") or s.startswith("'sha") for s in script_src):
        problems.append("script policy allows 'unsafe-inline'")
    if "'unsafe-eval'" in script_src:
        problems.append("script policy allows 'unsafe-eval'")
    # With 'strict-dynamic', browsers ignore host/scheme allowlists, so they are harmless.
    strict_dynamic = "'strict-dynamic'" in script_src
    if not strict_dynamic and any(s in ("*", "http:", "https:", "data:") for s in script_src):
        problems.append("script policy uses an overly broad source (*, http:, https:, data:)")
    if "default-src" not in directives and "script-src" not in directives:
        problems.append("no default-src or script-src directive")
    if "object-src" not in directives and "default-src" not in directives:
        problems.append("object-src not restricted")
    if "frame-ancestors" not in directives:
        problems.append("no frame-ancestors (clickjacking protection relies on X-Frame-Options)")
    if "base-uri" not in directives:
        problems.append("no base-uri directive")
    if problems:
        sev = "high" if any("unsafe-inline" in p or "broad" in p or "no default" in p for p in problems) else "medium"
        return Finding(name, STATUS_WARN, sev, value, "; ".join(problems) + ".", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")


def check_xfo(h, ctx):
    name = "X-Frame-Options"
    value = h.get(name)
    csp = h.get("Content-Security-Policy", "")
    has_fa = "frame-ancestors" in csp.lower()
    fix = "Add: X-Frame-Options: DENY (or SAMEORIGIN), and/or CSP 'frame-ancestors'."
    if not value:
        if has_fa:
            return Finding(name, STATUS_PASS, "info", "",
                           "Not set, but CSP frame-ancestors provides clickjacking protection.", "")
        return Finding(name, STATUS_MISSING, "medium", "",
                       "No clickjacking protection; the page can be embedded in a malicious iframe.", fix)
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(name, STATUS_WARN, "medium", value,
                       "Invalid or obsolete value (ALLOW-FROM is no longer supported by browsers).", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")


def check_xcto(h, ctx):
    name = "X-Content-Type-Options"
    value = h.get(name)
    fix = "Add: X-Content-Type-Options: nosniff"
    if not value:
        return Finding(name, STATUS_MISSING, "medium", "",
                       "Browsers may MIME-sniff responses, enabling some XSS and content-confusion attacks.", fix)
    if value.strip().lower() != "nosniff":
        return Finding(name, STATUS_WARN, "medium", value, "Value should be exactly 'nosniff'.", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")


def check_referrer(h, ctx):
    name = "Referrer-Policy"
    value = h.get(name)
    fix = "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)"
    if not value:
        return Finding(name, STATUS_MISSING, "low", "",
                       "Full URLs (possibly containing tokens or IDs) may leak to other sites via the Referer header.", fix)
    unsafe = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
    tokens = [t.strip().lower() for t in value.split(",")]
    if tokens[-1] in unsafe:
        return Finding(name, STATUS_WARN, "low", value,
                       f"'{tokens[-1]}' can leak full URLs to third parties.", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")


def check_permissions(h, ctx):
    name = "Permissions-Policy"
    value = h.get(name) or h.get("Feature-Policy")
    fix = "Add: Permissions-Policy: camera=(), microphone=(), geolocation=() (allow only what you use)"
    if not h.get(name):
        if value:
            return Finding(name, STATUS_WARN, "low", value,
                           "Only the deprecated Feature-Policy header is set.", fix)
        return Finding(name, STATUS_MISSING, "low", "",
                       "Powerful browser features (camera, mic, geolocation) are not explicitly restricted.", fix)
    return Finding(name, STATUS_PASS, "info", value, "Present.", "")


def check_coop(h, ctx):
    name = "Cross-Origin-Opener-Policy"
    value = h.get(name)
    fix = "Add: Cross-Origin-Opener-Policy: same-origin"
    if not value:
        return Finding(name, STATUS_MISSING, "low", "",
                       "Pages opened cross-origin keep a reference to this window, enabling some side-channel attacks.", fix)
    if value.strip().lower() == "unsafe-none":
        return Finding(name, STATUS_WARN, "low", value, "'unsafe-none' disables isolation.", fix)
    return Finding(name, STATUS_PASS, "info", value, "Properly configured.", "")


def check_corp(h, ctx):
    name = "Cross-Origin-Resource-Policy"
    value = h.get(name)
    fix = "Add: Cross-Origin-Resource-Policy: same-origin (or same-site)"
    if not value:
        return Finding(name, STATUS_MISSING, "low", "",
                       "Other origins can load this site's resources, aiding Spectre-style leaks.", fix)
    if value.strip().lower() not in ("same-origin", "same-site", "cross-origin"):
        return Finding(name, STATUS_WARN, "low", value, "Unrecognised value.", fix)
    return Finding(name, STATUS_PASS, "info", value, "Present.", "")


def check_coep(h, ctx):
    name = "Cross-Origin-Embedder-Policy"
    value = h.get(name)
    fix = "Add: Cross-Origin-Embedder-Policy: require-corp (only if you need cross-origin isolation)"
    if not value:
        return Finding(name, STATUS_MISSING, "info", "",
                       "Not set. Only required if you need cross-origin isolation (e.g. SharedArrayBuffer).", fix)
    return Finding(name, STATUS_PASS, "info", value, "Present.", "")


def check_xss_protection(h, ctx):
    name = "X-XSS-Protection"
    value = h.get(name)
    if value and value.strip().startswith("1"):
        return Finding(name, STATUS_WARN, "low", value,
                       "Legacy XSS auditor is deprecated and can introduce vulnerabilities in old browsers.",
                       "Set 'X-XSS-Protection: 0' or remove it, and rely on CSP instead.")
    return None


def check_leaky_headers(h, ctx):
    findings = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"):
        value = h.get(name)
        if not value:
            continue
        # Server: "nginx" alone is low-risk; flag when a version number is exposed.
        has_version = bool(re.search(r"\d+(\.\d+)+", value))
        if name == "Server" and not has_version:
            continue
        findings.append(Finding(
            name, STATUS_INFO, "low" if has_version else "info", value,
            "Discloses server/framework technology" + (" and version" if has_version else "") +
            ", which helps attackers target known vulnerabilities.",
            f"Remove or genericise the {name} header in your web server / framework config."))
    return findings


def check_cookies(response):
    """Inspect Set-Cookie headers (uses raw headers to handle multiple cookies)."""
    findings = []
    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw_cookies = []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        problems = []
        if "secure" not in flags and response.url.startswith("https"):
            problems.append("missing Secure")
        if "httponly" not in flags:
            problems.append("missing HttpOnly")
        if "samesite" not in flags:
            problems.append("missing SameSite")
        elif "samesite=none" in flags and "secure" not in flags:
            problems.append("SameSite=None without Secure")
        if problems:
            # Never put the cookie value in reports: it may be a live session token.
            attrs = raw.split(";", 1)[1].strip() if ";" in raw else ""
            shown = f"{name}=<redacted>" + (f"; {attrs}" if attrs else "")
            findings.append(Finding(
                f"Set-Cookie ({name})", STATUS_WARN, "medium", shown[:120],
                "Cookie " + ", ".join(problems) + ".",
                "Set cookies with: Secure; HttpOnly; SameSite=Lax (or Strict)."))
    return findings


CHECKS = [check_hsts, check_csp, check_xfo, check_xcto, check_referrer, check_permissions,
          check_coop, check_corp, check_coep, check_xss_protection]
