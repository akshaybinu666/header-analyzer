"""Fetches a URL, runs every check, and computes a score."""

import re
from dataclasses import asdict
from datetime import datetime, timezone

import requests

from .checks import CHECKS, check_leaky_headers, check_cookies
from .models import SEVERITY_WEIGHT, STATUS_WARN, STATUS_MISSING, STATUS_INFO


def normalise_url(url):
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url


def analyse(url, timeout=10, verify=True, user_agent=None, follow_redirects=True):
    url = normalise_url(url)
    headers = {"User-Agent": user_agent or "HeaderAnalyzer/1.0 (security header check)"}
    resp = requests.get(url, timeout=timeout, verify=verify, headers=headers,
                        allow_redirects=follow_redirects, stream=True)
    resp.close()
    ctx = {"https": resp.url.lower().startswith("https://")}

    findings = []
    for check in CHECKS:
        f = check(resp.headers, ctx)
        if f:
            findings.append(f)
    findings.extend(check_leaky_headers(resp.headers, ctx))
    findings.extend(check_cookies(resp))

    score = 100
    for f in findings:
        if f.status in (STATUS_MISSING, STATUS_WARN, STATUS_INFO):
            score -= SEVERITY_WEIGHT[f.severity]
    score = max(0, score)

    return {
        "requested_url": url,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score": score,
        "grade": grade(score),
        "findings": [asdict(f) for f in findings],
    }


def grade(score):
    for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return letter
    return "F"
