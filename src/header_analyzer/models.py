"""Shared constants and data models."""

from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SEVERITY_WEIGHT = {"high": 20, "medium": 10, "low": 3, "info": 0}

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"   # present but misconfigured
STATUS_MISSING = "MISSING"
STATUS_INFO = "INFO"   # informational (e.g. information leakage)


@dataclass
class Finding:
    header: str
    status: str
    severity: str
    value: str
    issue: str
    remediation: str
