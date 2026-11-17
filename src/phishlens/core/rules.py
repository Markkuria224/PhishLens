"""Structured finding model and shared heuristic definitions for PhishLens."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

URL_001 = "URL_001"
URL_002 = "URL_002"
URL_003 = "URL_003"
URL_004 = "URL_004"
URL_005 = "URL_005"

URL_007 = "URL_007"
URL_008 = "URL_008"
URL_009 = "URL_009"
URL_010 = "URL_010"

RULE_SEVERITIES = {
    URL_001: SEVERITY_HIGH,
    URL_002: SEVERITY_HIGH,
    URL_003: SEVERITY_MEDIUM,
    URL_004: SEVERITY_LOW,
    URL_005: SEVERITY_LOW,

    URL_007: SEVERITY_MEDIUM,
    URL_008: SEVERITY_MEDIUM,
    URL_009: SEVERITY_MEDIUM,
    URL_010: SEVERITY_LOW,
}

KNOWN_SHORTENING_SERVICES = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "cutt.ly",
    "tiny.cc",
}

SUSPICIOUS_KEYWORDS = {
    "account",
    "authenticate",
    "banking",
    "confirm",
    "credential",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

MAX_SUBDOMAINS = 4
MAX_URL_LENGTH = 200
MAX_HOSTNAME_LENGTH = 80

def get_severity(rule_id: str) -> str:
    """Return the configured severity for a heuristic rule."""
    return RULE_SEVERITIES.get(rule_id, SEVERITY_LOW)

@dataclass(frozen=True)
class Finding:
    """A structured, explainable observation from URL analysis."""

    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id cannot be empty")
        if not self.title.strip():
            raise ValueError("title cannot be empty")
        if self.severity not in {
            SEVERITY_LOW,
            SEVERITY_MEDIUM,
            SEVERITY_HIGH,
        }:
            raise ValueError(f"Invalid severity: {self.severity}")
        if not isinstance(self.weight, (int, float)):
            raise ValueError("weight must be numeric")
        if not isfinite(self.weight) or self.weight < 0:
            raise ValueError("weight must be finite and non-negative")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "weight": self.weight,
        }
