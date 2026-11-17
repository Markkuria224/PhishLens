"""Heuristic URL analysis engine for PhishLens.

Performs local-only analysis of normalized URLs to identify potentially
suspicious characteristics. Operates entirely without network requests.

The analyzer extracts the normalized hostname and examines its structure,
scheme, and components to generate explainable findings.
"""

from __future__ import annotations

import ipaddress
import re
from typing import List

from phishlens.core.rules import Finding, URL_001, URL_002, URL_003, URL_004, URL_005, URL_007, URL_008, URL_009, URL_010, get_severity, KNOWN_SHORTENING_SERVICES, SUSPICIOUS_KEYWORDS, MAX_SUBDOMAINS, MAX_URL_LENGTH, MAX_HOSTNAME_LENGTH

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by rule_id using weight/severity/ordering priority.

    - Higher weight wins.
    - If weights tie, higher severity wins (HIGH > MEDIUM > LOW).
    - If both tie, preserve the first finding.
    """
    deduped: list[Finding] = []
    seen_ids: set[str] = set()
    for f in findings:
        if f.rule_id not in seen_ids:
            seen_ids.add(f.rule_id)
            deduped.append(f)
        else:
            for existing in deduped:
                if existing.rule_id == f.rule_id:
                    if f.weight > existing.weight:
                        idx = deduped.index(existing)
                        deduped[idx] = f
                    elif f.weight == existing.weight:
                        sev_rank = SEVERITY_RANK.get(f.severity, 0)
                        sev_existing_rank = SEVERITY_RANK.get(existing.severity, 0)
                        if sev_rank > sev_existing_rank:
                            idx = deduped.index(existing)
                            deduped[idx] = f
                    # If both weight and severity tie, preserve first finding
    return deduped


def analyze_url(normalized_url: str) -> list[Finding]:
    """Analyze a normalized URL for heuristic suspicious characteristics."""
    if not normalized_url:
        raise ValueError("URL cannot be empty or None")

    from urllib.parse import urlparse
    parsed = urlparse(normalized_url)

    if not parsed.hostname:
        raise ValueError("URL has no valid hostname")

    hostname = parsed.hostname or ""
    scheme = parsed.scheme.lower()
    path = parsed.path or ""
    findings: list[Finding] = []

    # URL_001: IP address used as hostname (HIGH)
    try:
        ipaddress.ip_address(hostname)
        findings.append(Finding(
            rule_id="URL_001",
            title="IP address used as hostname",
            severity="high",
            description="The hostname is an IP address, which is unusual for a regular website.",
            evidence=hostname,
            weight=2.0,
        ))
    except ValueError:
        pass

    # URL_002: HTTP instead of HTTPS (HIGH)
    if scheme == "http":
        findings.append(Finding(
            rule_id="URL_002",
            title="HTTP instead of HTTPS",
            severity="high",
            description="The URL uses HTTP instead of HTTPS, which does not encrypt traffic.",
            evidence=scheme,
            weight=2.0,
        ))

    # URL_003: Excessive subdomains (MEDIUM)
    # Skip IP addresses and localhost
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass
    if not is_ip and hostname != "localhost":
        labels = hostname.split(".")
        subdomains = max(0, len(labels) - 2)
        if subdomains > MAX_SUBDOMAINS:
            findings.append(Finding(
                rule_id="URL_003",
                title="Excessive subdomains",
                severity="medium",
                description=f"The hostname has {subdomains} subdomain(s) beyond the normal two-label domain structure.",
                evidence=hostname,
                weight=1.0,
            ))

    # URL_004: Excessive URL length (LOW)
    if len(normalized_url) > MAX_URL_LENGTH:
        findings.append(Finding(
            rule_id="URL_004",
            title="Suspiciously long URL",
            severity="low",
            description=f"The URL length ({len(normalized_url)}) exceeds the normal threshold.",
            evidence=f"URL length: {len(normalized_url)} characters",
            weight=0.5,
        ))

    # URL_005: Excessively long hostname (LOW)
    if hostname and len(hostname) > MAX_HOSTNAME_LENGTH:
        findings.append(Finding(
            rule_id="URL_005",
            title="Excessively long hostname",
            severity="low",
            description=f"The hostname length ({len(hostname)}) exceeds the normal threshold.",
            evidence=hostname,
            weight=0.5,
        ))

    # URL_007: Suspicious percent-encoding in path (MEDIUM)
    path_lower = path.lower()
    has_suspicious_encoding = any(seq in path_lower for seq in ["%2f", "%40", "%2e"])
    if has_suspicious_encoding:
        findings.append(Finding(
            rule_id="URL_007",
            title="Suspicious percent-encoding in path",
            severity="medium",
            description="The URL path contains percent-encoding sequences that may obfuscate the path structure.",
            evidence="Suspicious percent-encoding detected in URL path",
            weight=1.0,
        ))

    # URL_008: Punycode hostname (MEDIUM)
    hostname_labels = hostname.lower().split(".")
    if any(label.startswith("xn--") for label in hostname_labels):
        findings.append(Finding(
            rule_id="URL_008",
            title="Punycode hostname detection",
            severity="medium",
            description="The hostname contains Punycode encoding (xn-- prefix), often used for internationalized domain names.",
            evidence=hostname,
            weight=1.0,
        ))

    # URL_009: URL-shortening service detection (MEDIUM)
    if hostname.lower() in KNOWN_SHORTENING_SERVICES:
        findings.append(Finding(
            rule_id="URL_009",
            title="URL-shortening service detected",
            severity="medium",
            description="The hostname matches a known URL-shortening service.",
            evidence=hostname,
            weight=1.0,
        ))

    # URL_010: Suspicious hostname keywords (LOW)
    hostname_labels_lower = hostname.lower().split(".")
    if any(label in SUSPICIOUS_KEYWORDS for label in hostname_labels_lower):
        findings.append(Finding(
            rule_id="URL_010",
            title="Suspicious hostname keywords",
            severity="low",
            description="The hostname contains keywords commonly used in phishing attempts.",
            evidence=hostname,
            weight=0.5,
        ))

    return _deduplicate_findings(findings)
