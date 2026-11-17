"""Explainable, deterministic risk scoring for PhishLens."""

from __future__ import annotations

from typing import Any

from phishlens.core.rules import (
    Finding,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
)

RISK_THRESHOLDS = {
    "critical": (75, 100),
    "high": (50, 74),
    "moderate": (25, 49),
    "low": (0, 24),
}

SEVERITY_POINTS = {
    SEVERITY_LOW: 10,
    SEVERITY_MEDIUM: 20,
    SEVERITY_HIGH: 30,
}

def get_risk_level(score: int) -> str:
    """Classify an integer risk score between 0 and 100."""
    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError("score must be an integer")

    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")

    for level, (minimum, maximum) in RISK_THRESHOLDS.items():
        if minimum <= score <= maximum:
            return level

    raise ValueError("Unable to classify score")

def handle_empty_findings() -> dict[str, Any]:
    """Return a consistent assessment when no findings exist."""
    return {
        "score": 0,
        "level": "low",
        "findings": [],
        "explanation": (
            "No analysis findings were triggered. No suspicious "
            "characteristics were detected by the local heuristic rules. "
            "This does not guarantee that the URL is safe."
        ),
        "score_breakdown": {},
    }

def compute_score(findings: list[Finding]) -> dict[str, Any]:
    """Calculate a weighted, explainable risk score."""
    if not isinstance(findings, (list, tuple)):
        raise TypeError("findings must be a list or tuple")

    if not findings:
        return handle_empty_findings()

    if not all(isinstance(item, Finding) for item in findings):
        raise TypeError("Every item must be a Finding instance")

    unique_findings: dict[str, Finding] = {}

    for finding in findings:
        previous = unique_findings.get(finding.rule_id)

        contribution = (
            SEVERITY_POINTS[finding.severity] * finding.weight
        )

        if previous is None:
            unique_findings[finding.rule_id] = finding
            continue

        previous_contribution = (
            SEVERITY_POINTS[previous.severity] * previous.weight
        )

        if contribution > previous_contribution:
            unique_findings[finding.rule_id] = finding

    breakdown: dict[str, dict[str, Any]] = {}
    total = 0.0

    for rule_id, finding in unique_findings.items():
        contribution = (
            SEVERITY_POINTS[finding.severity] * finding.weight
        )

        breakdown[rule_id] = {
            "weight": finding.weight,
            "severity": finding.severity,
            "title": finding.title,
            "contribution": round(contribution, 2),
        }

        total += contribution

    score = min(100, round(total))
    level = get_risk_level(score)

    serialized_findings = [
        finding.to_dict()
        for finding in unique_findings.values()
    ]

    explanation = (
        f"{len(unique_findings)} unique heuristic finding(s) "
        f"contributed to a risk score of {score}/100. "
        f"The resulting risk category is {level}."
    )

    return {
        "score": score,
        "level": level,
        "findings": serialized_findings,
        "explanation": explanation,
        "score_breakdown": breakdown,
    }
