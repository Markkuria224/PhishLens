import pytest

from phishlens.core.rules import (
    Finding,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
)
from phishlens.core.scoring import (
    compute_score,
    get_risk_level,
    handle_empty_findings,
)


def make_finding(
    rule_id="URL_001",
    severity=SEVERITY_LOW,
    weight=1.0,
):
    return Finding(
        rule_id=rule_id,
        title=f"Test finding {rule_id}",
        severity=severity,
        description="Test description",
        evidence="test.example",
        weight=weight,
    )


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "low"),
        (24, "low"),
        (25, "moderate"),
        (49, "moderate"),
        (50, "high"),
        (74, "high"),
        (75, "critical"),
        (100, "critical"),
    ],
)
def test_risk_level_boundaries(score, expected):
    assert get_risk_level(score) == expected


def test_empty_findings_return_zero_score():
    result = compute_score([])

    assert result["score"] == 0
    assert result["level"] == "low"
    assert result["findings"] == []
    assert result["score_breakdown"] == {}


def test_handle_empty_findings_structure():
    result = handle_empty_findings()

    assert "score" in result
    assert "level" in result
    assert "findings" in result
    assert "explanation" in result
    assert "score_breakdown" in result
    assert isinstance(result["explanation"], str)


def test_single_finding_produces_positive_score():
    result = compute_score([make_finding()])

    assert 0 < result["score"] <= 100
    assert result["level"] == "low"


def test_high_severity_scores_more_than_low():
    low = compute_score([make_finding(severity=SEVERITY_LOW)])
    high = compute_score([make_finding(severity=SEVERITY_HIGH)])

    assert high["score"] > low["score"]


def test_weight_changes_contribution():
    normal = compute_score([make_finding(weight=1.0)])
    weighted = compute_score([make_finding(weight=2.0)])

    assert weighted["score"] > normal["score"]


def test_multiple_unique_findings_accumulate():
    findings = [
        make_finding("URL_001", SEVERITY_MEDIUM),
        make_finding("URL_002", SEVERITY_MEDIUM),
    ]

    result = compute_score(findings)

    assert result["score"] == 40
    assert len(result["findings"]) == 2
    assert len(result["score_breakdown"]) == 2


def test_duplicate_rule_ids_keep_strongest_finding():
    findings = [
        make_finding("URL_001", SEVERITY_LOW),
        make_finding("URL_001", SEVERITY_HIGH),
    ]

    result = compute_score(findings)

    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == SEVERITY_HIGH
    assert result["score"] == 30


def test_score_is_capped_at_100():
    findings = [
        make_finding(f"URL_{i}", SEVERITY_HIGH, weight=10.0)
        for i in range(1, 6)
    ]

    result = compute_score(findings)

    assert result["score"] == 100
    assert result["level"] == "critical"


def test_result_has_expected_structure():
    result = compute_score([make_finding()])

    assert isinstance(result, dict)
    assert isinstance(result["score"], int)
    assert isinstance(result["level"], str)
    assert isinstance(result["findings"], list)
    assert isinstance(result["explanation"], str)
    assert isinstance(result["score_breakdown"], dict)


def test_score_breakdown_structure():
    result = compute_score([make_finding()])
    entry = result["score_breakdown"]["URL_001"]

    assert "weight" in entry
    assert "severity" in entry
    assert "title" in entry
    assert "contribution" in entry


def test_invalid_score_type_is_rejected():
    with pytest.raises(TypeError):
        get_risk_level("75")


@pytest.mark.parametrize("score", [-1, 101])
def test_out_of_range_score_is_rejected(score):
    with pytest.raises(ValueError):
        get_risk_level(score)


def test_non_finding_input_is_rejected():
    with pytest.raises(TypeError):
        compute_score(["not a finding"])
