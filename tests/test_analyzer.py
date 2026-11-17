"""Tests for the PhishLens URL analysis engine."""

import pytest

from phishlens.core.normalizer import normalize_url
from phishlens.core.rules import Finding
from phishlens.core.analyzer import analyze_url, _deduplicate_findings


class TestAnalyzerRules:
    # URL_001: IP address as hostname
    def test_url_001_ip_hostname(self):
        findings = analyze_url("http://192.168.1.1")
        url_001_findings = [f for f in findings if f.rule_id == "URL_001"]
        assert len(url_001_findings) == 1
        findings = analyze_url("http://[::1]")
        url_001_findings = [f for f in findings if f.rule_id == "URL_001"]
        assert len(url_001_findings) == 1

    def test_url_001_normal_hostname(self):
        findings = analyze_url("http://example.com")
        url_001_findings = [f for f in findings if f.rule_id == "URL_001"]
        assert len(url_001_findings) == 0

    # URL_002: HTTP instead of HTTPS
    def test_url_002_http_scheme(self):
        findings = analyze_url("http://example.com")
        url_002_findings = [f for f in findings if f.rule_id == "URL_002"]
        assert len(url_002_findings) == 1
        findings = analyze_url("http://localhost")
        url_002_findings = [f for f in findings if f.rule_id == "URL_002"]
        assert len(url_002_findings) == 1
        findings = analyze_url("https://example.com")
        url_002_findings = [f for f in findings if f.rule_id == "URL_002"]
        assert len(url_002_findings) == 0

    # URL_003: Excessive subdomains
    def test_url_003_excessive_subdomains(self):
        findings = analyze_url("http://a.b.c.d.e.example.com")
        url_003_findings = [f for f in findings if f.rule_id == "URL_003"]
        assert len(url_003_findings) == 1
        findings = analyze_url("http://login.example.com")
        url_003_findings = [f for f in findings if f.rule_id == "URL_003"]
        assert len(url_003_findings) == 0
        findings = analyze_url("http://example.com")
        url_003_findings = [f for f in findings if f.rule_id == "URL_003"]
        assert len(url_003_findings) == 0

    # URL_004: Excessive URL length
    def test_url_004_excessive_length(self):
        long_url = "https://example.com/" + "a" * 181  # 181 chars in path > 180
        findings = analyze_url(long_url)
        url_004_findings = [f for f in findings if f.rule_id == "URL_004"]
        assert len(url_004_findings) == 1
        exact_url = "https://example.com/" + "a" * 180  # exactly 180 chars
        findings = analyze_url(exact_url)
        url_004_findings = [f for f in findings if f.rule_id == "URL_004"]
        assert len(url_004_findings) == 0

    # URL_005: Excessively long hostname
    def test_url_005_excessive_hostname(self):
        # 81-char hostname (triggers URL_005 since > 80)
        long_hostname = "a" * 40 + "." + "b" * 36
        findings = analyze_url(f"https://{long_hostname}.com")
        url_005_findings = [f for f in findings if f.rule_id == "URL_005"]
        assert len(url_005_findings) == 1
        # exactly 80-char hostname does NOT trigger
        exact_hostname = "a" * 40 + "." + "b" * 35
        findings = analyze_url(f"https://{exact_hostname}.com")
        url_005_findings = [f for f in findings if f.rule_id == "URL_005"]
        assert len(url_005_findings) == 0

    # URL_007: Suspicious percent-encoding
    def test_url_007_percent_encoding(self):
        findings = analyze_url("http://example.com/path%2Ftest")
        url_007_findings = [f for f in findings if f.rule_id == "URL_007"]
        assert len(url_007_findings) == 1
        findings = analyze_url("http://example.com/path%40test")
        url_007_findings = [f for f in findings if f.rule_id == "URL_007"]
        assert len(url_007_findings) == 1
        findings = analyze_url("http://example.com/path%2Etest")
        url_007_findings = [f for f in findings if f.rule_id == "URL_007"]
        assert len(url_007_findings) == 1
        findings = analyze_url("http://example.com/path%4Etest")
        url_007_findings = [f for f in findings if f.rule_id == "URL_007"]
        assert len(url_007_findings) == 0
        findings = analyze_url("http://example.com/path%2ftest")
        url_007_findings = [f for f in findings if f.rule_id == "URL_007"]
        assert len(url_007_findings) == 1

    # URL_008: Punycode hostname
    def test_url_008_punycode(self):
        findings = analyze_url("http://xn--bcher-kva.example.com")
        url_008_findings = [f for f in findings if f.rule_id == "URL_008"]
        assert len(url_008_findings) == 1
        findings = analyze_url("http://example.com")
        url_008_findings = [f for f in findings if f.rule_id == "URL_008"]
        assert len(url_008_findings) == 0

    # URL_009: URL-shortening service
    def test_url_009_shortener(self):
        findings = analyze_url("http://bit.ly/abc")
        url_009_findings = [f for f in findings if f.rule_id == "URL_009"]
        assert len(url_009_findings) == 1
        findings = analyze_url("http://example.com")
        url_009_findings = [f for f in findings if f.rule_id == "URL_009"]
        assert len(url_009_findings) == 0

    # URL_010: Suspicious hostname keywords
    def test_url_010_keywords(self):
        findings = analyze_url("http://banking.example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 1
        findings = analyze_url("http://payment.example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 1
        findings = analyze_url("http://example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 0

    def test_url_010_case_insensitive(self):
        findings = analyze_url("http://Banking.example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 1
        findings = analyze_url("http://BANKING.example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 1
        findings = analyze_url("http://bankingpage.example.com")
        url_010_findings = [f for f in findings if f.rule_id == "URL_010"]
        assert len(url_010_findings) == 0

    def test_multiple_findings(self):
        findings = analyze_url("http://192.168.1.1/login")
        assert len(findings) >= 2

    def test_deduplication(self):
        findings = analyze_url("http://192.168.1.1")
        rule_ids = [f.rule_id for f in findings]
        assert len(rule_ids) == len(set(rule_ids))

    def test_invalid_input(self):
        try:
            analyze_url(None)  # type: ignore
        except ValueError:
            pass
        else:
            assert False, "ValueError expected for None input"
        try:
            analyze_url("")  # type: ignore
        except ValueError:
            pass
        else:
            assert False, "ValueError expected for empty string"

    def test_duplicate_rule_ids_are_deduplicated(self):
        """Two findings with the same rule_id should produce one result."""
        f1 = Finding(rule_id="URL_001", title="dup test 1", severity="high",
                     description="dup test 1", evidence="dup1", weight=1.0)
        f2 = Finding(rule_id="URL_001", title="dup test 2", severity="low",
                     description="dup test 2", evidence="dup2", weight=2.0)
        findings = _deduplicate_findings([f1, f2])
        assert len(findings) == 1
        assert findings[0].weight == 2.0  # higher weight wins

    def test_higher_weight_wins(self):
        """When duplicate findings have different weights, retain the one with the higher weight."""
        f1 = Finding(rule_id="URL_001", title="high weight", severity="low",
                     description="high weight dup", evidence="hweight", weight=3.0)
        f2 = Finding(rule_id="URL_001", title="low weight", severity="high",
                     description="low weight dup", evidence="lweight", weight=1.0)
        findings = _deduplicate_findings([f1, f2])
        assert len(findings) == 1
        assert findings[0].weight == 3.0  # higher weight wins

    def test_higher_severity_wins_when_weights_tie(self):
        """When weights are equal, retain the finding with higher severity."""
        f1 = Finding(rule_id="URL_001", title="low severity", severity="low",
                     description="low sev dup", evidence="lowsev", weight=1.0)
        f2 = Finding(rule_id="URL_001", title="high severity", severity="high",
                     description="high sev dup", evidence="hisev", weight=1.0)
        findings = _deduplicate_findings([f1, f2])
        assert len(findings) == 1
        assert findings[0].severity == "high"  # higher severity wins when weights tie

    def test_first_finding_wins_when_weight_and_severity_tie(self):
        """When both weight and severity are equal, retain the first finding."""
        f1 = Finding(rule_id="URL_001", title="first finding", severity="medium",
                     description="first dup", evidence="first", weight=1.0)
        f2 = Finding(rule_id="URL_001", title="second finding", severity="medium",
                     description="second dup", evidence="second", weight=1.0)
        findings = _deduplicate_findings([f1, f2])
        assert len(findings) == 1
        assert findings[0].evidence == "first"  # first finding retained

    def test_different_rule_ids_preserve_order(self):
        """Findings with different rule IDs must retain their original order."""
        f1 = Finding(rule_id="URL_001", title="first", severity="high",
                     description="first", evidence="first", weight=1.0)
        f2 = Finding(rule_id="URL_002", title="second", severity="medium",
                     description="second", evidence="second", weight=1.0)
        findings = _deduplicate_findings([f1, f2])
        assert len(findings) == 2
        assert findings[0].rule_id == "URL_001"
        assert findings[1].rule_id == "URL_002"

    def test_invalid_input(self):
        try:
            analyze_url(None)  # type: ignore
        except ValueError:
            pass
        else:
            assert False, "ValueError expected for None input"
        try:
            analyze_url("")  # type: ignore
        except ValueError:
            pass
        else:
            assert False, "ValueError expected for empty string"

    def test_url_004_evidence_does_not_expose_query_data(self):
        secret = "PRIVATE_QUERY_TOKEN_92831"
        long_url = (
            "https://example.com/"
            + "a" * 170
            + f"?token={secret}"
        )

        normalized_url = normalize_url(long_url)
        findings = analyze_url(normalized_url)
        matching = [f for f in findings if f.rule_id == "URL_004"]

        assert len(matching) == 1
        assert matching[0].evidence == (
            f"URL length: {len(normalized_url)} characters"
        )
        assert secret not in matching[0].evidence
        assert "token=" not in matching[0].evidence

    def test_url_007_evidence_does_not_expose_path_data(self):
        secret = "PRIVATE_CUSTOMER_RECORD_73921"
        url = f"http://example.com/private/{secret}%2Faccount"

        normalized_url = normalize_url(url)
        findings = analyze_url(normalized_url)
        matching = [f for f in findings if f.rule_id == "URL_007"]

        assert len(matching) == 1
        assert matching[0].evidence == (
            "Suspicious percent-encoding detected in URL path"
        )
        assert secret not in matching[0].evidence
