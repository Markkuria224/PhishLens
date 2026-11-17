"""Tests for the PhishLens URL normalizer module."""

import pytest
from phishlens.core.normalizer import (
    normalize_url,
    NormalizationError,
    UnsupportedSchemeError,
    EmbeddedCredentialsError,
    InvalidHostnameError,
    MalformedPortError,
    validate_url,
)


class TestNormalizeURL:
    """Test URL normalization functionality."""

    def test_empty_input(self):
        """Empty input should raise NormalizationError."""
        with pytest.raises(NormalizationError, match="URL cannot be empty"):
            normalize_url("")

    def test_whitespace_only(self):
        """Whitespace-only input should raise NormalizationError."""
        with pytest.raises(NormalizationError):
            normalize_url("   ")

    def test_trim_whitespace(self):
        """Surrounding whitespace should be trimmed."""
        result = normalize_url("  example.com  ")
        assert result == "https://example.com"

    def test_reject_embedded_whitespace(self):
        """URL with embedded whitespace should be rejected."""
        with pytest.raises(NormalizationError, match="embedded whitespace"):
            normalize_url("example .com")

    def test_add_https_scheme(self):
        """HTTP missing scheme should get HTTPS added."""
        result = normalize_url("example.com/login")
        assert result == "https://example.com/login"

    def test_http_scheme_preserved(self):
        """HTTP scheme should be preserved."""
        result = normalize_url("http://example.com")
        assert result == "http://example.com"

    def test_uppercase_scheme(self):
        """Uppercase HTTP scheme should be preserved lowercased in hostname."""
        result = normalize_url("HTTP://EXAMPLE.COM/login")
        assert result == "http://example.com/login"

    def test_javascript_scheme_rejected(self):
        """javascript: scheme should be rejected."""
        with pytest.raises(UnsupportedSchemeError):
            normalize_url("javascript:alert(1)")

    def test_unsupported_scheme_rejected(self):
        """Unsupported schemes should be rejected."""
        with pytest.raises(UnsupportedSchemeError):
            normalize_url("ftp://example.com")

    def test_embedded_credentials_rejected(self):
        """URLs with embedded credentials should be rejected."""
        with pytest.raises(EmbeddedCredentialsError):
            normalize_url("https://user:password@example.com")

    def test_invalid_hostname_no_dot(self):
        """Hostname without a dot (except localhost) should be rejected."""
        with pytest.raises(InvalidHostnameError):
            normalize_url("http://invalid")

    def test_localhost_with_malformed_port(self):
        """Localhost with an out-of-range port should be rejected."""
        with pytest.raises(MalformedPortError):
            normalize_url("http://localhost:99999")

    def test_malformed_port(self):
        """Malformed port should be rejected."""
        with pytest.raises(MalformedPortError):
            normalize_url("https://example.com:99999")

    def test_valid_hostname(self):
        """Valid hostnames should be normalized."""
        result = normalize_url("example.com")
        assert "example.com" in result

    def test_path_preserved(self):
        """URL path should be preserved."""
        result = normalize_url("https://example.com/path/to/resource")
        assert "/path/to/resource" in result

    def test_query_preserved(self):
        """URL query should be preserved."""
        result = normalize_url("https://example.com/search?q=test")
        assert "q=test" in result

    def test_fragment_preserved(self):
        """URL fragment should be preserved."""
        result = normalize_url("https://example.com/page#section")
        assert "section" in result

    def test_localhost(self):
        """localhost should be accepted."""
        result = normalize_url("localhost:8000")
        assert result.startswith("http://localhost")

    def test_validate_url_returns_bool(self):
        """validate_url should return True for valid URLs."""
        assert validate_url("https://example.com") is True
        assert validate_url("http://example.com/path") is True

    def test_validate_url_returns_false(self):
        """validate_url should return False for invalid URLs."""
        assert validate_url("") is False
        assert validate_url("javascript:alert(1)") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

class TestNumericHostnameValidation:
    """Test strict IPv4 and ambiguous numeric hostname handling."""

    @pytest.mark.parametrize(
        "hostname",
        [
            "192.168.1.1",
            "255.255.255.255",
            "0.0.0.0",
        ],
    )
    def test_accept_valid_ipv4_addresses(self, hostname):
        result = normalize_url(f"http://{hostname}")
        assert result == f"http://{hostname}"

    @pytest.mark.parametrize(
        "hostname",
        [
            "999.999.999.999",
            "256.1.1.1",
            "192.168.1.999",
            "127.1",
            "0177.0.0.1",
            "0x7f.0.0.1",
        ],
    )
    def test_reject_invalid_or_ambiguous_numeric_hosts(self, hostname):
        with pytest.raises(InvalidHostnameError):
            normalize_url(f"http://{hostname}")
