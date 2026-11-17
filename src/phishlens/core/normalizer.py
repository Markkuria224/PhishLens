"""Local URL normalization and validation for PhishLens."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

class NormalizationError(ValueError):
    """Raised when URL normalization fails."""

class UnsupportedSchemeError(NormalizationError):
    """Raised when a URL uses an unsupported scheme."""

class EmbeddedCredentialsError(NormalizationError):
    """Raised when a URL contains embedded credentials."""

class InvalidHostnameError(NormalizationError):
    """Raised when a URL contains an invalid hostname."""

class MalformedPortError(NormalizationError):
    """Raised when a URL contains a malformed port."""

def _validate_hostname(hostname: str) -> str:
    """Validate a hostname and return its lowercase ASCII form."""
    if not hostname:
        raise InvalidHostnameError("URL has no hostname")

    try:
        ip = ipaddress.ip_address(hostname)
        return str(ip)
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidHostnameError("Hostname contains invalid characters") from exc

    # Reject ambiguous numeric hosts that browsers may interpret as IPv4.
    last_label = ascii_hostname.rstrip(".").rsplit(".", 1)[-1]

    decimal_numeric = last_label.isascii() and last_label.isdigit()
    hexadecimal_numeric = (
        last_label.startswith("0x")
        and all(character in "0123456789abcdef" for character in last_label[2:])
    )

    if decimal_numeric or hexadecimal_numeric:
        raise InvalidHostnameError(
            f"Hostname '{hostname}' is an invalid or ambiguous numeric address"
        )

    if ascii_hostname == "localhost":
        return ascii_hostname

    if len(ascii_hostname) > 253:
        raise InvalidHostnameError("Hostname is too long")

    labels = ascii_hostname.rstrip(".").split(".")

    if len(labels) < 2 or any(not label for label in labels):
        raise InvalidHostnameError(
            f"Hostname '{hostname}' is not a valid domain name"
        )

    for label in labels:
        if len(label) > 63:
            raise InvalidHostnameError("Hostname label is too long")

        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
            label,
        ):
            raise InvalidHostnameError(
                f"Hostname '{hostname}' contains invalid characters"
            )

    return ascii_hostname

def normalize_url(raw_url: str) -> str:
    """Normalize and validate a URL without making network requests."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise NormalizationError("URL cannot be empty")

    url = raw_url.strip()

    if any(character.isspace() for character in url):
        raise NormalizationError("URL contains embedded whitespace")

    # Identify explicit schemes without confusing host:port with a scheme.
    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", url)

    if url.startswith("//"):
        url = "https:" + url

    elif scheme_match:
        candidate_scheme = scheme_match.group(1).lower()
        remainder = url[scheme_match.end():]

        has_explicit_http_authority = (
            candidate_scheme in ("http", "https")
            and remainder.startswith("//")
        )

        looks_like_host_port = (
            candidate_scheme == "localhost"
            or "." in candidate_scheme
            or candidate_scheme.startswith("[")
        )

        if not has_explicit_http_authority and not looks_like_host_port:
            raise UnsupportedSchemeError(
                f"URL scheme '{candidate_scheme}' is not supported"
            )

        if not has_explicit_http_authority:
            url = ("http://" if candidate_scheme == "localhost" else "https://") + url

    else:
        if re.match(r"^localhost(?::\d+)?(?:[/\?#]|$)", url, re.IGNORECASE):
            url = "http://" + url
        else:
            url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise UnsupportedSchemeError(
                f"URL scheme '{parsed.scheme}' is not supported"
            )

        if not parsed.netloc:
            raise InvalidHostnameError("URL has no valid hostname")

        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise EmbeddedCredentialsError(
                "URL contains embedded credentials"
            )

        hostname = parsed.hostname

        if hostname is None:
            raise InvalidHostnameError("URL has no valid hostname")

        normalized_hostname = _validate_hostname(hostname)

        try:
            port = parsed.port
        except ValueError as exc:
            raise MalformedPortError(f"Invalid URL port: {exc}") from exc

        if port is not None and not 0 <= port <= 65535:
            raise MalformedPortError(
                f"URL port {port} is outside the valid range (0-65535)"
            )

        # Rebuild the authority while preserving the port.
        if ":" in normalized_hostname:
            normalized_netloc = f"[{normalized_hostname}]"
        else:
            normalized_netloc = normalized_hostname

        if port is not None:
            normalized_netloc += f":{port}"

        return urllib.parse.urlunparse((
            parsed.scheme.lower(),
            normalized_netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        ))

    except NormalizationError:
        raise
    except ValueError as exc:
        raise NormalizationError(f"Invalid URL: {exc}") from exc

def validate_url(raw_url: str) -> bool:
    """Return True if the input can be normalized, otherwise False."""
    try:
        normalize_url(raw_url)
        return True
    except (NormalizationError, TypeError, ValueError):
        return False
