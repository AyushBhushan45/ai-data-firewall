"""Utility functions for safe representations and formatting.

Provides centralized helpers for:
- URL sanitization for user-facing displays and logs (scrubbing userinfo and secrets).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

# Sensitive query parameter key substrings (lowercased)
_SENSITIVE_PARAM_SUBSTRINGS = (
    "key",
    "token",
    "secret",
    "auth",
    "password",
    "passwd",
    "pwd",
    "credential",
    "sig",
    "signature",
    "session",
    "jwt",
    "bearer",
    "private",
)

# Common regex pattern for high-entropy secret-like query parameter values
_SECRET_VALUE_PATTERN = re.compile(
    r"^(sk-[a-zA-Z0-9_\-]{16,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+.*|AIza[0-9A-Za-z\-_]{20,})$"
)


def sanitize_url_for_display(url: str | None) -> str:
    """Sanitize a URL for safe user-facing display and logging.

    Guarantees:
    - Userinfo credentials (username:password@) are replaced with `[REDACTED]@`.
    - Sensitive query parameters (containing key, token, secret, auth, etc.) have
      their values replaced with `[REDACTED]`.
    - Any query parameter value matching known secret patterns is redacted.
    - Malformed URLs fail safely without raising exceptions or leaking raw strings.

    Args:
        url: The raw URL string to sanitize.

    Returns:
        A sanitized URL string safe for console output, logs, and error messages.
    """
    if not url or not isinstance(url, str):
        return ""

    raw_url = url.strip()
    if not raw_url:
        return ""

    try:
        parsed = urlsplit(raw_url)
    except Exception:
        return "[MALFORMED_URL]"

    # 1. Sanitize userinfo in netloc (username / password)
    netloc = parsed.netloc
    if "@" in netloc:
        # Netloc contains userinfo before the last '@'
        _, _, host_port = netloc.rpartition("@")
        netloc = f"[REDACTED]@{host_port}"

    # 2. Sanitize query string parameters
    query = parsed.query
    if query:
        sanitized_pairs: list[str] = []
        for key, val in parse_qsl(query, keep_blank_values=True):
            lower_key = key.lower()
            is_sensitive_key = any(
                sub in lower_key for sub in _SENSITIVE_PARAM_SUBSTRINGS
            )
            is_secret_val = bool(_SECRET_VALUE_PATTERN.match(val))

            if is_sensitive_key or is_secret_val:
                sanitized_pairs.append(f"{quote(key)}=[REDACTED]")
            else:
                sanitized_pairs.append(f"{quote(key)}={quote(val)}")
        query = "&".join(sanitized_pairs)

    sanitized = urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
    return sanitized
