"""Proxy-specific exception hierarchy and safe error response builders.

Privacy Rule: Proxy error messages and payload responses must NEVER expose
raw secrets, credentials, full upstream response bodies, or Authorization tokens.
"""

from typing import Any

from aifirewall.core.errors import AIFirewallError

# Standard HTTP status codes used by the firewall
HTTP_STATUS_BAD_REQUEST = 400
HTTP_STATUS_FORBIDDEN = 403
HTTP_STATUS_NOT_FOUND = 404
HTTP_STATUS_METHOD_NOT_ALLOWED = 405
HTTP_STATUS_PAYLOAD_TOO_LARGE = 413
HTTP_STATUS_INTERNAL_SERVER_ERROR = 500
HTTP_STATUS_BAD_GATEWAY = 502
HTTP_STATUS_GATEWAY_TIMEOUT = 504

# Standard error codes
ERR_REQUEST_BLOCKED = "firewall_request_blocked"
ERR_RESPONSE_BLOCKED = "firewall_response_blocked"
ERR_PAYLOAD_TOO_LARGE = "payload_too_large"
ERR_UPSTREAM_UNAVAILABLE = "upstream_unavailable"
ERR_UPSTREAM_TIMEOUT = "upstream_timeout"
ERR_METHOD_NOT_ALLOWED = "method_not_allowed"
ERR_INVALID_REQUEST = "invalid_request"
ERR_INTERNAL_ERROR = "firewall_internal_error"


class ProxyError(AIFirewallError):
    """Base class for all proxy-related runtime errors."""


class UpstreamError(ProxyError):
    """Raised when the upstream service encounters a network, DNS, or TLS failure."""

    def __init__(
        self, message: str, status_code: int = HTTP_STATUS_BAD_GATEWAY
    ) -> None:
        super().__init__(message)
        self.status_code = status_code


class UpstreamTimeoutError(UpstreamError):
    """Raised when an upstream request times out (connect, read, or total)."""

    def __init__(self, message: str = "Upstream request timed out.") -> None:
        super().__init__(message, status_code=HTTP_STATUS_GATEWAY_TIMEOUT)


class PayloadTooLargeError(ProxyError):
    """Raised when a request or response body exceeds the configured maximum bytes."""

    def __init__(
        self,
        message: str,
        status_code: int = HTTP_STATUS_PAYLOAD_TOO_LARGE,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code


class BlockedRequestError(ProxyError):
    """Raised when an inbound request is blocked by security policy."""

    def __init__(
        self,
        reason: str = "Request blocked by security policy.",
        status_code: int = HTTP_STATUS_FORBIDDEN,
    ) -> None:
        super().__init__(reason)
        self.status_code = status_code


class BlockedResponseError(ProxyError):
    """Raised when an outbound upstream response is blocked by security policy."""

    def __init__(
        self,
        reason: str = "Response blocked by security policy.",
        status_code: int = HTTP_STATUS_BAD_GATEWAY,
    ) -> None:
        super().__init__(reason)
        self.status_code = status_code


def create_safe_error_payload(code: str, message: str) -> dict[str, Any]:
    """Generate a standardized, machine-readable safe error dictionary.

    Security Rule: This payload MUST NOT contain raw secrets, tracebacks,
    Authorization tokens, or internal filesystem paths.

    Args:
        code: Machine-readable error code string (e.g. 'firewall_request_blocked').
        message: Safe human-readable explanation for clients.

    Returns:
        Structured dictionary adhering to `{"error": {"code": ..., "message": ...}}`.
    """
    return {
        "error": {
            "code": str(code),
            "message": str(message),
        }
    }
