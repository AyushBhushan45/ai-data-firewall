"""Upstream HTTP client for forwarding requests to the fixed target destination.

Security Guarantees:
- Strict SSRF protection: Target host is fixed to `config.upstream_url`.
- Hop-by-hop transport headers are stripped before forwarding.
- Authorization headers are forwarded if present, but NEVER logged or persisted.
- Upstream timeouts and connection errors are translated into safe proxy exceptions.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    PayloadTooLargeError,
    UpstreamError,
    UpstreamTimeoutError,
)

# Standard hop-by-hop headers defined in RFC 2616 and RFC 7230
HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)


@dataclass(frozen=True)
class UpstreamResponse:
    """Encapsulates the response received from the upstream AI server.

    Attributes:
        status_code: HTTP response status code from upstream.
        headers: Filtered upstream response headers.
        body: Raw response bytes.
    """

    status_code: int
    headers: dict[str, str]
    body: bytes


class UpstreamClient:
    """Manages an asynchronous HTTP connection pool to the fixed upstream server."""

    def __init__(self, config: ProxyConfig) -> None:
        """Initialize with validated ProxyConfig.

        Args:
            config: ProxyConfig defining upstream_url, timeouts, and body limits.
        """
        self._config = config
        self._client: httpx.AsyncClient | None = None

    @property
    def is_running(self) -> bool:
        """Check if the internal HTTP client pool is initialized."""
        return self._client is not None

    async def start(self) -> None:
        """Initialize the long-lived async HTTP connection pool."""
        if self._client is None:
            timeout = httpx.Timeout(
                connect=self._config.connect_timeout,
                read=self._config.read_timeout,
                write=self._config.write_timeout,
                pool=self._config.total_timeout,
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=self._config.follow_redirects,
                http2=False,
            )

    async def close(self) -> None:
        """Close all open connections in the client pool."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def forward(
        self,
        method: str,
        path: str,
        query_string: str,
        headers: Mapping[str, str],
        body: bytes,
    ) -> UpstreamResponse:
        """Forward an HTTP request to the fixed upstream target.

        Args:
            method: HTTP verb (GET, POST, etc.).
            path: Target request path (e.g. '/v1/chat/completions').
            query_string: Raw URL query string without leading '?'.
            headers: Incoming request headers.
            body: Request body bytes (potentially redacted).

        Returns:
            An UpstreamResponse containing status, headers, and body bytes.

        Raises:
            UpstreamTimeoutError: If upstream connection or response times out.
            UpstreamError: If upstream encounters network, DNS, or TLS failures.
            PayloadTooLargeError: If upstream response exceeds max_response_body_bytes.
        """
        if self._client is None:
            await self.start()
        assert self._client is not None

        # Build target URL strictly using the fixed configured upstream base
        target_url = self._build_target_url(path, query_string)

        # Filter out hop-by-hop headers
        forward_headers = self._sanitize_request_headers(headers)

        try:
            response = await self._client.request(
                method=method,
                url=target_url,
                headers=forward_headers,
                content=body,
            )
            response_body = response.content
        except httpx.TimeoutException as err:
            raise UpstreamTimeoutError(
                "Upstream request timed out while communicating with target server."
            ) from err
        except (httpx.ConnectError, httpx.NetworkError, httpx.ProtocolError) as err:
            raise UpstreamError(
                "Upstream server is unreachable or returned an invalid "
                "network response."
            ) from err
        except Exception as err:
            raise UpstreamError(
                f"Failed to communicate with upstream server: {type(err).__name__}"
            ) from err

        # Enforce max response body size
        if len(response_body) > self._config.max_response_body_bytes:
            raise PayloadTooLargeError(
                "Upstream response body exceeded configured limit of "
                f"{self._config.max_response_body_bytes} bytes."
            )

        sanitized_resp_headers = self._sanitize_response_headers(
            response.headers, len(response_body)
        )

        return UpstreamResponse(
            status_code=response.status_code,
            headers=sanitized_resp_headers,
            body=response_body,
        )

    def _build_target_url(self, path: str, query_string: str) -> str:
        """Construct upstream target URL from fixed base and relative path."""
        base = self._config.upstream_url
        clean_path = "/" + path.lstrip("/") if path else ""
        url = f"{base}{clean_path}"
        if query_string:
            clean_query = query_string.lstrip("?")
            url = f"{url}?{clean_query}"
        return url

    @staticmethod
    def _sanitize_request_headers(
        headers: Mapping[str, str],
    ) -> dict[str, str]:
        """Strip hop-by-hop and client-controlled proxy routing headers."""
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            lower_k = key.strip().lower()
            if lower_k in HOP_BY_HOP_HEADERS:
                continue
            # Drop user-supplied target override headers (anti-SSRF / anti-open-proxy)
            if lower_k.startswith("x-target") or lower_k.startswith("x-upstream"):
                continue
            sanitized[key] = value
        return sanitized

    @staticmethod
    def _sanitize_response_headers(
        headers: Mapping[str, Any], body_length: int
    ) -> dict[str, str]:
        """Strip hop-by-hop headers from upstream response and fix Content-Length."""
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            lower_k = key.strip().lower()
            if lower_k in HOP_BY_HOP_HEADERS:
                continue
            sanitized[key] = str(value)
        sanitized["content-length"] = str(body_length)
        return sanitized
