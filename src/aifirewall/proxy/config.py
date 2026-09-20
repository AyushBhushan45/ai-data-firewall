"""Proxy configuration model for AI Data Firewall local reverse proxy.

Provides typed, validated configuration governing local binding, upstream targets,
timeouts, body size limits, and security inspection toggles.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from aifirewall.core.errors import ConfigurationError

DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 8080
DEFAULT_CONNECT_TIMEOUT: float = 5.0
DEFAULT_READ_TIMEOUT: float = 30.0
DEFAULT_WRITE_TIMEOUT: float = 10.0
DEFAULT_TOTAL_TIMEOUT: float = 60.0
DEFAULT_MAX_REQUEST_BODY_BYTES: int = 5 * 1024 * 1024  # 5 MB
DEFAULT_MAX_RESPONSE_BODY_BYTES: int = 10 * 1024 * 1024  # 10 MB

DEFAULT_ALLOWED_METHODS: tuple[str, ...] = (
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
)

ALLOWED_UPSTREAM_SCHEMES: frozenset[str] = frozenset({"http", "https"})


@dataclass(frozen=True)
class ProxyConfig:
    """Configuration for the local AI Data Firewall reverse proxy.

    Security Defaults:
    - Binds strictly to localhost (127.0.0.1) by default to prevent LAN exposure.
    - Upstream URL is fixed at startup; client requests cannot alter the destination.
    - Follow redirects is disabled by default to prevent unintended SSRF pivots.

    Attributes:
        upstream_url: The fixed target HTTP/HTTPS URL of the upstream AI server.
        host: Local network interface address to bind (default: 127.0.0.1).
        port: Local port number to bind (default: 8080).
        connect_timeout: Timeout in seconds for establishing upstream connections.
        read_timeout: Timeout in seconds for reading upstream responses.
        write_timeout: Timeout in seconds for writing requests upstream.
        total_timeout: Overall upstream request deadline in seconds.
        max_request_body_bytes: Maximum allowed request body size in bytes.
        max_response_body_bytes: Maximum allowed response body size in bytes.
        follow_redirects: Whether to follow upstream HTTP redirects (default: False).
        allowed_http_methods: Tuple of forwarded HTTP methods.
        request_inspection_enabled: Whether to inspect inbound requests.
        response_inspection_enabled: Whether to inspect outbound responses.
    """

    upstream_url: str
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    read_timeout: float = DEFAULT_READ_TIMEOUT
    write_timeout: float = DEFAULT_WRITE_TIMEOUT
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT
    max_request_body_bytes: int = DEFAULT_MAX_REQUEST_BODY_BYTES
    max_response_body_bytes: int = DEFAULT_MAX_RESPONSE_BODY_BYTES
    follow_redirects: bool = False
    allowed_http_methods: tuple[str, ...] = DEFAULT_ALLOWED_METHODS
    request_inspection_enabled: bool = True
    response_inspection_enabled: bool = True

    def __post_init__(self) -> None:
        """Validate proxy configuration invariants."""
        # 1. Validate upstream_url
        if not self.upstream_url or not isinstance(self.upstream_url, str):
            raise ConfigurationError("upstream_url must be a non-empty string")

        clean_url = self.upstream_url.strip()
        if not clean_url:
            raise ConfigurationError("upstream_url cannot be empty or whitespace")

        try:
            parsed = urlsplit(clean_url)
        except Exception as err:
            raise ConfigurationError(
                f"Invalid upstream_url format: {clean_url!r}"
            ) from err

        scheme = parsed.scheme.lower()
        if not scheme:
            raise ConfigurationError(
                "upstream_url must include an explicit scheme "
                f"(e.g. http:// or https://): {clean_url!r}"
            )

        if scheme not in ALLOWED_UPSTREAM_SCHEMES:
            raise ConfigurationError(
                f"Unsupported upstream_url scheme {scheme!r}. "
                "Only http and https are permitted."
            )

        if not parsed.netloc or not parsed.hostname:
            raise ConfigurationError(
                f"upstream_url must include a valid host: {clean_url!r}"
            )

        # Normalize trailing slashes on upstream_url
        normalized_upstream = clean_url.rstrip("/")
        object.__setattr__(self, "upstream_url", normalized_upstream)

        # 2. Validate host
        if not self.host or not isinstance(self.host, str) or not self.host.strip():
            raise ConfigurationError("host must be a non-empty string")

        # 3. Validate port
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ConfigurationError(
                f"port must be an integer, got {type(self.port).__name__}"
            )
        if not (1 <= self.port <= 65535):
            raise ConfigurationError(
                f"port must be between 1 and 65535, got {self.port}"
            )

        # 4. Validate timeouts
        timeouts = {
            "connect_timeout": self.connect_timeout,
            "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout,
            "total_timeout": self.total_timeout,
        }
        for name, value in timeouts.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigurationError(
                    f"{name} must be a positive number, got {type(value).__name__}"
                )
            if value <= 0:
                raise ConfigurationError(
                    f"{name} must be greater than 0, got {value}"
                )
            object.__setattr__(self, name, float(value))

        # 5. Validate body size limits
        if (
            not isinstance(self.max_request_body_bytes, int)
            or isinstance(self.max_request_body_bytes, bool)
            or self.max_request_body_bytes <= 0
        ):
            raise ConfigurationError(
                "max_request_body_bytes must be a positive integer, "
                f"got {self.max_request_body_bytes}"
            )

        if (
            not isinstance(self.max_response_body_bytes, int)
            or isinstance(self.max_response_body_bytes, bool)
            or self.max_response_body_bytes <= 0
        ):
            raise ConfigurationError(
                "max_response_body_bytes must be a positive integer, "
                f"got {self.max_response_body_bytes}"
            )

        # 6. Validate allowed_http_methods
        if not isinstance(self.allowed_http_methods, (tuple, list)):
            raise ConfigurationError(
                "allowed_http_methods must be a sequence of HTTP method strings"
            )

        normalized_methods: list[str] = []
        for m in self.allowed_http_methods:
            if not isinstance(m, str) or not m.strip():
                raise ConfigurationError(
                    "HTTP methods in allowed_http_methods must be non-empty strings"
                )
            upper_m = m.strip().upper()
            if upper_m == "CONNECT":
                raise ConfigurationError(
                    "CONNECT method is forbidden: raw TCP tunneling is not supported"
                )
            normalized_methods.append(upper_m)

        object.__setattr__(
            self, "allowed_http_methods", tuple(normalized_methods)
        )
