"""Unit tests for ProxyConfig and proxy error handling."""

import pytest

from aifirewall.core.errors import AIFirewallError, ConfigurationError, ValidationError
from aifirewall.core.types import ContentDirection, ContentSource, PolicyAction
from aifirewall.models.content import ContentLocation
from aifirewall.models.event import PolicyDecision
from aifirewall.proxy.config import (
    DEFAULT_HOST,
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_PORT,
    ProxyConfig,
)
from aifirewall.proxy.errors import (
    BlockedRequestError,
    BlockedResponseError,
    PayloadTooLargeError,
    ProxyError,
    UpstreamError,
    UpstreamTimeoutError,
    create_safe_error_payload,
)
from aifirewall.proxy.models import ExtractedItem, PipelineResult


class TestProxyConfigValidation:
    """Test suite for ProxyConfig validation and security invariants."""

    def test_default_config_valid(self) -> None:
        """Verify default binding is localhost-only with conservative defaults."""
        config = ProxyConfig(upstream_url="http://127.0.0.1:9000")
        assert config.host == DEFAULT_HOST == "127.0.0.1"
        assert config.port == DEFAULT_PORT == 8080
        assert config.upstream_url == "http://127.0.0.1:9000"
        assert config.follow_redirects is False
        assert config.max_request_body_bytes == DEFAULT_MAX_REQUEST_BODY_BYTES
        assert config.max_response_body_bytes == DEFAULT_MAX_RESPONSE_BODY_BYTES
        assert config.request_inspection_enabled is True
        assert config.response_inspection_enabled is True

    def test_trailing_slash_normalized(self) -> None:
        """Upstream URL trailing slashes should be stripped for clean path joining."""
        config = ProxyConfig(upstream_url="https://api.example.com/v1///")
        assert config.upstream_url == "https://api.example.com/v1"

    def test_custom_valid_config(self) -> None:
        """Verify custom configurations within valid ranges."""
        config = ProxyConfig(
            upstream_url="https://upstream.ai.internal:8443",
            host="127.0.0.2",
            port=9090,
            connect_timeout=2.5,
            read_timeout=15.0,
            write_timeout=5.0,
            total_timeout=30.0,
            max_request_body_bytes=1024 * 1024,
            max_response_body_bytes=2 * 1024 * 1024,
            follow_redirects=True,
            allowed_http_methods=("GET", "POST"),
            request_inspection_enabled=False,
            response_inspection_enabled=False,
        )
        assert config.host == "127.0.0.2"
        assert config.port == 9090
        assert config.connect_timeout == 2.5
        assert config.allowed_http_methods == ("GET", "POST")
        assert config.follow_redirects is True
        assert config.request_inspection_enabled is False

    @pytest.mark.parametrize(
        "invalid_url",
        [
            "",
            "   ",
            "ftp://example.com",
            "file:///etc/passwd",
            "data:text/plain;base64,SGVsbG8=",
            "javascript:alert(1)",
            "http://",
            "https://",
            "example.com",
            "://missing-scheme",
        ],
    )
    def test_invalid_upstream_urls(self, invalid_url: str) -> None:
        """Reject empty, malformed, and non-http/https schemes."""
        with pytest.raises(ConfigurationError):
            ProxyConfig(upstream_url=invalid_url)

    @pytest.mark.parametrize(
        "invalid_port", [0, -1, 65536, 100000, "8080", True, False]
    )
    def test_invalid_ports(self, invalid_port: object) -> None:
        """Reject ports outside 1..65535 or non-integers."""
        with pytest.raises(ConfigurationError):
            ProxyConfig(upstream_url="http://127.0.0.1:9000", port=invalid_port)  # type: ignore[arg-type]

    @pytest.mark.parametrize("invalid_host", ["", "   ", None])
    def test_invalid_hosts(self, invalid_host: object) -> None:
        """Reject empty or non-string hosts."""
        with pytest.raises(ConfigurationError):
            ProxyConfig(upstream_url="http://127.0.0.1:9000", host=invalid_host)  # type: ignore[arg-type]

    @pytest.mark.parametrize("invalid_timeout", [0, -5.0, "10", None, True])
    def test_invalid_timeouts(self, invalid_timeout: object) -> None:
        """Reject zero, negative, or non-numeric timeouts."""
        with pytest.raises(ConfigurationError):
            ProxyConfig(
                upstream_url="http://127.0.0.1:9000",
                read_timeout=invalid_timeout,  # type: ignore[arg-type]
            )

    @pytest.mark.parametrize("invalid_limit", [0, -100, 10.5, "1024", None])
    def test_invalid_body_limits(self, invalid_limit: object) -> None:
        """Reject zero, negative, or non-integer body limits."""
        with pytest.raises(ConfigurationError):
            ProxyConfig(
                upstream_url="http://127.0.0.1:9000",
                max_request_body_bytes=invalid_limit,  # type: ignore[arg-type]
            )

    def test_reject_connect_tunneling_method(self) -> None:
        """CONNECT method must be strictly rejected from allowed methods."""
        with pytest.raises(ConfigurationError, match="CONNECT method is forbidden"):
            ProxyConfig(
                upstream_url="http://127.0.0.1:9000",
                allowed_http_methods=("GET", "POST", "CONNECT"),
            )


class TestProxyErrorsAndModels:
    """Test suite for proxy error structures and domain models."""

    def test_safe_error_payload_structure(self) -> None:
        """Verify error payload format is standard without secret disclosure."""
        payload = create_safe_error_payload(
            code="firewall_request_blocked",
            message="Request blocked by security policy.",
        )
        assert payload == {
            "error": {
                "code": "firewall_request_blocked",
                "message": "Request blocked by security policy.",
            }
        }

    def test_proxy_exception_hierarchy(self) -> None:
        """Verify all proxy exceptions inherit from AIFirewallError."""
        assert issubclass(ProxyError, AIFirewallError)
        assert issubclass(UpstreamError, ProxyError)
        assert issubclass(UpstreamTimeoutError, UpstreamError)
        assert issubclass(PayloadTooLargeError, ProxyError)
        assert issubclass(BlockedRequestError, ProxyError)
        assert issubclass(BlockedResponseError, ProxyError)

    def test_extracted_item_validation(self) -> None:
        """Verify ExtractedItem field requirements."""
        loc = ContentLocation(source=ContentSource.USER, field_path="prompt")
        item = ExtractedItem(
            item_id="item_1",
            path="prompt",
            text="Hello AI",
            location=loc,
        )
        assert item.item_id == "item_1"
        assert item.text == "Hello AI"

        with pytest.raises(ValidationError):
            ExtractedItem(item_id="", path="prompt", text="Hi", location=loc)

    def test_pipeline_result_repr_privacy(self) -> None:
        """Verify PipelineResult repr does not leak secret or body content."""
        decision = PolicyDecision(
            action=PolicyAction.BLOCK,
            reason="Blocked rule match.",
            matched_rules=["rule_1"],
            detections=[],
        )
        res = PipelineResult(
            request_id="req_123",
            direction=ContentDirection.REQUEST,
            action=PolicyAction.BLOCK,
            decision=decision,
            detection_count=1,
            transformed=False,
        )
        repr_str = repr(res)
        assert "req_123" in repr_str
        assert "block" in repr_str.lower()
        assert "sk-" not in repr_str
