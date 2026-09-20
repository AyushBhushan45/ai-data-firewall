"""Unit tests for the security pipeline and upstream client components."""

import json

import pytest

from aifirewall.core.types import DetectionCategory, PolicyAction, Severity
from aifirewall.detectors.secret import SecretDetector
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyRule
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    BlockedRequestError,
    BlockedResponseError,
    PayloadTooLargeError,
)
from aifirewall.proxy.pipeline import DetectorRegistry, SecurityPipeline
from aifirewall.proxy.upstream import UpstreamClient


class TestDetectorRegistry:
    """Test suite for DetectorRegistry."""

    def test_default_registry_has_secret_detector(self) -> None:
        """Verify default initialization contains SecretDetector."""
        reg = DetectorRegistry()
        assert len(reg.detectors) == 1
        assert isinstance(reg.detectors[0], SecretDetector)


class TestSecurityPipeline:
    """Test suite for SecurityPipeline enforcement across requests and responses."""

    @pytest.fixture
    def test_config(self) -> ProxyConfig:
        return ProxyConfig(
            upstream_url="http://127.0.0.1:9000",
            max_request_body_bytes=1024,
            max_response_body_bytes=1024,
        )

    def test_clean_request_allowed(self, test_config: ProxyConfig) -> None:
        """Inbound request without sensitive content is permitted unmodified."""
        pipeline = SecurityPipeline(config=test_config)
        body = json.dumps({"prompt": "Tell me a joke"}).encode("utf-8")
        out_body, result = pipeline.process_request(
            raw_body=body,
            content_type_header="application/json",
            request_id="req_clean",
        )
        assert out_body == body
        assert result.action == PolicyAction.ALLOW
        assert result.transformed is False
        assert result.detection_count == 0

    def test_secret_request_blocked(self, test_config: ProxyConfig) -> None:
        """Inbound request with secret matching BLOCK raises BlockedRequestError."""
        block_rule = PolicyRule(
            rule_id="block_secrets",
            action=PolicyAction.BLOCK,
            category=DetectionCategory.SECRET,
            minimum_severity=Severity.HIGH,
        )
        engine = PolicyEngine(PolicyConfig(rules=[block_rule]))
        pipeline = SecurityPipeline(config=test_config, policy_engine=engine)

        body = json.dumps({"prompt": "My key is sk-1234567890abcdef12345678"}).encode(
            "utf-8"
        )
        with pytest.raises(BlockedRequestError) as exc_info:
            pipeline.process_request(
                raw_body=body,
                content_type_header="application/json",
                request_id="req_block",
            )
        assert exc_info.value.status_code == 403
        assert "Blocked" in str(exc_info.value)
        # Verify no raw secret in exception message
        assert "sk-1234567890abcdef12345678" not in str(exc_info.value)

    def test_secret_request_redacted(self, test_config: ProxyConfig) -> None:
        """Inbound request with secret matching REDACT rule is transformed."""
        redact_rule = PolicyRule(
            rule_id="redact_secrets",
            action=PolicyAction.REDACT,
            category=DetectionCategory.SECRET,
        )
        engine = PolicyEngine(PolicyConfig(rules=[redact_rule]))
        pipeline = SecurityPipeline(config=test_config, policy_engine=engine)

        data = {"prompt": "Connect with sk-1234567890abcdef12345678 please."}
        body = json.dumps(data).encode("utf-8")
        out_body, result = pipeline.process_request(
            raw_body=body,
            content_type_header="application/json",
            request_id="req_redact",
        )
        assert result.action == PolicyAction.REDACT
        assert result.transformed is True
        assert result.detection_count >= 1

        parsed = json.loads(out_body.decode("utf-8"))
        assert "[REDACTED_SECRET]" in parsed["prompt"]
        assert "sk-1234567890abcdef12345678" not in parsed["prompt"]

    def test_secret_request_warn(self, test_config: ProxyConfig) -> None:
        """Inbound request with secret matching WARN rule is passed unchanged."""
        warn_rule = PolicyRule(
            rule_id="warn_secrets",
            action=PolicyAction.WARN,
            category=DetectionCategory.SECRET,
        )
        engine = PolicyEngine(PolicyConfig(rules=[warn_rule]))
        pipeline = SecurityPipeline(config=test_config, policy_engine=engine)

        data = {"prompt": "sk-1234567890abcdef12345678"}
        body = json.dumps(data).encode("utf-8")
        out_body, result = pipeline.process_request(
            raw_body=body,
            content_type_header="application/json",
            request_id="req_warn",
        )
        assert out_body == body
        assert result.action == PolicyAction.WARN
        assert result.transformed is False
        assert result.detection_count >= 1

    def test_oversized_request_rejected(self, test_config: ProxyConfig) -> None:
        """Request exceeding max_request_body_bytes raises PayloadTooLargeError."""
        pipeline = SecurityPipeline(config=test_config)
        huge_body = b"x" * (test_config.max_request_body_bytes + 1)
        with pytest.raises(PayloadTooLargeError) as exc_info:
            pipeline.process_request(
                raw_body=huge_body,
                content_type_header="text/plain",
                request_id="req_huge",
            )
        assert exc_info.value.status_code == 413

    def test_response_secret_blocked(self, test_config: ProxyConfig) -> None:
        """Response with secret matching BLOCK raises BlockedResponseError."""
        block_rule = PolicyRule(
            rule_id="block_resp_secrets",
            action=PolicyAction.BLOCK,
            category=DetectionCategory.SECRET,
        )
        engine = PolicyEngine(PolicyConfig(rules=[block_rule]))
        pipeline = SecurityPipeline(config=test_config, policy_engine=engine)

        resp_body = json.dumps(
            {"response": "Here is the key: sk-1234567890abcdef12345678"}
        ).encode("utf-8")
        with pytest.raises(BlockedResponseError) as exc_info:
            pipeline.process_response(
                raw_body=resp_body,
                content_type_header="application/json",
                request_id="resp_block",
            )
        assert exc_info.value.status_code == 502
        assert "Blocked" in str(exc_info.value)
        assert "sk-1234567890abcdef12345678" not in str(exc_info.value)

    def test_response_secret_redacted(self, test_config: ProxyConfig) -> None:
        """Outbound response containing secret matching REDACT is sanitized."""
        redact_rule = PolicyRule(
            rule_id="redact_resp_secrets",
            action=PolicyAction.REDACT,
            category=DetectionCategory.SECRET,
        )
        engine = PolicyEngine(PolicyConfig(rules=[redact_rule]))
        pipeline = SecurityPipeline(config=test_config, policy_engine=engine)

        resp_body = json.dumps(
            {"response": "Your token is sk-1234567890abcdef12345678"}
        ).encode("utf-8")
        out_body, result = pipeline.process_response(
            raw_body=resp_body,
            content_type_header="application/json",
            request_id="resp_redact",
        )
        assert result.action == PolicyAction.REDACT
        assert result.transformed is True
        parsed = json.loads(out_body.decode("utf-8"))
        assert "[REDACTED_SECRET]" in parsed["response"]


class TestUpstreamClientHelpers:
    """Test suite for UpstreamClient URL formatting and header sanitization."""

    def test_url_building(self) -> None:
        """Verify clean URL composition without double slashes."""
        config = ProxyConfig(upstream_url="http://127.0.0.1:9000/api")
        client = UpstreamClient(config)
        url1 = client._build_target_url("/v1/models", "")
        assert url1 == "http://127.0.0.1:9000/api/v1/models"

        url2 = client._build_target_url("chat", "verbose=1&limit=5")
        assert url2 == "http://127.0.0.1:9000/api/chat?verbose=1&limit=5"

    def test_header_sanitization_removes_hop_by_hop_and_spoofs(self) -> None:
        """Verify hop-by-hop headers and target overrides are removed."""
        headers = {
            "Host": "evil.com",
            "Connection": "keep-alive",
            "Upgrade": "websocket",
            "X-Target-URL": "https://malicious.example/steal",
            "X-Upstream-Override": "http://other.host",
            "Authorization": "Bearer sensitive-token-here",
            "Content-Type": "application/json",
        }
        sanitized = UpstreamClient._sanitize_request_headers(headers)
        assert "Host" not in sanitized
        assert "Connection" not in sanitized
        assert "Upgrade" not in sanitized
        assert "X-Target-URL" not in sanitized
        assert "X-Upstream-Override" not in sanitized
        # Authorization and Content-Type must be preserved
        assert sanitized["Authorization"] == "Bearer sensitive-token-here"
        assert sanitized["Content-Type"] == "application/json"
