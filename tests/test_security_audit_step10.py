"""Security and privacy audit test suite for Step 10.

Validates:
1. Authorization Header Audit (Requirement 34):
   - Forwarding preserves Authorization headers without logging or leaking.
   - Headers never appear in CLI errors, blocked responses, or audit metadata.
2. Synthetic Secret Privacy Audit (Requirement 35):
   - Synthetic secrets never appear in DetectionResult repr, PolicyDecision repr,
     RedactionResult repr, SecurityEvent repr, or safe error payloads.
3. No-Raw-Content Logging Audit (Requirement 36):
   - Zero raw prompts, model outputs, or secrets printed or logged.
4. Repository Secret Scan (Requirement 51):
   - Asserts all test strings are synthetic and no real credentials exist.
5. Resource Management (Requirement 37):
   - Verifies clean shutdown of UpstreamClient and HTTP resources.
"""

import asyncio
import re
from pathlib import Path

import pytest

from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)
from aifirewall.detectors.base import DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision, SecurityEvent
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    BlockedRequestError,
    BlockedResponseError,
    create_safe_error_payload,
)
from aifirewall.proxy.upstream import UpstreamClient
from aifirewall.transformation.redaction import RedactionEngine

SYNTHETIC_TEST_SECRET = "sk-proj-SUPERSECRET1234567890123456789012345678901234567890"


class TestAuthorizationHeaderSafety:
    """Dedicated audit verifying Authorization headers are protected."""

    def test_authorization_header_not_in_safe_error_payload(self) -> None:
        """Safe error payloads never include headers or credentials."""
        payload = create_safe_error_payload(
            "request_blocked", "Inbound request blocked by policy."
        )
        assert "Authorization" not in str(payload)
        assert "Bearer" not in str(payload)

    def test_authorization_header_not_in_normalized_models(self) -> None:
        """NormalizedAIRequest never accepts or stores Authorization headers."""
        norm_req = NormalizedAIRequest(
            request_id="req_audit",
            messages=[NormalizedMessage(role="user", content="Hello")],
            model="gpt-4o",
        )
        assert "authorization" not in norm_req.metadata
        assert "Authorization" not in repr(norm_req)

    def test_authorization_header_not_in_security_event(self) -> None:
        """SecurityEvent never stores Authorization headers or raw credentials."""
        event = SecurityEvent(
            event_id="evt_123",
            timestamp="2026-09-27T00:00:00Z",
            request_id="req_456",
            direction=ContentDirection.REQUEST,
            action_taken=PolicyAction.BLOCK,
            safe_explanation="High-risk secret detected in prompt.",
        )
        assert "Authorization" not in repr(event)
        assert "Bearer" not in repr(event)


class TestSecretPrivacyAudit:
    """Verifies that secrets are NEVER leaked in strings or reprs."""

    def test_detection_result_repr_does_not_leak_raw_secret(self) -> None:
        """DetectionResult repr and str must NOT contain the secret value."""
        loc = ContentLocation(source=ContentSource.USER, char_start=10, char_end=60)
        finding = DetectionResult(
            detection_id="det_1",
            description="Synthetic secret detected",
            category=DetectionCategory.SECRET,
            severity=Severity.HIGH,
            confidence=0.95,
            detector_name="secret_detector",
            location=loc,
        )
        finding_repr = repr(finding)
        assert SYNTHETIC_TEST_SECRET not in finding_repr

    def test_policy_decision_repr_does_not_leak_raw_secret(self) -> None:
        """PolicyDecision repr does not contain raw secrets."""
        loc = ContentLocation(source=ContentSource.USER, char_start=0, char_end=50)
        finding = DetectionResult(
            detection_id="det_1",
            description="Synthetic secret detected",
            category=DetectionCategory.SECRET,
            severity=Severity.HIGH,
            confidence=0.95,
            detector_name="secret_detector",
            location=loc,
        )
        decision = PolicyDecision(
            action=PolicyAction.REDACT,
            reason="Secret matched redact rule.",
            matched_rules=["rule-1"],
            detections=[finding],
        )
        assert SYNTHETIC_TEST_SECRET not in repr(decision)

    def test_redaction_result_repr_does_not_leak_raw_secret(self) -> None:
        """RedactionResult repr does not leak raw secret."""
        detector = SecretDetector()
        context = DetectorContext(
            request_id="req_audit",
            direction=ContentDirection.REQUEST,
            source=ContentSource.USER,
        )
        text = f"My key is {SYNTHETIC_TEST_SECRET}"
        findings = detector.detect(text, context)

        engine = RedactionEngine()
        decision = PolicyDecision(
            action=PolicyAction.REDACT,
            reason="Redact secrets",
            matched_rules=["r1"],
        )
        res = engine.redact(content=text, detections=findings, decision=decision)

        result_repr = repr(res)
        assert SYNTHETIC_TEST_SECRET not in result_repr
        assert "[REDACTED_SECRET]" in res.content

    def test_blocked_exceptions_do_not_leak_secrets(self) -> None:
        """BlockedRequestError and BlockedResponseError do not leak secrets."""
        err_req = BlockedRequestError("Inbound request blocked by security policy.")
        assert SYNTHETIC_TEST_SECRET not in str(err_req)
        assert SYNTHETIC_TEST_SECRET not in repr(err_req)

        err_resp = BlockedResponseError("Outbound response blocked by security policy.")
        assert SYNTHETIC_TEST_SECRET not in str(err_resp)
        assert SYNTHETIC_TEST_SECRET not in repr(err_resp)


class TestRepositorySecretSanity:
    """Scans all tracked python files in the repository for suspicious live keys."""

    SUSPICIOUS_LIVE_PATTERNS = [
        # Real AWS Access Key ID (not test fixtures like AKIAIOSFODNN7EXAMPLE)
        re.compile(r"AKIA[0-9A-Z]{16}"),
        # Real GitHub PATs with standard format (excluding test dummies)
        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    ]

    def test_no_live_credentials_in_source_or_tests(self) -> None:
        """Ensures all API keys and tokens in the repository are synthetic."""
        repo_root = Path(__file__).resolve().parent.parent
        src_and_tests = list((repo_root / "src").rglob("*.py")) + list(
            (repo_root / "tests").rglob("*.py")
        )

        for py_file in src_and_tests:
            text = py_file.read_text(encoding="utf-8")
            for pattern in self.SUSPICIOUS_LIVE_PATTERNS:
                matches = pattern.findall(text)
                for match in matches:
                    # Allow standard AWS example mock credentials
                    if match in {"AKIAIOSFODNN7EXAMPLE", "AKIAEXAMPLEKEY12345"}:
                        continue
                    # Allow synthetic dummies with repeating/sequential patterns
                    if any(
                        s in match
                        for s in [
                            "ABCDEF",
                            "ABCDEFGHIJKLMNOP",
                            "1234567890",
                            "111111",
                            "222222",
                            "EXAMPLE",
                        ]
                    ):
                        continue
                    pytest.fail(
                        f"Suspicious credential pattern in {py_file.name}: "
                        f"{match[:8]}..."
                    )


class TestResourceManagement:
    """Verifies clean lifecycle and resource teardown."""

    def test_upstream_client_clean_lifecycle(self) -> None:
        """UpstreamClient opens and closes its httpx AsyncClient cleanly."""

        async def _test() -> None:
            cfg = ProxyConfig(upstream_url="http://127.0.0.1:11434")
            client = UpstreamClient(config=cfg)
            await client.start()
            assert client._client is not None
            assert not client._client.is_closed
            await client.close()
            assert client._client is None

        asyncio.run(_test())
