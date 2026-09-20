"""Tests for core domain models and protocol definitions."""

from dataclasses import FrozenInstanceError

import pytest

from aifirewall.models import (
    ContentLocation,
    ContentSource,
    DetectionResult,
    NormalizedAIRequest,
    NormalizedAIResponse,
    NormalizedMessage,
    PolicyAction,
    PolicyDecision,
    SecurityEvent,
    Severity,
)
from aifirewall.protocols import Detector


def test_content_location_creation():
    """Verify ContentLocation fields and immutability."""
    loc = ContentLocation(
        source=ContentSource.USER_INPUT,
        message_index=0,
        char_start=10,
        char_end=25,
        field_path="messages[0].content",
    )
    assert loc.source == ContentSource.USER_INPUT
    assert loc.char_start == 10
    assert loc.char_end == 25

    with pytest.raises(FrozenInstanceError):
        loc.char_start = 0  # type: ignore[misc]


def test_detection_result_privacy_preservation():
    """Verify DetectionResult accepts classification metadata without raw secrets."""
    loc = ContentLocation(source=ContentSource.USER_INPUT, message_index=0)
    result = DetectionResult(
        detector_name="secret_pattern_detector",
        category="api_key",
        severity=Severity.CRITICAL,
        confidence=0.98,
        location=loc,
        description="High-entropy credential pattern identified.",
        recommended_action=PolicyAction.BLOCK,
    )
    assert result.severity == Severity.CRITICAL
    assert result.recommended_action == PolicyAction.BLOCK
    assert "api_key" in result.category
    # Verify no raw secret is stored or exposed
    assert hasattr(result, "detected_value") is False


def test_normalized_ai_request_and_response():
    """Verify normalized AI request and response models."""
    msg = NormalizedMessage(
        role="user",
        content="Hello world",
        source=ContentSource.USER_INPUT,
    )
    req = NormalizedAIRequest(
        request_id="req-12345",
        model="gpt-4o",
        messages=[msg],
    )
    assert req.request_id == "req-12345"
    assert len(req.messages) == 1
    assert req.messages[0].content == "Hello world"

    resp = NormalizedAIResponse(
        request_id="req-12345",
        model="gpt-4o",
        content="Response text",
        finish_reason="stop",
    )
    assert resp.request_id == "req-12345"
    assert resp.content == "Response text"
    assert resp.finish_reason == "stop"


def test_policy_decision_and_security_event():
    """Verify PolicyDecision and SecurityEvent audit logging structures."""
    decision = PolicyDecision(
        action=PolicyAction.BLOCK,
        reason="Critical secret policy violation.",
        matched_rules=["block_critical_secrets"],
    )
    assert decision.action == PolicyAction.BLOCK
    assert "block_critical_secrets" in decision.matched_rules

    event = SecurityEvent(
        event_id="evt-001",
        timestamp="2026-09-20T12:00:00Z",
        request_id="req-12345",
        direction="request",
        action_taken=PolicyAction.BLOCK,
        safe_explanation="Request blocked due to policy rule block_critical_secrets",
    )
    assert event.event_id == "evt-001"
    assert event.action_taken == PolicyAction.BLOCK


def test_detector_protocol_conformance():
    """Verify that a minimal class adheres to the Detector protocol."""

    class DummyDetector:
        @property
        def name(self) -> str:
            return "dummy_detector"

        @property
        def category(self) -> str:
            return "test"

        def detect(
            self, content: str, location: ContentLocation
        ) -> list[DetectionResult]:
            return []

    dummy = DummyDetector()
    assert isinstance(dummy, Detector)
