"""Tests for core domain models: requests, responses, events, and locations."""

from dataclasses import FrozenInstanceError

import pytest

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    EventType,
    PolicyAction,
    Severity,
)
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision, SecurityEvent
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse


def test_content_location_valid():
    """Verify ContentLocation initialization with valid values."""
    loc = ContentLocation(
        source=ContentSource.USER,
        message_index=1,
        block_index=0,
        char_start=10,
        char_end=25,
        field_path="messages[1].content",
    )
    assert loc.source == ContentSource.USER
    assert loc.message_index == 1
    assert loc.block_index == 0
    assert loc.char_start == 10
    assert loc.char_end == 25
    assert loc.field_path == "messages[1].content"


def test_content_location_immutability():
    """Verify ContentLocation is frozen and cannot be mutated."""
    loc = ContentLocation(source=ContentSource.USER, char_start=5, char_end=15)
    with pytest.raises(FrozenInstanceError):
        loc.char_start = 0  # type: ignore[misc]


def test_normalized_message_creation_and_validation():
    """Verify NormalizedMessage creation, defaults, and validation."""
    msg = NormalizedMessage(
        role="user",
        content="Analyze this quarterly report.",
        source=ContentSource.USER,
        metadata={"priority": "high"},
    )
    assert msg.role == "user"
    assert msg.content == "Analyze this quarterly report."
    assert msg.source == ContentSource.USER
    assert msg.metadata["priority"] == "high"

    # Message must reject empty role
    with pytest.raises(ValidationError, match="role"):
        NormalizedMessage(role="", content="Test")

    with pytest.raises(ValidationError, match="role"):
        NormalizedMessage(role="   ", content="Test")

    # Message must be immutable
    with pytest.raises(FrozenInstanceError):
        msg.content = "Modified content"  # type: ignore[misc]


def test_normalized_ai_request():
    """Verify NormalizedAIRequest creation, validation, and immutability."""
    msg = NormalizedMessage(role="user", content="Draft an email.")
    req = NormalizedAIRequest(
        request_id="req-abc-001",
        model="gpt-4o",
        messages=[msg],
        parameters={"temperature": 0.7},
        metadata={"app_id": "crm"},
    )
    assert req.request_id == "req-abc-001"
    assert req.model == "gpt-4o"
    assert len(req.messages) == 1
    assert req.parameters["temperature"] == 0.7
    assert req.metadata["app_id"] == "crm"

    # Reject empty request_id
    with pytest.raises(ValidationError, match="request_id"):
        NormalizedAIRequest(request_id="", model="gpt-4o")

    with pytest.raises(ValidationError, match="request_id"):
        NormalizedAIRequest(request_id="   ", model="gpt-4o")

    # Immutability
    with pytest.raises(FrozenInstanceError):
        req.model = "claude-3-5-sonnet"  # type: ignore[misc]


def test_normalized_ai_response():
    """Verify NormalizedAIResponse creation, validation, and immutability."""
    resp = NormalizedAIResponse(
        request_id="req-abc-001",
        model="gpt-4o",
        content="Here is the draft email.",
        finish_reason="stop",
        parameters={"usage": {"tokens": 42}},
        metadata={"latency_ms": 320},
    )
    assert resp.request_id == "req-abc-001"
    assert resp.model == "gpt-4o"
    assert resp.content == "Here is the draft email."
    assert resp.finish_reason == "stop"

    # Reject empty request_id
    with pytest.raises(ValidationError, match="request_id"):
        NormalizedAIResponse(request_id="", model="gpt-4o", content="text")

    # Immutability
    with pytest.raises(FrozenInstanceError):
        resp.content = "Changed"  # type: ignore[misc]


def test_policy_decision():
    """Verify PolicyDecision structure and attributes."""
    loc = ContentLocation(source=ContentSource.USER, char_start=0, char_end=10)
    det = DetectionResult(
        detection_id="det-1",
        detector_name="test_scanner",
        category="secret",
        severity=Severity.HIGH,
        confidence=0.95,
        location=loc,
        description="Test finding description",
    )
    decision = PolicyDecision(
        action=PolicyAction.BLOCK,
        reason="High severity credential detected.",
        matched_rules=["block_high_secrets"],
        detections=[det],
    )
    assert decision.action == PolicyAction.BLOCK
    assert decision.reason == "High severity credential detected."
    assert len(decision.matched_rules) == 1
    assert len(decision.detections) == 1

    with pytest.raises(FrozenInstanceError):
        decision.action = PolicyAction.ALLOW  # type: ignore[misc]


def test_security_event_valid_and_safe_repr():
    """Verify SecurityEvent creation, validation, and privacy-safe representations."""
    event = SecurityEvent(
        event_id="evt-100",
        timestamp="2026-09-20T12:00:00Z",
        request_id="req-abc-001",
        direction=ContentDirection.REQUEST,
        action_taken=PolicyAction.BLOCK,
        safe_explanation="Request blocked: credential pattern found in user input.",
        event_type=EventType.BLOCK,
        detector="credential_detector",
        category="secret",
        severity=Severity.CRITICAL,
        detections_summary=[{"category": "secret", "severity": "critical"}],
    )
    assert event.event_id == "evt-100"
    assert event.action_taken == PolicyAction.BLOCK
    assert event.event_type == EventType.BLOCK

    # Safe string representations
    str_repr = str(event)
    assert "evt-100" in str_repr
    assert "BLOCK" in str_repr
    assert "credential pattern found" in str_repr

    dev_repr = repr(event)
    assert "SecurityEvent" in dev_repr
    assert "evt-100" in dev_repr
    assert "req-abc-001" in dev_repr

    # Validate mandatory fields
    with pytest.raises(ValidationError, match="event_id"):
        SecurityEvent(
            event_id="",
            timestamp="2026-09-20T12:00:00Z",
            request_id="req-1",
            direction=ContentDirection.REQUEST,
            action_taken=PolicyAction.ALLOW,
            safe_explanation="Safe",
        )

    with pytest.raises(ValidationError, match="request_id"):
        SecurityEvent(
            event_id="evt-1",
            timestamp="2026-09-20T12:00:00Z",
            request_id="",
            direction=ContentDirection.REQUEST,
            action_taken=PolicyAction.ALLOW,
            safe_explanation="Safe",
        )

    with pytest.raises(ValidationError, match="safe_explanation"):
        SecurityEvent(
            event_id="evt-1",
            timestamp="2026-09-20T12:00:00Z",
            request_id="req-1",
            direction=ContentDirection.REQUEST,
            action_taken=PolicyAction.ALLOW,
            safe_explanation="",
        )
