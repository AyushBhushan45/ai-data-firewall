"""Tests for package exports, versioning, and module boundaries."""

import aifirewall
from aifirewall import (
    AIFirewallError,
    ContentDirection,
    ContentLocation,
    ContentSource,
    DetectionCategory,
    DetectionResult,
    Detector,
    DetectorContext,
    DetectorError,
    EventType,
    NormalizedAIRequest,
    NormalizedAIResponse,
    NormalizedMessage,
    PolicyAction,
    PolicyDecision,
    SecurityEvent,
    Severity,
    ValidationError,
    __version__,
)


def test_package_version():
    """Verify that the package exposes a semantic version string."""
    assert __version__ == "0.1.0"
    assert aifirewall.__version__ == "0.1.0"


def test_package_exports():
    """Verify that all core types, models, errors, and protocols are exported."""
    expected_exports = [
        ContentDirection,
        ContentSource,
        DetectionCategory,
        Severity,
        PolicyAction,
        EventType,
        ContentLocation,
        DetectionResult,
        NormalizedMessage,
        NormalizedAIRequest,
        NormalizedAIResponse,
        PolicyDecision,
        SecurityEvent,
        Detector,
        DetectorContext,
        AIFirewallError,
        ValidationError,
        DetectorError,
    ]
    for export in expected_exports:
        assert export is not None


def test_enum_members_and_values():
    """Verify that core enums define expected members and string values."""
    assert ContentDirection.REQUEST == "request"
    assert ContentDirection.RESPONSE == "response"

    assert ContentSource.USER == "user"
    assert ContentSource.SYSTEM == "system"
    assert ContentSource.ASSISTANT == "assistant"
    assert ContentSource.TOOL_INPUT == "tool_input"
    assert ContentSource.TOOL_OUTPUT == "tool_output"
    assert ContentSource.RETRIEVED_CONTENT == "retrieved_content"
    assert ContentSource.UNKNOWN == "unknown"

    assert Severity.INFO == "info"
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"

    assert DetectionCategory.SECRET == "secret"
    assert DetectionCategory.PII == "pii"
    assert DetectionCategory.PROMPT_INJECTION == "prompt_injection"
    assert DetectionCategory.OTHER == "other"

    assert PolicyAction.ALLOW == "allow"
    assert PolicyAction.WARN == "warn"
    assert PolicyAction.REDACT == "redact"
    assert PolicyAction.BLOCK == "block"

    assert EventType.DETECTION == "detection"
    assert EventType.WARNING == "warning"
    assert EventType.REDACTION == "redaction"
    assert EventType.BLOCK == "block"
    assert EventType.ERROR == "error"
