"""Foundational domain models for AI Data Firewall.

These models represent normalized internal representations of AI traffic,
detection findings, policy evaluations, and privacy-safe security events.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Severity classification for security findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(StrEnum):
    """Enforcement actions determined by the policy engine."""

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


class ContentSource(StrEnum):
    """Identifies the origin or context of inspected content."""

    USER_INPUT = "user_input"
    SYSTEM_INSTRUCTION = "system_instruction"
    ASSISTANT_HISTORY = "assistant_history"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_DOCUMENT = "retrieved_document"
    MODEL_OUTPUT = "model_output"


@dataclass(frozen=True)
class ContentLocation:
    """Specifies where an inspected segment or finding is located."""

    source: ContentSource
    message_index: int | None = None
    char_start: int | None = None
    char_end: int | None = None
    field_path: str | None = None


@dataclass(frozen=True)
class DetectionResult:
    """Describes a finding produced by a detector.

    Security Rule: This model must NEVER store raw secrets, credentials,
    or sensitive PII in plaintext. It stores only classification metadata,
    confidence metrics, and location references.
    """

    detector_name: str
    category: str
    severity: Severity
    confidence: float
    location: ContentLocation
    description: str
    recommended_action: PolicyAction = PolicyAction.WARN
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedMessage:
    """Represents a conversational message in a normalized AI request."""

    role: str
    content: str
    source: ContentSource = ContentSource.USER_INPUT
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedAIRequest:
    """Represents a provider-agnostic AI model invocation request."""

    request_id: str
    model: str
    messages: list[NormalizedMessage] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedAIResponse:
    """Represents a provider-agnostic AI model completion response."""

    request_id: str
    model: str
    content: str
    finish_reason: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of evaluating detection findings against security policies."""

    action: PolicyAction
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityEvent:
    """Privacy-preserving audit record of a security decision.

    Security Rule: Audit events record metadata, actions, and non-sensitive rule
    identifiers. They must never persist raw prompt bodies or full completions.
    """

    event_id: str
    timestamp: str
    request_id: str
    direction: str  # "request" or "response"
    action_taken: PolicyAction
    safe_explanation: str
    detections_summary: list[dict[str, Any]] = field(default_factory=list)
