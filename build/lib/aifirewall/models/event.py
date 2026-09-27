"""Security audit events and policy decision models."""

from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import (
    ContentDirection,
    DetectionCategory,
    EventType,
    PolicyAction,
    Severity,
)
from aifirewall.models.detection import DetectionResult


@dataclass(frozen=True)
class PolicyDecision:
    """Outcome of evaluating detection findings against security policies.

    Encapsulates the enforcement action, the deterministic reason, and
    which policy rules triggered the decision.
    """

    action: PolicyAction
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityEvent:
    """Privacy-preserving audit record of a security pipeline event.

    Security Rule: Audit events record operational metadata, actions taken,
    and non-sensitive rule/detector references. They must NEVER persist raw
    prompts, credentials, or full completions.
    """

    event_id: str
    timestamp: str
    request_id: str
    direction: ContentDirection | str
    action_taken: PolicyAction
    safe_explanation: str
    event_type: EventType = EventType.DETECTION
    detector: str | None = None
    category: DetectionCategory | str | None = None
    severity: Severity | None = None
    detections_summary: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate security event identifiers."""
        if not self.event_id or not self.event_id.strip():
            raise ValidationError("event_id must be a non-empty string")
        if not self.request_id or not self.request_id.strip():
            raise ValidationError("request_id must be a non-empty string")
        if not self.safe_explanation or not self.safe_explanation.strip():
            raise ValidationError("safe_explanation must be a non-empty string")

    def __repr__(self) -> str:
        """Return a privacy-safe developer representation."""
        return (
            f"SecurityEvent(id={self.event_id!r}, "
            f"type={str(self.event_type)!r}, "
            f"req_id={self.request_id!r}, "
            f"action={str(self.action_taken)!r}, "
            f"detector={self.detector!r}, "
            f"category={str(self.category)!r}, "
            f"severity={str(self.severity)!r})"
        )

    def __str__(self) -> str:
        """Return a human-readable safe summary."""
        return (
            f"[{self.timestamp}] [{self.action_taken.upper()}] "
            f"Event {self.event_id} ({self.event_type}) for request {self.request_id}: "
            f"{self.safe_explanation}"
        )
