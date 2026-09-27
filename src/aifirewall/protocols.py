"""Architectural protocols and interfaces for AI Data Firewall.

These protocols define structural subtyping contracts for modular components:
detectors, provider adapters, policy engines, content transformers, and audit sinks.
Implementations will be introduced incrementally in subsequent stages.
"""

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from aifirewall.detectors.base import Detector, DetectorContext
from aifirewall.models import (
    DetectionResult,
    NormalizedAIRequest,
    NormalizedAIResponse,
    PolicyDecision,
    SecurityEvent,
)


@runtime_checkable
class ProviderAdapter(Protocol):
    """Protocol bridging provider-specific API formats to normalized internal models.

    Isolates external schema variance (OpenAI, Anthropic, Gemini, Ollama)
    from core security inspection logic.
    """

    @property
    def provider_name(self) -> str:
        """Identifier of the AI provider."""
        ...

    @property
    def adapter_version(self) -> str:
        """Version of the provider adapter implementation."""
        ...

    @property
    def version(self) -> str:
        """Convenience alias for adapter_version."""
        ...

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine if payload matches this provider's schema."""
        ...

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert a provider-specific request payload into a NormalizedAIRequest."""
        ...

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert a provider response payload into a NormalizedAIResponse."""
        ...

    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to provider native payload schema."""
        ...

    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to provider native response schema."""
        ...


@runtime_checkable
class PolicyEngine(Protocol):
    """Protocol for evaluating detection findings against declarative security policies.

    The policy engine determines whether to ALLOW, WARN, REDACT, or BLOCK traffic.
    """

    def evaluate(
        self,
        detections: Sequence[DetectionResult],
        context: Any = None,
        request: NormalizedAIRequest | None = None,
    ) -> PolicyDecision:
        """Evaluate findings and return a deterministic policy decision."""
        ...


@runtime_checkable
class ContentTransformer(Protocol):
    """Protocol for mutating content based on approved policy actions (e.g., redaction).

    Operates strictly after policy evaluation has determined a REDACT action.
    """

    def transform(self, content: str, detections: list[DetectionResult]) -> str:
        """Apply deterministic transformations (such as masking) to detected spans."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for persisting or emitting privacy-safe security events."""

    def record(self, event: SecurityEvent) -> None:
        """Record an audit event without blocking critical request execution."""
        ...


__all__ = [
    "Detector",
    "DetectorContext",
    "ProviderAdapter",
    "PolicyEngine",
    "ContentTransformer",
    "AuditSink",
]
