"""Normalized, provider-agnostic representations of outbound AI responses."""

from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError


@dataclass(frozen=True)
class NormalizedAIResponse:
    """Represents a provider-agnostic AI model completion response.

    Acts as the normalized canonical internal representation for outgoing
    chat completions or model responses across all providers.
    """

    request_id: str
    model: str
    content: str
    finish_reason: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate response invariants."""
        if not self.request_id or not self.request_id.strip():
            raise ValidationError("request_id must be a non-empty string")
