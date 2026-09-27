"""Normalized, provider-agnostic representations of inbound AI requests."""

from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import ContentSource


@dataclass(frozen=True)
class NormalizedMessage:
    """Represents an individual message in an AI conversation history."""

    role: str
    content: str
    source: ContentSource = ContentSource.USER
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate core message fields."""
        if not self.role or not self.role.strip():
            raise ValidationError("message role must be a non-empty string")


@dataclass(frozen=True)
class NormalizedAIRequest:
    """Represents a provider-agnostic AI model invocation request.

    Acts as the normalized canonical internal representation for incoming
    chat or completion requests across all providers (OpenAI, Anthropic, Gemini, etc.).
    """

    request_id: str
    model: str
    messages: list[NormalizedMessage] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate request invariants."""
        if not self.request_id or not self.request_id.strip():
            raise ValidationError("request_id must be a non-empty string")
