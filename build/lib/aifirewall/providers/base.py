"""Base protocol and abstract interface for AI provider adapters.

Provider adapters are pure structural translators:
    PROVIDER HTTP PAYLOAD <-> NORMALIZED DOMAIN MODEL

They encapsulate provider-specific schema details (OpenAI, Anthropic, Gemini, Ollama)
without leaking external API shapes into the security detection or policy engines.

Architectural Rule:
    PROVIDER FORMAT != NORMALIZED DOMAIN MODEL != DETECTION != POLICY != TRANSFORMATION

Adapters must NOT:
- detect secrets or run security regular expressions
- evaluate policy rules (ALLOW, WARN, REDACT, BLOCK)
- redact content directly
- execute external network or telemetry calls
- log or persist request/response bodies or credentials
"""

from abc import ABC, abstractmethod
from typing import Any, Protocol, runtime_checkable

from aifirewall.models.request import NormalizedAIRequest
from aifirewall.models.response import NormalizedAIResponse


@runtime_checkable
class ProviderAdapter(Protocol):
    """Protocol contract bridging provider-specific payloads to normalized models."""

    @property
    def provider_name(self) -> str:
        """Stable lowercase identifier of the AI provider (e.g. 'openai')."""
        ...

    @property
    def adapter_version(self) -> str:
        """Implementation version of this adapter (not the provider API version)."""
        ...

    @property
    def version(self) -> str:
        """Convenience alias for adapter_version."""
        ...

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine whether the payload structure matches this provider's schema."""
        ...

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert a provider-specific request payload into a NormalizedAIRequest."""
        ...

    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to provider request format."""
        ...

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert a provider response payload into a NormalizedAIResponse."""
        ...

    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to provider response format."""
        ...


class BaseProviderAdapter(ABC):
    """Abstract base class providing standard helper utilities for adapters."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Stable lowercase identifier of the AI provider."""
        ...

    @property
    @abstractmethod
    def adapter_version(self) -> str:
        """Implementation version of this adapter."""
        ...

    @property
    def version(self) -> str:
        """Compatibility property returning the adapter implementation version."""
        return self.adapter_version

    @abstractmethod
    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine whether the payload structure matches this provider's schema."""
        ...

    @abstractmethod
    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert a provider-specific request payload into a NormalizedAIRequest."""
        ...

    @abstractmethod
    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to provider request format."""
        ...

    @abstractmethod
    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert a provider response payload into a NormalizedAIResponse."""
        ...

    @abstractmethod
    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to provider response format."""
        ...

    def __repr__(self) -> str:
        """Safe developer representation without sensitive state."""
        cls_name = self.__class__.__name__
        return (
            f"{cls_name}(provider={self.provider_name!r}, "
            f"version={self.adapter_version!r})"
        )
