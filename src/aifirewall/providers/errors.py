"""Exception hierarchy for AI provider adapters in AI Data Firewall.

Privacy Rule: Error messages must NEVER expose raw secrets, credentials,
Authorization headers, raw prompts, or full model completions.
Exceptions provide safe, structured diagnostic descriptions for operators.
"""

from aifirewall.core.errors import AIFirewallError


class ProviderAdapterError(AIFirewallError):
    """Base exception for all provider adapter failures."""

    def __init__(
        self,
        message: str,
        provider: str | None = None,
        field: str | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.field = field


class NormalizationError(ProviderAdapterError):
    """Raised when a provider-specific payload cannot be normalized.

    Indicates missing required structural fields, invalid types, or
    unparseable message structures.
    """


class DenormalizationError(ProviderAdapterError):
    """Raised when a normalized model cannot be mapped back to provider schema."""


class UnsupportedProviderError(ProviderAdapterError):
    """Raised when an unknown or unregistered provider identifier is requested."""


class UnsupportedPayloadError(ProviderAdapterError):
    """Raised when an adapter encounters an unsupported payload variant."""


class UnsupportedStreamingError(UnsupportedPayloadError):
    """Raised when a streaming request is received while streaming is deferred.

    The firewall fails safely and explicitly rejects streaming requests
    rather than silently claiming uninspected tokens were scanned.
    """
