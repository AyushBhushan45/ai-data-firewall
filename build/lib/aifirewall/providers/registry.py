"""Deterministic provider adapter registry for AI Data Firewall.

Maintains an explicit, ordered sequence of registered ProviderAdapters.
Provides deterministic resolution by identifier or safe structural auto-detection.

Architectural Rule:
- Deterministic behavior: no dynamic code execution or arbitrary module loading.
- Rejects ambiguous auto-detection matches.
- Immutable registry queries.
"""

from collections.abc import Sequence
from typing import Any

from aifirewall.core.errors import ConfigurationError
from aifirewall.providers.anthropic import AnthropicAdapter
from aifirewall.providers.base import ProviderAdapter
from aifirewall.providers.errors import UnsupportedProviderError
from aifirewall.providers.gemini import GeminiAdapter
from aifirewall.providers.ollama import OllamaAdapter
from aifirewall.providers.openai import OpenAIAdapter


class ProviderRegistry:
    """Registry maintaining registered provider adapters in deterministic order."""

    def __init__(self, adapters: Sequence[ProviderAdapter] | None = None) -> None:
        """Initialize registry with a sequence of adapters or empty."""
        self._adapters: dict[str, ProviderAdapter] = {}
        if adapters is not None:
            for adapter in adapters:
                self.register(adapter)

    def register(self, adapter: ProviderAdapter) -> None:
        """Register a ProviderAdapter instance.

        Raises:
            ConfigurationError: If an adapter with same identifier is registered.
        """
        if not isinstance(adapter, ProviderAdapter):
            cls_name = type(adapter).__name__
            raise ConfigurationError(
                f"Object {cls_name} does not conform to ProviderAdapter protocol."
            )

        name = adapter.provider_name.strip().lower()
        if not name:
            raise ConfigurationError(
                "ProviderAdapter must have a non-empty provider_name."
            )

        if name in self._adapters:
            raise ConfigurationError(
                f"Provider adapter '{name}' is already registered in registry."
            )

        self._adapters[name] = adapter

    def get(self, provider_name: str) -> ProviderAdapter | None:
        """Retrieve an adapter by case-insensitive name, or None if not found."""
        if not provider_name or not isinstance(provider_name, str):
            return None
        return self._adapters.get(provider_name.strip().lower())

    def get_or_raise(self, provider_name: str) -> ProviderAdapter:
        """Retrieve an adapter by name or raise UnsupportedProviderError."""
        adapter = self.get(provider_name)
        if adapter is None:
            supported = ", ".join(repr(k) for k in self.list_providers())
            raise UnsupportedProviderError(
                f"Unsupported provider: {provider_name!r}. "
                f"Registered providers: [{supported}].",
                provider=provider_name,
            )
        return adapter

    def auto_detect(self, raw_request: dict[str, Any]) -> ProviderAdapter | None:
        """Attempt safe structural auto-detection against registered adapters.

        Returns matching adapter if exactly one matches.
        Rejects ambiguous matches by returning None to fail safe.
        """
        if not isinstance(raw_request, dict):
            return None

        matches: list[ProviderAdapter] = []
        for name in sorted(self._adapters.keys()):
            adapter = self._adapters[name]
            try:
                if adapter.can_handle_request(raw_request):
                    matches.append(adapter)
            except Exception:
                continue

        # Ambiguous match: multiple adapters match -> fail safe (return None)
        if len(matches) == 1:
            return matches[0]

        return None

    def list_providers(self) -> tuple[str, ...]:
        """Return alphabetically sorted tuple of registered provider names."""
        return tuple(sorted(self._adapters.keys()))

    def __contains__(self, provider_name: str) -> bool:
        """Check if provider identifier is registered."""
        return self.get(provider_name) is not None

    def __len__(self) -> int:
        """Return total count of registered adapters."""
        return len(self._adapters)


def create_default_registry() -> ProviderRegistry:
    """Construct a ProviderRegistry with default first-party adapters."""
    registry = ProviderRegistry()
    registry.register(OpenAIAdapter())
    registry.register(AnthropicAdapter())
    registry.register(GeminiAdapter())
    registry.register(OllamaAdapter())
    return registry
