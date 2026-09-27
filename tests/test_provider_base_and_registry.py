"""Unit tests for ProviderAdapter base interface and ProviderRegistry."""

import pytest

from aifirewall.core.errors import ConfigurationError
from aifirewall.protocols import ProviderAdapter
from aifirewall.providers import (
    AnthropicAdapter,
    GeminiAdapter,
    OllamaAdapter,
    OpenAIAdapter,
    ProviderRegistry,
    UnsupportedProviderError,
    create_default_registry,
)


def test_adapters_satisfy_protocol() -> None:
    """Verify all 4 adapters satisfy the ProviderAdapter protocol."""
    openai = OpenAIAdapter()
    anthropic = AnthropicAdapter()
    gemini = GeminiAdapter()
    ollama = OllamaAdapter()

    for adapter in (openai, anthropic, gemini, ollama):
        assert isinstance(adapter, ProviderAdapter)
        assert adapter.provider_name
        assert adapter.adapter_version
        assert adapter.version == adapter.adapter_version
        assert "provider=" in repr(adapter)


def test_registry_registration_and_lookup() -> None:
    """Verify registration, case-insensitivity, and lookup."""
    registry = ProviderRegistry()
    assert len(registry) == 0

    openai = OpenAIAdapter()
    registry.register(openai)
    assert len(registry) == 1
    assert "openai" in registry
    assert "OPENAI" in registry
    assert registry.get("openai") is openai
    assert registry.get("OpenAI") is openai
    assert registry.get_or_raise("openai") is openai


def test_registry_rejects_duplicate_registration() -> None:
    """Verify registering a duplicate provider identifier raises ConfigurationError."""
    registry = ProviderRegistry()
    registry.register(OpenAIAdapter())

    with pytest.raises(ConfigurationError, match="already registered"):
        registry.register(OpenAIAdapter())


def test_registry_rejects_non_adapter() -> None:
    """Verify registering an invalid object raises ConfigurationError."""
    registry = ProviderRegistry()

    class Fake:
        pass

    with pytest.raises(ConfigurationError, match="does not conform"):
        registry.register(Fake())  # type: ignore[arg-type]


def test_registry_get_or_raise_unknown() -> None:
    """Verify looking up an unknown provider raises UnsupportedProviderError."""
    registry = create_default_registry()
    with pytest.raises(
        UnsupportedProviderError, match="Unsupported provider: 'unknown'"
    ):
        registry.get_or_raise("unknown")


def test_registry_deterministic_ordering() -> None:
    """Verify list_providers returns deterministic alphabetical ordering."""
    registry = create_default_registry()
    providers = registry.list_providers()
    assert providers == ("anthropic", "gemini", "ollama", "openai")


def test_registry_auto_detect_unique() -> None:
    """Verify auto-detection selects the unique matching adapter."""
    registry = create_default_registry()

    gemini_req = {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
    detected = registry.auto_detect(gemini_req)
    assert detected is not None
    assert detected.provider_name == "gemini"


def test_registry_auto_detect_ambiguous_fails_safe() -> None:
    """Verify ambiguous requests fail safe by returning None."""
    registry = ProviderRegistry()

    class AdapterA(OpenAIAdapter):
        @property
        def provider_name(self) -> str:
            return "a"

        def can_handle_request(self, raw_request: dict) -> bool:
            return True

    class AdapterB(OpenAIAdapter):
        @property
        def provider_name(self) -> str:
            return "b"

        def can_handle_request(self, raw_request: dict) -> bool:
            return True

    registry.register(AdapterA())
    registry.register(AdapterB())

    # When both match, auto_detect must return None to avoid guessing
    assert registry.auto_detect({"test": 1}) is None
