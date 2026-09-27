"""AI Data Firewall Provider Adapters.

Translates vendor-specific AI payloads (OpenAI, Anthropic, Gemini, Ollama)
to and from canonical normalized domain models (NormalizedAIRequest,
NormalizedAIResponse).
"""

from aifirewall.providers.anthropic import AnthropicAdapter
from aifirewall.providers.base import BaseProviderAdapter, ProviderAdapter
from aifirewall.providers.errors import (
    DenormalizationError,
    NormalizationError,
    ProviderAdapterError,
    UnsupportedPayloadError,
    UnsupportedProviderError,
    UnsupportedStreamingError,
)
from aifirewall.providers.gemini import GeminiAdapter
from aifirewall.providers.ollama import OllamaAdapter
from aifirewall.providers.openai import OpenAIAdapter
from aifirewall.providers.registry import ProviderRegistry, create_default_registry

__all__ = [
    "BaseProviderAdapter",
    "ProviderAdapter",
    "ProviderRegistry",
    "create_default_registry",
    "OpenAIAdapter",
    "AnthropicAdapter",
    "GeminiAdapter",
    "OllamaAdapter",
    "ProviderAdapterError",
    "NormalizationError",
    "DenormalizationError",
    "UnsupportedProviderError",
    "UnsupportedPayloadError",
    "UnsupportedStreamingError",
]
