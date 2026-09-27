"""Unit tests for Ollama-compatible provider adapter.

Covers Section 42 requirements.
"""

import pytest

from aifirewall.core.types import ContentSource
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.providers.errors import (
    NormalizationError,
    UnsupportedPayloadError,
    UnsupportedStreamingError,
)
from aifirewall.providers.ollama import OllamaAdapter


@pytest.fixture
def adapter() -> OllamaAdapter:
    return OllamaAdapter()


def test_ollama_identity(adapter: OllamaAdapter) -> None:
    """Verify provider identity and version."""
    assert adapter.provider_name == "ollama"
    assert adapter.adapter_version == "1.0.0"
    assert adapter.version == "1.0.0"


def test_ollama_chat_request_normalization(adapter: OllamaAdapter) -> None:
    """Requirements 1-4: /api/chat normalization, message extraction, model, options."""
    payload = {
        "model": "llama3:8b",
        "messages": [
            {"role": "system", "content": "You are a local assistant."},
            {"role": "user", "content": "Hello Ollama!"},
        ],
        "options": {
            "temperature": 0.3,
            "num_predict": 128,
            "seed": 42,
        },
        "stream": False,
    }
    req = adapter.normalize_request(payload, request_id="req_ollama_1")
    assert req.request_id == "req_ollama_1"
    assert req.model == "llama3:8b"
    assert len(req.messages) == 2
    assert req.messages[0].role == "system"
    assert req.messages[0].source == ContentSource.SYSTEM
    assert req.messages[0].content == "You are a local assistant."
    assert req.messages[1].role == "user"
    assert req.messages[1].source == ContentSource.USER
    assert req.messages[1].content == "Hello Ollama!"
    assert req.parameters["options"]["temperature"] == 0.3
    assert req.metadata["endpoint"] == "chat"


def test_ollama_generate_request_normalization(adapter: OllamaAdapter) -> None:
    """Requirement 1, 2: /api/generate prompt and system extraction."""
    payload = {
        "model": "mistral",
        "prompt": "Summarize this document.",
        "system": "Be concise.",
        "stream": False,
        "options": {"temperature": 0.5},
    }
    req = adapter.normalize_request(payload)
    assert req.model == "mistral"
    assert len(req.messages) == 2
    assert req.messages[0].role == "system"
    assert req.messages[0].content == "Be concise."
    assert req.messages[1].role == "user"
    assert req.messages[1].content == "Summarize this document."
    assert req.metadata["endpoint"] == "generate"


def test_ollama_chat_response_normalization(adapter: OllamaAdapter) -> None:
    """Requirements 5-7: response normalization, text, done/finish reason."""
    raw_response = {
        "model": "llama3:8b",
        "created_at": "2023-08-04T19:22:45.499127Z",
        "message": {
            "role": "assistant",
            "content": "Paris is the capital of France.",
        },
        "done": True,
        "done_reason": "stop",
        "total_duration": 5000000,
        "prompt_eval_count": 10,
        "eval_count": 25,
    }
    resp = adapter.normalize_response(raw_response, request_id="req_123")
    assert resp.request_id == "req_123"
    assert resp.model == "llama3:8b"
    assert resp.content == "Paris is the capital of France."
    assert resp.finish_reason == "stop"
    assert resp.metadata["total_duration"] == 5000000


def test_ollama_generate_response_normalization(adapter: OllamaAdapter) -> None:
    """Requirement 5, 6: /api/generate response normalization."""
    raw_response = {
        "model": "mistral",
        "created_at": "2023-08-04T19:22:45Z",
        "response": "Here is the summary.",
        "done": True,
        "done_reason": "length",
    }
    resp = adapter.normalize_response(raw_response, request_id="req_gen")
    assert resp.model == "mistral"
    assert resp.content == "Here is the summary."
    assert resp.finish_reason == "length"


def test_ollama_request_reconstruction(adapter: OllamaAdapter) -> None:
    """Requirement 8: request reconstruction for chat and generate."""
    # 1. Chat roundtrip
    chat_payload = {
        "model": "llama3",
        "messages": [{"role": "user", "content": "My secret is password123"}],
        "options": {"temperature": 0.7},
        "stream": False,
    }
    req = adapter.normalize_request(chat_payload)
    transformed_req = NormalizedAIRequest(
        request_id=req.request_id,
        model=req.model,
        messages=[
            NormalizedMessage(
                role="user",
                content="My secret is [REDACTED_SECRET]",
                source=ContentSource.USER,
            )
        ],
        parameters=req.parameters,
        metadata=req.metadata,
    )
    reconstructed = adapter.denormalize_request(
        transformed_req, original_request=chat_payload
    )
    assert reconstructed["model"] == "llama3"
    assert reconstructed["messages"][0]["content"] == "My secret is [REDACTED_SECRET]"
    assert reconstructed["stream"] is False

    # 2. Generate roundtrip
    gen_payload = {
        "model": "llama3",
        "system": "System instructions.",
        "prompt": "Prompt with password123",
        "stream": False,
    }
    req_gen = adapter.normalize_request(gen_payload)
    transformed_gen = NormalizedAIRequest(
        request_id=req_gen.request_id,
        model=req_gen.model,
        messages=[
            req_gen.messages[0],
            NormalizedMessage(
                role="user",
                content="Prompt with [REDACTED_SECRET]",
                source=ContentSource.USER,
            ),
        ],
        metadata=req_gen.metadata,
    )
    reconstructed_gen = adapter.denormalize_request(
        transformed_gen, original_request=gen_payload
    )
    assert reconstructed_gen["prompt"] == "Prompt with [REDACTED_SECRET]"
    assert reconstructed_gen["system"] == "System instructions."


def test_ollama_response_reconstruction(adapter: OllamaAdapter) -> None:
    """Requirement 9: response reconstruction for both chat and generate."""
    # Chat response
    chat_resp = {
        "model": "llama3",
        "message": {"role": "assistant", "content": "Old token123"},
        "done": True,
    }
    resp = adapter.normalize_response(chat_resp, request_id="req_1")
    transformed_resp = NormalizedAIResponse(
        request_id=resp.request_id,
        model=resp.model,
        content="New [REDACTED]",
        finish_reason=resp.finish_reason,
    )
    denorm = adapter.denormalize_response(transformed_resp, original_response=chat_resp)
    assert denorm["message"]["content"] == "New [REDACTED]"

    # Generate response
    gen_resp = {
        "model": "mistral",
        "response": "Old token123",
        "done": True,
    }
    resp_g = adapter.normalize_response(gen_resp, request_id="req_2")
    transformed_g = NormalizedAIResponse(
        request_id=resp_g.request_id,
        model=resp_g.model,
        content="New [REDACTED]",
        finish_reason=resp_g.finish_reason,
    )
    denorm_g = adapter.denormalize_response(transformed_g, original_response=gen_resp)
    assert denorm_g["response"] == "New [REDACTED]"


def test_ollama_streaming_rejected(adapter: OllamaAdapter) -> None:
    """Requirement: streaming requests explicitly rejected."""
    payload = {
        "model": "llama3",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": True,
    }
    with pytest.raises(UnsupportedStreamingError, match="Ollama streaming"):
        adapter.normalize_request(payload)


def test_ollama_unsupported_payload_error(adapter: OllamaAdapter) -> None:
    """Requirement: malformed payloads raise safe errors."""
    with pytest.raises(NormalizationError, match="missing required 'model'"):
        adapter.normalize_request({"messages": []})

    with pytest.raises(NormalizationError, match="either 'messages' or 'prompt'"):
        adapter.normalize_request({"model": "llama3"})

    with pytest.raises(
        UnsupportedPayloadError, match="missing both 'message' and 'response'"
    ):
        adapter.normalize_response({"model": "llama3"}, request_id="req_1")


def test_ollama_privacy_guarantees(adapter: OllamaAdapter) -> None:
    """Requirement 10: privacy guarantees."""
    payload = {
        "model": "llama3",
        "prompt": "Test prompt",
        "api_key": "ollama_internal_key",
        "Authorization": "Bearer secret",
    }
    req = adapter.normalize_request(payload)
    assert "api_key" not in req.parameters
    assert "Authorization" not in req.parameters
    assert "ollama_internal_key" not in str(req)
