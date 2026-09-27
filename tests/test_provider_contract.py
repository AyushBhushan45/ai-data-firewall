"""Cross-provider contract tests verifying consistent behavior across all adapters.

Enforces Section 43 & 44 requirements:
- Common interface contract adherence
- Valid payloads normalized to canonical models
- Textual preservation and deterministic round-trips
- Safe rejection of invalid and streaming payloads
- Zero network calls and zero credential leakage
"""

from typing import Any

import pytest

from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.providers import (
    AnthropicAdapter,
    GeminiAdapter,
    OllamaAdapter,
    OpenAIAdapter,
    ProviderAdapter,
    UnsupportedStreamingError,
)

# Canonical synthetic test payloads for each provider representing the
# same semantic task:
# System: "You are an assistant."
# User: "Tell me a joke."
# Assistant: "Why did the chicken cross the road?"
SAMPLE_REQUESTS: dict[str, dict[str, Any]] = {
    "openai": {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are an assistant."},
            {"role": "user", "content": "Tell me a joke."},
        ],
        "temperature": 0.7,
    },
    "anthropic": {
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are an assistant.",
        "messages": [
            {"role": "user", "content": "Tell me a joke."},
        ],
        "max_tokens": 100,
    },
    "gemini": {
        "model": "gemini-1.5-pro",
        "systemInstruction": {
            "role": "system",
            "parts": [{"text": "You are an assistant."}],
        },
        "contents": [
            {"role": "user", "parts": [{"text": "Tell me a joke."}]},
        ],
    },
    "ollama": {
        "model": "llama3",
        "messages": [
            {"role": "system", "content": "You are an assistant."},
            {"role": "user", "content": "Tell me a joke."},
        ],
        "stream": False,
    },
}

SAMPLE_RESPONSES: dict[str, dict[str, Any]] = {
    "openai": {
        "id": "chatcmpl-contract",
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Why did the chicken cross the road?",
                },
                "finish_reason": "stop",
            }
        ],
    },
    "anthropic": {
        "id": "msg_contract",
        "model": "claude-3-5-sonnet-20241022",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "Why did the chicken cross the road?"}],
        "stop_reason": "end_turn",
    },
    "gemini": {
        "modelVersion": "gemini-1.5-pro",
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": "Why did the chicken cross the road?"}],
                },
                "finishReason": "STOP",
            }
        ],
    },
    "ollama": {
        "model": "llama3",
        "message": {
            "role": "assistant",
            "content": "Why did the chicken cross the road?",
        },
        "done": True,
        "done_reason": "stop",
    },
}

STREAMING_PAYLOADS: dict[str, dict[str, Any]] = {
    "openai": {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    },
    "anthropic": {
        "model": "claude-3",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    },
    "gemini": {
        "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "stream": True,
    },
    "ollama": {
        "model": "llama3",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": True,
    },
}


@pytest.fixture(params=[OpenAIAdapter, AnthropicAdapter, GeminiAdapter, OllamaAdapter])
def adapter_instance(request: pytest.FixtureRequest) -> ProviderAdapter:
    cls = request.param
    return cls()


def test_contract_identity_and_version(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must expose provider_name and semantic adapter_version."""
    assert isinstance(adapter_instance.provider_name, str)
    assert len(adapter_instance.provider_name) > 0
    assert isinstance(adapter_instance.adapter_version, str)
    assert adapter_instance.adapter_version == adapter_instance.version
    assert "1.0.0" in adapter_instance.adapter_version


def test_contract_can_handle_request(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must recognize its own sample payload and reject others."""
    p_name = adapter_instance.provider_name
    own_payload = SAMPLE_REQUESTS[p_name]
    assert adapter_instance.can_handle_request(own_payload) is True

    # Non-dict must return False
    assert adapter_instance.can_handle_request({}) is False  # type: ignore[arg-type]


def test_contract_normalize_request(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must normalize valid sample request to NormalizedAIRequest."""
    p_name = adapter_instance.provider_name
    payload = SAMPLE_REQUESTS[p_name]

    req = adapter_instance.normalize_request(payload, request_id="contract_test_req")
    assert isinstance(req, NormalizedAIRequest)
    assert req.request_id == "contract_test_req"
    assert len(req.model) > 0
    assert len(req.messages) >= 1

    # Verify message contents are preserved
    user_msg = next((m for m in req.messages if m.role == "user"), None)
    assert user_msg is not None
    assert user_msg.content == "Tell me a joke."


def test_contract_normalize_response(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must normalize valid sample response to NormalizedAIResponse."""
    p_name = adapter_instance.provider_name
    payload = SAMPLE_RESPONSES[p_name]

    resp = adapter_instance.normalize_response(payload, request_id="contract_resp")
    assert isinstance(resp, NormalizedAIResponse)
    assert resp.content == "Why did the chicken cross the road?"
    assert resp.finish_reason is not None


def test_contract_deterministic_roundtrip(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must support deterministic round-trip transformation."""
    p_name = adapter_instance.provider_name
    orig_req = SAMPLE_REQUESTS[p_name]

    normalized = adapter_instance.normalize_request(orig_req)

    # Redact user message text
    new_messages = []
    for m in normalized.messages:
        if m.role == "user":
            new_messages.append(
                NormalizedMessage(
                    role=m.role,
                    content="Tell me a [REDACTED_SECRET].",
                    source=m.source,
                    metadata=m.metadata,
                )
            )
        else:
            new_messages.append(m)

    transformed_req = NormalizedAIRequest(
        request_id=normalized.request_id,
        model=normalized.model,
        messages=new_messages,
        parameters=normalized.parameters,
        metadata=normalized.metadata,
    )

    reconstructed = adapter_instance.denormalize_request(
        transformed_req, original_request=orig_req
    )

    # Re-normalize reconstructed payload
    roundtrip_norm = adapter_instance.normalize_request(reconstructed)
    roundtrip_user = next(
        (m for m in roundtrip_norm.messages if m.role == "user"), None
    )
    assert roundtrip_user is not None
    assert "[REDACTED_SECRET]" in roundtrip_user.content


def test_contract_streaming_rejection(adapter_instance: ProviderAdapter) -> None:
    """Every adapter must reject stream=True with UnsupportedStreamingError."""
    p_name = adapter_instance.provider_name
    stream_payload = STREAMING_PAYLOADS[p_name]

    with pytest.raises(UnsupportedStreamingError):
        adapter_instance.normalize_request(stream_payload)


def test_contract_no_credential_leakage(adapter_instance: ProviderAdapter) -> None:
    """Adapters must never store sensitive headers or keys in parameters."""
    p_name = adapter_instance.provider_name
    dirty_payload = dict(SAMPLE_REQUESTS[p_name])
    dirty_payload["Authorization"] = "Bearer confidential_token_xyz"
    dirty_payload["api_key"] = "confidential_api_key_123"

    req = adapter_instance.normalize_request(dirty_payload)
    assert "Authorization" not in req.parameters
    assert "api_key" not in req.parameters
    assert "Authorization" not in req.metadata
    assert "api_key" not in req.metadata
    assert "confidential_token_xyz" not in str(req)
    assert "confidential_api_key_123" not in str(req)
