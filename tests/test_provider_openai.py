"""Unit tests for OpenAI-compatible provider adapter.

Covers Section 39 requirements.
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
from aifirewall.providers.openai import OpenAIAdapter


@pytest.fixture
def adapter() -> OpenAIAdapter:
    return OpenAIAdapter()


def test_openai_identity(adapter: OpenAIAdapter) -> None:
    """Verify adapter name and version."""
    assert adapter.provider_name == "openai"
    assert adapter.adapter_version == "1.0.0"
    assert adapter.version == "1.0.0"


def test_openai_basic_request_normalization(adapter: OpenAIAdapter) -> None:
    """Requirement 1 & 3: basic request and user message normalization."""
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Explain quantum physics."}],
        "temperature": 0.7,
    }
    req = adapter.normalize_request(payload, request_id="req_test_123")
    assert isinstance(req, NormalizedAIRequest)
    assert req.request_id == "req_test_123"
    assert req.model == "gpt-4o"
    assert len(req.messages) == 1
    assert req.messages[0].role == "user"
    assert req.messages[0].content == "Explain quantum physics."
    assert req.messages[0].source == ContentSource.USER
    assert req.parameters.get("temperature") == 0.7


def test_openai_system_message_normalization(adapter: OpenAIAdapter) -> None:
    """Requirement 2: system message normalization."""
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful coding assistant."},
            {"role": "user", "content": "Write a python function."},
        ],
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 2
    assert req.messages[0].role == "system"
    assert req.messages[0].content == "You are a helpful coding assistant."
    assert req.messages[0].source == ContentSource.SYSTEM
    assert req.messages[1].role == "user"


def test_openai_assistant_and_tool_messages(adapter: OpenAIAdapter) -> None:
    """Requirement 4 & 5: assistant, tool message normalization and multiple turns."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "System prompt."},
            {"role": "user", "content": "What is the weather?"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_abc123",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": '{"location": "San Francisco"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_abc123",
                "content": '{"temperature": "65F"}',
            },
            {"role": "assistant", "content": "The weather is 65F."},
        ],
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 5
    assert req.messages[2].role == "assistant"
    assert req.messages[2].source == ContentSource.ASSISTANT
    assert req.messages[2].metadata["tool_calls"][0]["id"] == "call_abc123"
    assert req.messages[3].role == "tool"
    assert req.messages[3].source == ContentSource.TOOL_OUTPUT
    assert req.messages[3].content == '{"temperature": "65F"}'
    assert req.messages[4].role == "assistant"
    assert req.messages[4].content == "The weather is 65F."


def test_openai_multipart_text_extraction(adapter: OpenAIAdapter) -> None:
    """Requirement 6: multi-part content text extraction and non-text preservation."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this image:"},
                    {
                        "type": "image_url",
                        "image_url": {"url": "https://example.com/test.png"},
                    },
                    {"type": "text", "text": "Focus on details."},
                ],
            }
        ],
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 1
    # Text extracted and joined
    assert "Describe this image:" in req.messages[0].content
    assert "Focus on details." in req.messages[0].content
    # Non-text blocks preserved in metadata
    assert req.messages[0].metadata["is_multipart"] is True
    blocks = req.messages[0].metadata["blocks"]
    assert len(blocks) == 3
    assert blocks[1]["type"] == "image_url"


def test_openai_parameter_preservation(adapter: OpenAIAdapter) -> None:
    """Requirement 7: provider parameter preservation without credential leakage."""
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.2,
        "max_tokens": 150,
        "top_p": 0.95,
        "frequency_penalty": 0.5,
        "presence_penalty": 0.5,
        "seed": 42,
    }
    req = adapter.normalize_request(payload)
    assert req.parameters["temperature"] == 0.2
    assert req.parameters["max_tokens"] == 150
    assert req.parameters["top_p"] == 0.95
    assert req.parameters["frequency_penalty"] == 0.5
    assert req.parameters["presence_penalty"] == 0.5
    assert req.parameters["seed"] == 42


def test_openai_response_normalization(adapter: OpenAIAdapter) -> None:
    """Requirement 8, 9, 10: response normalization, text extraction, finish reason."""
    raw_response = {
        "id": "chatcmpl-987xyz",
        "object": "chat.completion",
        "created": 1677652288,
        "model": "gpt-4o-2024-05-13",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Paris is the capital of France.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 15,
            "completion_tokens": 8,
            "total_tokens": 23,
        },
    }
    resp = adapter.normalize_response(raw_response, request_id="req_fallback")
    assert isinstance(resp, NormalizedAIResponse)
    assert resp.request_id == "chatcmpl-987xyz"
    assert resp.model == "gpt-4o-2024-05-13"
    assert resp.content == "Paris is the capital of France."
    assert resp.finish_reason == "stop"
    assert resp.metadata["usage"]["total_tokens"] == 23


def test_openai_request_denormalization_and_roundtrip(adapter: OpenAIAdapter) -> None:
    """Requirement 11, 13: request denormalization and transformed text round-trip."""
    original_payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "My key is sk-dummy12345678901234567890."},
                    {"type": "image_url", "image_url": {"url": "data:..."}},
                ],
            },
        ],
        "temperature": 0.5,
    }
    req = adapter.normalize_request(original_payload)

    # Simulate redaction on the user message
    transformed_messages = [
        req.messages[0],
        NormalizedMessage(
            role="user",
            content="My key is [REDACTED_SECRET].",
            source=ContentSource.USER,
            metadata=req.messages[1].metadata,
        ),
    ]
    transformed_req = NormalizedAIRequest(
        request_id=req.request_id,
        model=req.model,
        messages=transformed_messages,
        parameters=req.parameters,
    )

    reconstructed = adapter.denormalize_request(
        transformed_req, original_request=original_payload
    )
    assert reconstructed["model"] == "gpt-4o"
    assert reconstructed["temperature"] == 0.5
    assert reconstructed["messages"][0]["content"] == "You are a helpful assistant."

    # Multi-part text block was updated while image block was preserved
    user_content = reconstructed["messages"][1]["content"]
    assert isinstance(user_content, list)
    assert user_content[0]["text"] == "My key is [REDACTED_SECRET]."
    assert user_content[1]["type"] == "image_url"


def test_openai_response_denormalization(adapter: OpenAIAdapter) -> None:
    """Requirement 12, 13: response denormalization with transformed content."""
    original_response = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 12345678,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "The password is supersecret123.",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"total_tokens": 10},
    }
    resp = adapter.normalize_response(original_response, request_id="req_1")

    # Simulate redaction
    transformed_resp = NormalizedAIResponse(
        request_id=resp.request_id,
        model=resp.model,
        content="The password is [REDACTED_SECRET].",
        finish_reason=resp.finish_reason,
    )

    denorm = adapter.denormalize_response(
        transformed_resp, original_response=original_response
    )
    assert denorm["id"] == "chatcmpl-test"
    assert (
        denorm["choices"][0]["message"]["content"]
        == "The password is [REDACTED_SECRET]."
    )
    assert denorm["usage"]["total_tokens"] == 10


def test_openai_unsupported_streaming(adapter: OpenAIAdapter) -> None:
    """Requirement 14: streaming requests are explicitly rejected."""
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hi"}],
        "stream": True,
    }
    with pytest.raises(
        UnsupportedStreamingError, match="streaming .* is not supported"
    ):
        adapter.normalize_request(payload)


def test_openai_invalid_payload_error(adapter: OpenAIAdapter) -> None:
    """Requirement 14: invalid structures raise safe NormalizationError."""
    with pytest.raises(NormalizationError, match="must be a JSON dictionary"):
        adapter.normalize_request("invalid")  # type: ignore[arg-type]

    with pytest.raises(NormalizationError, match="missing required 'model'"):
        adapter.normalize_request({"messages": []})

    with pytest.raises(NormalizationError, match="missing required 'messages'"):
        adapter.normalize_request({"model": "gpt-4o"})

    with pytest.raises(UnsupportedPayloadError, match="missing valid 'choices'"):
        adapter.normalize_response({"id": "123", "choices": []}, request_id="req_1")


def test_openai_privacy_no_credentials_in_metadata(adapter: OpenAIAdapter) -> None:
    """Requirement 15: no raw credentials appear in model metadata."""
    payload = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Test prompt"}],
        "Authorization": "Bearer sk-secret123",
        "api_key": "secret_key_xyz",
    }
    req = adapter.normalize_request(payload)
    # Check parameters and metadata
    assert "Authorization" not in req.parameters
    assert "api_key" not in req.parameters
    assert "Authorization" not in req.metadata
    assert "api_key" not in req.metadata
    assert "sk-secret123" not in str(req)
