"""Unit tests for Anthropic-compatible provider adapter.

Covers Section 40 requirements.
"""

import pytest

from aifirewall.core.types import ContentSource
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.providers.anthropic import AnthropicAdapter
from aifirewall.providers.errors import (
    NormalizationError,
    UnsupportedPayloadError,
    UnsupportedStreamingError,
)


@pytest.fixture
def adapter() -> AnthropicAdapter:
    return AnthropicAdapter()


def test_anthropic_identity(adapter: AnthropicAdapter) -> None:
    """Verify provider identity and version."""
    assert adapter.provider_name == "anthropic"
    assert adapter.adapter_version == "1.0.0"
    assert adapter.version == "1.0.0"


def test_anthropic_request_normalization_and_roles(adapter: AnthropicAdapter) -> None:
    """Requirement 1 & 3: request normalization and role mapping."""
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": "Hello Claude"},
            {"role": "assistant", "content": "Hello! How can I help you?"},
        ],
    }
    req = adapter.normalize_request(payload, request_id="req_ant_1")
    assert req.request_id == "req_ant_1"
    assert req.model == "claude-3-5-sonnet-20241022"
    assert len(req.messages) == 2
    assert req.messages[0].role == "user"
    assert req.messages[0].source == ContentSource.USER
    assert req.messages[1].role == "assistant"
    assert req.messages[1].source == ContentSource.ASSISTANT
    assert req.parameters["max_tokens"] == 1024


def test_anthropic_system_instruction_mapping(adapter: AnthropicAdapter) -> None:
    """Requirement 2: system instruction mapping (string and block format)."""
    # 1. String system
    payload_str = {
        "model": "claude-3-haiku",
        "system": "You are a concise assistant.",
        "messages": [{"role": "user", "content": "Hi"}],
    }
    req_str = adapter.normalize_request(payload_str)
    assert len(req_str.messages) == 2
    assert req_str.messages[0].role == "system"
    assert req_str.messages[0].source == ContentSource.SYSTEM
    assert req_str.messages[0].content == "You are a concise assistant."
    assert req_str.messages[1].role == "user"

    # 2. Block system
    payload_blocks = {
        "model": "claude-3-haiku",
        "system": [
            {"type": "text", "text": "Part 1."},
            {"type": "text", "text": "Part 2."},
        ],
        "messages": [{"role": "user", "content": "Hi"}],
    }
    req_blocks = adapter.normalize_request(payload_blocks)
    assert req_blocks.messages[0].content == "Part 1.\nPart 2."


def test_anthropic_multiblock_and_non_text_preservation(
    adapter: AnthropicAdapter,
) -> None:
    """Requirements 4 & 5: multi-block text and non-text preservation."""
    payload = {
        "model": "claude-3-opus",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Look at this chart:"},
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": "iVBORw0KGgoAAAANSUhEUgAA...",
                        },
                    },
                    {"type": "text", "text": "What does it show?"},
                ],
            }
        ],
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 1
    assert "Look at this chart:" in req.messages[0].content
    assert "What does it show?" in req.messages[0].content
    # Non-text block preserved
    assert req.messages[0].metadata["is_multipart"] is True
    blocks = req.messages[0].metadata["blocks"]
    assert len(blocks) == 3
    assert blocks[1]["type"] == "image"
    assert blocks[1]["source"]["media_type"] == "image/png"


def test_anthropic_response_normalization(adapter: AnthropicAdapter) -> None:
    """Requirement 6, 7, 8: response normalization, content blocks, finish reason."""
    raw_response = {
        "id": "msg_01XFDUDYJgAACzvnptvVoYEE",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": "The answer is 42."}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 12,
            "output_tokens": 8,
        },
    }
    resp = adapter.normalize_response(raw_response, request_id="req_fallback")
    assert resp.request_id == "msg_01XFDUDYJgAACzvnptvVoYEE"
    assert resp.model == "claude-3-5-sonnet-20241022"
    assert resp.content == "The answer is 42."
    assert resp.finish_reason == "end_turn"
    assert resp.metadata["usage"]["output_tokens"] == 8


def test_anthropic_denormalization_and_reconstruction(
    adapter: AnthropicAdapter,
) -> None:
    """Requirement 9, 10: denormalization and transformed content reconstruction."""
    original_payload = {
        "model": "claude-3-5-sonnet-20241022",
        "system": "System instructions here.",
        "max_tokens": 500,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Secret: sk-dummy12345678901234567890"},
                    {"type": "image", "source": {"data": "..."}},
                ],
            }
        ],
    }
    req = adapter.normalize_request(original_payload)

    # Simulate redaction
    transformed_messages = [
        req.messages[0],  # system message
        NormalizedMessage(
            role="user",
            content="Secret: [REDACTED_SECRET]",
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
    assert reconstructed["model"] == "claude-3-5-sonnet-20241022"
    assert reconstructed["system"] == "System instructions here."
    assert reconstructed["max_tokens"] == 500
    user_blocks = reconstructed["messages"][0]["content"]
    assert user_blocks[0]["text"] == "Secret: [REDACTED_SECRET]"
    assert user_blocks[1]["type"] == "image"


def test_anthropic_response_denormalization(adapter: AnthropicAdapter) -> None:
    """Requirement 9 & 10: response denormalization with transformed content."""
    original_response = {
        "id": "msg_123",
        "type": "message",
        "role": "assistant",
        "model": "claude-3",
        "content": [{"type": "text", "text": "Original text with token123"}],
        "stop_reason": "end_turn",
    }
    resp = adapter.normalize_response(original_response, request_id="req_1")

    transformed_resp = NormalizedAIResponse(
        request_id=resp.request_id,
        model=resp.model,
        content="Original text with [REDACTED_SECRET]",
        finish_reason=resp.finish_reason,
    )
    rebuilt = adapter.denormalize_response(
        transformed_resp, original_response=original_response
    )
    assert rebuilt["id"] == "msg_123"
    assert rebuilt["content"][0]["text"] == "Original text with [REDACTED_SECRET]"
    assert rebuilt["stop_reason"] == "end_turn"


def test_anthropic_unsupported_streaming(adapter: AnthropicAdapter) -> None:
    """Requirement 11: streaming requests are explicitly rejected."""
    payload = {
        "model": "claude-3",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": True,
    }
    with pytest.raises(UnsupportedStreamingError, match="Anthropic streaming"):
        adapter.normalize_request(payload)


def test_anthropic_unsupported_content_error(adapter: AnthropicAdapter) -> None:
    """Requirement 11: invalid payloads raise safe NormalizationError."""
    with pytest.raises(NormalizationError, match="must be a JSON dictionary"):
        adapter.normalize_request([1, 2, 3])  # type: ignore[arg-type]

    with pytest.raises(NormalizationError, match="missing required 'model'"):
        adapter.normalize_request({"messages": []})

    with pytest.raises(UnsupportedPayloadError, match="missing valid 'content'"):
        adapter.normalize_response({"id": "123"}, request_id="req_1")


def test_anthropic_privacy_guarantees(adapter: AnthropicAdapter) -> None:
    """Requirement 12: privacy guarantees - credentials and auth headers omitted."""
    payload = {
        "model": "claude-3",
        "messages": [{"role": "user", "content": "Clean prompt"}],
        "x-api-key": "secret-anthropic-key",
        "Authorization": "Bearer token",
    }
    req = adapter.normalize_request(payload)
    assert "x-api-key" not in req.parameters
    assert "Authorization" not in req.parameters
    assert "secret-anthropic-key" not in str(req)
