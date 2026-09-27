"""Unit tests for Google Gemini-compatible provider adapter.

Covers Section 41 requirements.
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
from aifirewall.providers.gemini import GeminiAdapter


@pytest.fixture
def adapter() -> GeminiAdapter:
    return GeminiAdapter()


def test_gemini_identity(adapter: GeminiAdapter) -> None:
    """Verify provider identity and version."""
    assert adapter.provider_name == "gemini"
    assert adapter.adapter_version == "1.0.0"
    assert adapter.version == "1.0.0"


def test_gemini_request_normalization_and_role_mapping(adapter: GeminiAdapter) -> None:
    """Requirements 1 & 2: request normalization and role mapping."""
    payload = {
        "model": "gemini-1.5-pro",
        "contents": [
            {"role": "user", "parts": [{"text": "Hello Gemini"}]},
            {"role": "model", "parts": [{"text": "Hello human!"}]},
        ],
        "generationConfig": {"temperature": 0.4},
    }
    req = adapter.normalize_request(payload, request_id="req_gem_1")
    assert req.request_id == "req_gem_1"
    assert req.model == "gemini-1.5-pro"
    assert len(req.messages) == 2
    assert req.messages[0].role == "user"
    assert req.messages[0].source == ContentSource.USER
    assert req.messages[0].content == "Hello Gemini"

    # 'model' role mapped to 'assistant'
    assert req.messages[1].role == "assistant"
    assert req.messages[1].source == ContentSource.ASSISTANT
    assert req.messages[1].content == "Hello human!"
    assert req.parameters["generationConfig"]["temperature"] == 0.4


def test_gemini_system_instruction(adapter: GeminiAdapter) -> None:
    """Verify systemInstruction normalization into normalized system message."""
    payload = {
        "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
        "systemInstruction": {
            "role": "system",
            "parts": [{"text": "Act as a security expert."}],
        },
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 2
    assert req.messages[0].role == "system"
    assert req.messages[0].content == "Act as a security expert."
    assert req.messages[0].source == ContentSource.SYSTEM
    assert req.messages[1].role == "user"


def test_gemini_text_and_multiple_parts_extraction(adapter: GeminiAdapter) -> None:
    """Requirement 3, 4, 10: text part extraction and non-text part preservation."""
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "Analyze this data:"},
                    {"inlineData": {"mimeType": "image/jpeg", "data": "base64data..."}},
                    {"text": "Is it valid?"},
                ],
            }
        ]
    }
    req = adapter.normalize_request(payload)
    assert len(req.messages) == 1
    assert "Analyze this data:" in req.messages[0].content
    assert "Is it valid?" in req.messages[0].content
    assert req.messages[0].metadata["has_parts"] is True
    parts = req.messages[0].metadata["parts"]
    assert len(parts) == 3
    assert parts[1]["inlineData"]["mimeType"] == "image/jpeg"


def test_gemini_response_normalization(adapter: GeminiAdapter) -> None:
    """Requirement 5, 6, 7: response candidate extraction, text, finish reason."""
    raw_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "The secret code is 12345."}],
                    "role": "model",
                },
                "finishReason": "STOP",
                "index": 0,
                "safetyRatings": [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "probability": "NEGLIGIBLE",
                    }
                ],
            }
        ],
        "modelVersion": "gemini-1.5-flash",
    }
    resp = adapter.normalize_response(raw_response, request_id="req_123")
    assert resp.request_id == "req_123"
    assert resp.model == "gemini-1.5-flash"
    assert resp.content == "The secret code is 12345."
    assert resp.finish_reason == "STOP"
    assert "safetyRatings" in resp.metadata


def test_gemini_request_reconstruction_roundtrip(adapter: GeminiAdapter) -> None:
    """Requirement 8: reconstruction preserving non-text parts and system."""
    original_payload = {
        "model": "gemini-1.5-pro",
        "systemInstruction": {"role": "system", "parts": [{"text": "System rule."}]},
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "Key is sk-proj-dummy1234567890abcdef."},
                    {"inlineData": {"data": "bytes"}},
                ],
            }
        ],
    }
    req = adapter.normalize_request(original_payload)

    # Redact user text
    transformed_messages = [
        req.messages[0],  # system
        NormalizedMessage(
            role="user",
            content="Key is [REDACTED_SECRET].",
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
    assert reconstructed["systemInstruction"]["parts"][0]["text"] == "System rule."
    turn_parts = reconstructed["contents"][0]["parts"]
    assert turn_parts[0]["text"] == "Key is [REDACTED_SECRET]."
    assert turn_parts[1]["inlineData"]["data"] == "bytes"
    assert reconstructed["contents"][0]["role"] == "user"


def test_gemini_response_reconstruction(adapter: GeminiAdapter) -> None:
    """Requirement 9: response reconstruction with transformed text."""
    original_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Password: pass123"}],
                    "role": "model",
                },
                "finishReason": "STOP",
            }
        ],
        "modelVersion": "gemini-1.5",
    }
    resp = adapter.normalize_response(original_response, request_id="req_test")
    transformed_resp = NormalizedAIResponse(
        request_id=resp.request_id,
        model=resp.model,
        content="Password: [REDACTED_SECRET]",
        finish_reason=resp.finish_reason,
    )
    denorm = adapter.denormalize_response(
        transformed_resp, original_response=original_response
    )
    cand_parts = denorm["candidates"][0]["content"]["parts"]
    assert cand_parts[0]["text"] == "Password: [REDACTED_SECRET]"
    assert denorm["candidates"][0]["finishReason"] == "STOP"


def test_gemini_unsupported_streaming(adapter: GeminiAdapter) -> None:
    """Requirement 10: streaming rejected safely."""
    payload = {
        "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
        "stream": True,
    }
    with pytest.raises(UnsupportedStreamingError, match="Gemini streaming"):
        adapter.normalize_request(payload)


def test_gemini_unsupported_payload_error(adapter: GeminiAdapter) -> None:
    """Requirement 10: invalid payload raises NormalizationError."""
    with pytest.raises(NormalizationError, match="missing required 'contents'"):
        adapter.normalize_request({"model": "gemini"})

    with pytest.raises(UnsupportedPayloadError, match="missing valid 'candidates'"):
        adapter.normalize_response({"candidates": []}, request_id="req_1")


def test_gemini_privacy_guarantees(adapter: GeminiAdapter) -> None:
    """Requirement 11: no credentials leak into model parameters or metadata."""
    payload = {
        "contents": [{"role": "user", "parts": [{"text": "Safe text"}]}],
        "key": "AIzaSyDummySecretKey1234567890",
    }
    req = adapter.normalize_request(payload)
    assert "key" not in req.parameters
    assert "AIzaSyDummySecretKey1234567890" not in str(req)
