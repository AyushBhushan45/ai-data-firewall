"""Cross-provider security consistency tests.

Verifies Section 67 requirement:
For equivalent semantic content across OpenAI, Anthropic, Gemini, and Ollama:
- The same synthetic secret in a user message is detected as DetectionCategory.SECRET.
- The same policy engine and rules apply uniformly without provider-specific rules.
- Redaction and denormalization eliminate the secret across all 4 provider formats.
"""

from dataclasses import replace
from typing import Any

from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)
from aifirewall.detectors.base import DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.content import ContentLocation
from aifirewall.models.request import NormalizedAIRequest
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyContext, PolicyRule
from aifirewall.providers.anthropic import AnthropicAdapter
from aifirewall.providers.gemini import GeminiAdapter
from aifirewall.providers.ollama import OllamaAdapter
from aifirewall.providers.openai import OpenAIAdapter
from aifirewall.transformation.redaction import RedactionEngine

SYNTHETIC_SECRET = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SYNTHETIC_RESPONSE_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _build_provider_requests(
    secret_text: str,
) -> dict[str, tuple[Any, dict[str, Any]]]:
    """Return (adapter, raw_payload) for each provider with user secret."""
    user_prompt = f"Please use this token to authenticate: {secret_text}."

    openai_payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_prompt},
        ],
    }

    anthropic_payload = {
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a helpful assistant.",
        "messages": [
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 1024,
    }

    gemini_payload = {
        "systemInstruction": {"parts": [{"text": "You are a helpful assistant."}]},
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_prompt}],
            }
        ],
    }

    ollama_payload = {
        "model": "llama3",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": user_prompt},
        ],
    }

    return {
        "openai": (OpenAIAdapter(), openai_payload),
        "anthropic": (AnthropicAdapter(), anthropic_payload),
        "gemini": (GeminiAdapter(), gemini_payload),
        "ollama": (OllamaAdapter(), ollama_payload),
    }


def _build_provider_responses(
    secret_text: str,
) -> dict[str, tuple[Any, dict[str, Any]]]:
    """Return (adapter, raw_payload) for each provider with model secret."""
    assistant_text = f"Found the credential: {secret_text} for deployment."

    openai_resp = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": assistant_text},
                "finish_reason": "stop",
            }
        ],
    }

    anthropic_resp = {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": assistant_text}],
        "stop_reason": "end_turn",
    }

    gemini_resp = {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"text": assistant_text}],
                },
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "modelVersion": "gemini-1.5-pro",
    }

    ollama_resp = {
        "model": "llama3",
        "message": {"role": "assistant", "content": assistant_text},
        "done": True,
        "done_reason": "stop",
    }

    return {
        "openai": (OpenAIAdapter(), openai_resp),
        "anthropic": (AnthropicAdapter(), anthropic_resp),
        "gemini": (GeminiAdapter(), gemini_resp),
        "ollama": (OllamaAdapter(), ollama_resp),
    }


def test_cross_provider_request_secret_detection_consistency() -> None:
    """The same secret in a user message across 4 providers yields same finding."""
    providers = _build_provider_requests(SYNTHETIC_SECRET)
    detector = SecretDetector()

    for provider_name, (adapter, payload) in providers.items():
        norm_req: NormalizedAIRequest = adapter.normalize_request(
            payload, request_id="req-test"
        )

        # Inspect all messages
        all_findings = []
        for i, msg in enumerate(norm_req.messages):
            ctx = DetectorContext(
                request_id="req-test",
                direction=ContentDirection.REQUEST,
                source=msg.source,
                location=ContentLocation(source=msg.source, message_index=i),
            )
            findings = detector.detect(msg.content, ctx)
            all_findings.extend(findings)

        assert len(all_findings) == 1, (
            f"Provider {provider_name} should produce 1 finding, "
            f"got {len(all_findings)}"
        )
        finding = all_findings[0]
        assert finding.category == DetectionCategory.SECRET, (
            f"Provider {provider_name} finding category should be SECRET"
        )
        assert finding.severity == Severity.HIGH, (
            f"Provider {provider_name} finding severity should be HIGH"
        )
        assert (
            finding.location.char_start is not None
            and finding.location.char_end is not None
        )
        # Verify span correctly identifies synthetic secret in original content
        user_msg = [m for m in norm_req.messages if m.source == ContentSource.USER][0]
        assert (
            user_msg.content[finding.location.char_start : finding.location.char_end]
            == SYNTHETIC_SECRET
        )


def test_cross_provider_policy_block_consistency() -> None:
    """A blocking policy rule produces BLOCK action across all providers uniformly."""
    providers = _build_provider_requests(SYNTHETIC_SECRET)
    detector = SecretDetector()
    policy_engine = PolicyEngine(
        PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="block-all-secrets",
                    category=DetectionCategory.SECRET,
                    action=PolicyAction.BLOCK,
                )
            ]
        )
    )

    for provider_name, (adapter, payload) in providers.items():
        norm_req: NormalizedAIRequest = adapter.normalize_request(
            payload, request_id="req-test"
        )
        findings = []
        for i, msg in enumerate(norm_req.messages):
            findings.extend(
                detector.detect(
                    msg.content,
                    DetectorContext(
                        request_id="req-test",
                        direction=ContentDirection.REQUEST,
                        source=msg.source,
                        location=ContentLocation(source=msg.source, message_index=i),
                    ),
                )
            )

        decision = policy_engine.evaluate(
            findings,
            PolicyContext(
                direction=ContentDirection.REQUEST,
                source=ContentSource.USER,
            ),
        )
        assert decision.action == PolicyAction.BLOCK, (
            f"Provider {provider_name} policy action should be BLOCK"
        )


def test_cross_provider_request_redaction_consistency() -> None:
    """A redaction policy produces redacted output that safely round-trips."""
    providers = _build_provider_requests(SYNTHETIC_SECRET)
    detector = SecretDetector()
    policy_engine = PolicyEngine(
        PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="redact-all-secrets",
                    category=DetectionCategory.SECRET,
                    action=PolicyAction.REDACT,
                )
            ]
        )
    )
    redaction_engine = RedactionEngine()

    for provider_name, (adapter, payload) in providers.items():
        norm_req: NormalizedAIRequest = adapter.normalize_request(
            payload, request_id="req-test"
        )

        # Detect per message
        new_messages = []
        for i, msg in enumerate(norm_req.messages):
            ctx = DetectorContext(
                request_id="req-test",
                direction=ContentDirection.REQUEST,
                source=msg.source,
                location=ContentLocation(source=msg.source, message_index=i),
            )
            findings = detector.detect(msg.content, ctx)
            decision = policy_engine.evaluate(
                findings,
                PolicyContext(
                    direction=ContentDirection.REQUEST,
                    source=msg.source,
                ),
            )
            if decision.action == PolicyAction.REDACT:
                redacted_res = redaction_engine.redact(
                    msg.content, decision.detections, decision
                )
                new_msg = replace(msg, content=redacted_res.content)
                new_messages.append(new_msg)
            else:
                new_messages.append(msg)

        transformed_req = replace(norm_req, messages=new_messages)
        denorm_payload = adapter.denormalize_request(transformed_req)

        # Assert secret is strictly absent from the denormalized payload
        import json

        raw_serialized = json.dumps(denorm_payload)
        assert SYNTHETIC_SECRET not in raw_serialized, (
            f"Provider {provider_name} leaked secret in denormalized request"
        )
        assert "[REDACTED_SECRET]" in raw_serialized, (
            f"Provider {provider_name} missing placeholder in denormalized request"
        )


def test_cross_provider_response_redaction_consistency() -> None:
    """The same secret in a model response is redacted uniformly across providers."""
    providers = _build_provider_responses(SYNTHETIC_RESPONSE_SECRET)
    detector = SecretDetector()
    policy_engine = PolicyEngine(
        PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="redact-response-secrets",
                    category=DetectionCategory.SECRET,
                    action=PolicyAction.REDACT,
                )
            ]
        )
    )
    redaction_engine = RedactionEngine()

    for provider_name, (adapter, payload) in providers.items():
        norm_resp: NormalizedAIResponse = adapter.normalize_response(
            payload, request_id="resp-test"
        )

        ctx = DetectorContext(
            request_id="resp-test",
            direction=ContentDirection.RESPONSE,
            source=ContentSource.ASSISTANT,
            location=ContentLocation(source=ContentSource.ASSISTANT),
        )
        findings = detector.detect(norm_resp.content, ctx)
        assert len(findings) == 1, (
            f"Provider {provider_name} should detect 1 secret, got {len(findings)}"
        )
        assert (
            findings[0].location.char_start is not None
            and findings[0].location.char_end is not None
        )
        assert (
            norm_resp.content[
                findings[0].location.char_start : findings[0].location.char_end
            ]
            == SYNTHETIC_RESPONSE_SECRET
        )

        decision = policy_engine.evaluate(
            findings,
            PolicyContext(
                direction=ContentDirection.RESPONSE,
                source=ContentSource.ASSISTANT,
            ),
        )
        assert decision.action == PolicyAction.REDACT

        redacted_res = redaction_engine.redact(
            norm_resp.content, decision.detections, decision
        )
        transformed_resp = replace(norm_resp, content=redacted_res.content)
        denorm_resp = adapter.denormalize_response(transformed_resp)

        import json

        raw_serialized = json.dumps(denorm_resp)
        assert SYNTHETIC_RESPONSE_SECRET not in raw_serialized, (
            f"Provider {provider_name} leaked secret in denormalized response"
        )
        assert "[REDACTED_SECRET]" in raw_serialized, (
            f"Provider {provider_name} missing placeholder in denormalized response"
        )
