"""OpenAI-compatible request and response adapter for AI Data Firewall.

Converts between OpenAI chat completion payloads (/v1/chat/completions)
and normalized domain models (NormalizedAIRequest, NormalizedAIResponse).

Architectural Rule:
- Translator only: no detection, no policy, no redaction.
- Preserves multi-part content and tool call structures.
- Fails closed and safely rejects streaming requests (stream=True).
"""

import copy
import uuid
from typing import Any

from aifirewall.core.types import ContentSource
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.providers.base import BaseProviderAdapter
from aifirewall.providers.errors import (
    NormalizationError,
    UnsupportedPayloadError,
    UnsupportedStreamingError,
)

OPENAI_SAFE_PARAMETERS: frozenset[str] = frozenset(
    {
        "temperature",
        "top_p",
        "n",
        "max_tokens",
        "max_completion_tokens",
        "stop",
        "presence_penalty",
        "frequency_penalty",
        "logit_bias",
        "user",
        "response_format",
        "seed",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
    }
)


class OpenAIAdapter(BaseProviderAdapter):
    """Adapter translating between OpenAI-compatible JSON and normalized models."""

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return "openai"

    @property
    def adapter_version(self) -> str:
        """Adapter implementation version."""
        return "1.0.0"

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine if raw payload matches OpenAI chat completion structure."""
        if not isinstance(raw_request, dict):
            return False
        # Gemini uses 'contents', Ollama /api/generate uses 'prompt'
        if "contents" in raw_request:
            return False
        if "messages" not in raw_request or not isinstance(
            raw_request["messages"], list
        ):
            return False
        if "model" not in raw_request or not isinstance(raw_request["model"], str):
            return False
        # Check messages shape
        for msg in raw_request["messages"]:
            if isinstance(msg, dict) and "role" in msg:
                return True
        return len(raw_request["messages"]) == 0

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert OpenAI chat completion request to NormalizedAIRequest."""
        if not isinstance(raw_request, dict):
            raise NormalizationError(
                "OpenAI request payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        if raw_request.get("stream") is True:
            raise UnsupportedStreamingError(
                "OpenAI streaming (stream=True) is not supported.",
                provider=self.provider_name,
            )

        model = raw_request.get("model")
        if not model or not isinstance(model, str) or not model.strip():
            raise NormalizationError(
                "OpenAI request missing required 'model' string.",
                provider=self.provider_name,
                field="model",
            )

        raw_messages = raw_request.get("messages")
        if not isinstance(raw_messages, list):
            raise NormalizationError(
                "OpenAI request missing required 'messages' list.",
                provider=self.provider_name,
                field="messages",
            )

        req_id = (
            request_id.strip()
            if request_id and request_id.strip()
            else f"req_{uuid.uuid4().hex[:16]}"
        )

        norm_messages: list[NormalizedMessage] = []
        for idx, raw_msg in enumerate(raw_messages):
            if not isinstance(raw_msg, dict):
                raise NormalizationError(
                    f"Message at index {idx} must be a dictionary.",
                    provider=self.provider_name,
                    field=f"messages[{idx}]",
                )

            role = raw_msg.get("role")
            if not role or not isinstance(role, str) or not role.strip():
                raise NormalizationError(
                    f"Message at index {idx} has invalid or missing 'role'.",
                    provider=self.provider_name,
                    field=f"messages[{idx}].role",
                )

            source = self._map_role_to_source(role)
            content_val = raw_msg.get("content")
            meta: dict[str, Any] = {}

            if "name" in raw_msg:
                meta["name"] = str(raw_msg["name"])
            if "tool_calls" in raw_msg and isinstance(raw_msg["tool_calls"], list):
                meta["tool_calls"] = copy.deepcopy(raw_msg["tool_calls"])
            if "tool_call_id" in raw_msg:
                meta["tool_call_id"] = str(raw_msg["tool_call_id"])

            if isinstance(content_val, str):
                text_content = content_val
            elif isinstance(content_val, list):
                # Multi-part content blocks (text + image_url / audio etc.)
                meta["is_multipart"] = True
                meta["blocks"] = copy.deepcopy(content_val)
                text_parts: list[str] = []
                for block in content_val:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_parts.append(str(block.get("text", "")))
                text_content = "\n".join(text_parts)
            elif content_val is None:
                # Assistant tool call messages may have content=None
                text_content = ""
            else:
                val_type = type(content_val).__name__
                raise NormalizationError(
                    f"Unsupported content type {val_type!r} at message {idx}.",
                    provider=self.provider_name,
                    field=f"messages[{idx}].content",
                )

            norm_messages.append(
                NormalizedMessage(
                    role=role,
                    content=text_content,
                    source=source,
                    metadata=meta,
                )
            )

        # Extract allowed parameters without storing credentials
        safe_params: dict[str, Any] = {}
        for param_key in OPENAI_SAFE_PARAMETERS:
            if param_key in raw_request:
                safe_params[param_key] = copy.deepcopy(raw_request[param_key])

        return NormalizedAIRequest(
            request_id=req_id,
            model=model.strip(),
            messages=norm_messages,
            parameters=safe_params,
            metadata={"provider": self.provider_name},
        )

    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to OpenAI chat completion JSON."""
        if original_request is not None:
            result = copy.deepcopy(original_request)
            result["model"] = request.model
            new_messages: list[dict[str, Any]] = []

            for idx, norm_msg in enumerate(request.messages):
                orig_msg = (
                    result.get("messages", [])[idx]
                    if idx < len(result.get("messages", []))
                    else {}
                )
                msg_dict = copy.deepcopy(orig_msg) if isinstance(orig_msg, dict) else {}
                msg_dict["role"] = norm_msg.role

                if (
                    norm_msg.metadata.get("is_multipart")
                    and "blocks" in norm_msg.metadata
                ):
                    blocks = copy.deepcopy(norm_msg.metadata["blocks"])
                    # Update text blocks with transformed content
                    updated = False
                    for block in blocks:
                        if isinstance(block, dict) and block.get("type") == "text":
                            block["text"] = norm_msg.content
                            updated = True
                            break
                    if not updated:
                        blocks.insert(0, {"type": "text", "text": norm_msg.content})
                    msg_dict["content"] = blocks
                else:
                    msg_dict["content"] = norm_msg.content

                new_messages.append(msg_dict)

            result["messages"] = new_messages
            return result

        # Construct from normalized request fields
        rebuilt_messages: list[dict[str, Any]] = []
        for norm_msg in request.messages:
            msg_dict = {"role": norm_msg.role}
            if norm_msg.metadata.get("is_multipart") and "blocks" in norm_msg.metadata:
                blocks = copy.deepcopy(norm_msg.metadata["blocks"])
                for block in blocks:
                    if isinstance(block, dict) and block.get("type") == "text":
                        block["text"] = norm_msg.content
                        break
                msg_dict["content"] = blocks
            else:
                msg_dict["content"] = norm_msg.content

            if "name" in norm_msg.metadata:
                msg_dict["name"] = norm_msg.metadata["name"]
            if "tool_calls" in norm_msg.metadata:
                msg_dict["tool_calls"] = norm_msg.metadata["tool_calls"]
            if "tool_call_id" in norm_msg.metadata:
                msg_dict["tool_call_id"] = norm_msg.metadata["tool_call_id"]

            rebuilt_messages.append(msg_dict)

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": rebuilt_messages,
        }
        payload.update(copy.deepcopy(request.parameters))
        return payload

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert OpenAI response JSON to NormalizedAIResponse."""
        if not isinstance(raw_response, dict):
            raise NormalizationError(
                "OpenAI response payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        choices = raw_response.get("choices")
        if not isinstance(choices, list) or not choices:
            raise UnsupportedPayloadError(
                "OpenAI response missing valid 'choices' list.",
                provider=self.provider_name,
                field="choices",
            )

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise NormalizationError(
                "OpenAI response choice must be a dictionary.",
                provider=self.provider_name,
                field="choices[0]",
            )

        message = first_choice.get("message", {})
        if not isinstance(message, dict):
            raise NormalizationError(
                "OpenAI response choice missing 'message' object.",
                provider=self.provider_name,
                field="choices[0].message",
            )

        content = message.get("content") or ""
        finish_reason = first_choice.get("finish_reason")
        model = str(raw_response.get("model", ""))
        resp_id = str(raw_response.get("id") or request_id)

        meta: dict[str, Any] = {"provider": self.provider_name}
        if "usage" in raw_response and isinstance(raw_response["usage"], dict):
            meta["usage"] = copy.deepcopy(raw_response["usage"])
        if "object" in raw_response:
            meta["object"] = str(raw_response["object"])

        return NormalizedAIResponse(
            request_id=resp_id,
            model=model,
            content=str(content),
            finish_reason=str(finish_reason) if finish_reason else None,
            metadata=meta,
        )

    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to OpenAI response JSON."""
        if original_response is not None:
            result = copy.deepcopy(original_response)
            if (
                "choices" in result
                and isinstance(result["choices"], list)
                and result["choices"]
            ):
                if isinstance(result["choices"][0], dict):
                    msg = result["choices"][0].setdefault("message", {})
                    if isinstance(msg, dict):
                        msg["content"] = response.content
            return result

        return {
            "id": response.request_id,
            "object": "chat.completion",
            "model": response.model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": response.content,
                    },
                    "finish_reason": response.finish_reason or "stop",
                }
            ],
        }

    @staticmethod
    def _map_role_to_source(role: str) -> ContentSource:
        """Map standard OpenAI message role string to ContentSource enum."""
        norm_role = role.strip().lower()
        if norm_role == "system":
            return ContentSource.SYSTEM
        if norm_role == "user":
            return ContentSource.USER
        if norm_role == "assistant":
            return ContentSource.ASSISTANT
        if norm_role in ("tool", "function"):
            return ContentSource.TOOL_OUTPUT
        return ContentSource.UNKNOWN
