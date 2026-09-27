"""Anthropic-compatible request and response adapter for AI Data Firewall.

Converts between Anthropic Messages API payloads (/v1/messages)
and normalized domain models (NormalizedAIRequest, NormalizedAIResponse).

Architectural Rule:
- Translator only: no detection, no policy, no redaction.
- Preserves top-level system instructions and rich content blocks (image, tool_use).
- Safely rejects streaming requests (stream=True).
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

ANTHROPIC_SAFE_PARAMETERS: frozenset[str] = frozenset(
    {
        "max_tokens",
        "temperature",
        "top_p",
        "top_k",
        "stop_sequences",
        "tools",
        "tool_choice",
        "metadata",
    }
)


class AnthropicAdapter(BaseProviderAdapter):
    """Adapter translating between Anthropic-compatible JSON and normalized models."""

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return "anthropic"

    @property
    def adapter_version(self) -> str:
        """Adapter implementation version."""
        return "1.0.0"

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine if raw payload matches Anthropic Messages API structure."""
        if not isinstance(raw_request, dict):
            return False
        if "contents" in raw_request:
            return False
        if "messages" not in raw_request or not isinstance(
            raw_request["messages"], list
        ):
            return False
        if "model" not in raw_request or not isinstance(raw_request["model"], str):
            return False

        # Specific indicators for Anthropic:
        # 1. Has 'max_tokens'
        # 2. Or has top-level 'system'
        # 3. Or messages contain Anthropic content block formats
        if "max_tokens" in raw_request or "system" in raw_request:
            return True

        for msg in raw_request["messages"]:
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, list):
                    for b in content:
                        if isinstance(b, dict) and b.get("type") in (
                            "tool_use",
                            "tool_result",
                            "image",
                        ):
                            return True
        return False

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert Anthropic Messages API request to NormalizedAIRequest."""
        if not isinstance(raw_request, dict):
            raise NormalizationError(
                "Anthropic request payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        if raw_request.get("stream") is True:
            raise UnsupportedStreamingError(
                "Anthropic streaming (stream=True) is not supported.",
                provider=self.provider_name,
            )

        model = raw_request.get("model")
        if not model or not isinstance(model, str) or not model.strip():
            raise NormalizationError(
                "Anthropic request missing required 'model' string.",
                provider=self.provider_name,
                field="model",
            )

        raw_messages = raw_request.get("messages")
        if not isinstance(raw_messages, list):
            raise NormalizationError(
                "Anthropic request missing required 'messages' list.",
                provider=self.provider_name,
                field="messages",
            )

        req_id = (
            request_id.strip()
            if request_id and request_id.strip()
            else f"req_{uuid.uuid4().hex[:16]}"
        )
        norm_messages: list[NormalizedMessage] = []

        # 1. Normalize top-level Anthropic 'system' instruction if present
        raw_system = raw_request.get("system")
        if raw_system is not None:
            if isinstance(raw_system, str):
                sys_text = raw_system
                sys_meta: dict[str, Any] = {
                    "is_anthropic_system": True,
                    "system_type": "string",
                }
            elif isinstance(raw_system, list):
                # Anthropic supports system as list of text blocks
                parts: list[str] = []
                for b in raw_system:
                    if isinstance(b, dict) and b.get("type") == "text":
                        parts.append(str(b.get("text", "")))
                sys_text = "\n".join(parts)
                sys_meta = {
                    "is_anthropic_system": True,
                    "system_type": "blocks",
                    "blocks": copy.deepcopy(raw_system),
                }
            else:
                raise NormalizationError(
                    f"Unsupported Anthropic 'system' type: {type(raw_system).__name__}",
                    provider=self.provider_name,
                    field="system",
                )

            norm_messages.append(
                NormalizedMessage(
                    role="system",
                    content=sys_text,
                    source=ContentSource.SYSTEM,
                    metadata=sys_meta,
                )
            )

        # 2. Normalize messages
        for idx, raw_msg in enumerate(raw_messages):
            if not isinstance(raw_msg, dict):
                raise NormalizationError(
                    f"Anthropic message at index {idx} must be a dictionary.",
                    provider=self.provider_name,
                    field=f"messages[{idx}]",
                )

            role = raw_msg.get("role")
            if not role or not isinstance(role, str) or not role.strip():
                raise NormalizationError(
                    f"Anthropic message at index {idx} has invalid or missing 'role'.",
                    provider=self.provider_name,
                    field=f"messages[{idx}].role",
                )

            norm_role = role.strip().lower()
            source = (
                ContentSource.USER if norm_role == "user" else ContentSource.ASSISTANT
            )
            content_val = raw_msg.get("content")
            meta: dict[str, Any] = {}

            if isinstance(content_val, str):
                text_content = content_val
            elif isinstance(content_val, list):
                meta["is_multipart"] = True
                meta["blocks"] = copy.deepcopy(content_val)
                text_parts: list[str] = []
                for b in content_val:
                    if isinstance(b, dict):
                        b_type = b.get("type")
                        if b_type == "text":
                            text_parts.append(str(b.get("text", "")))
                        elif b_type == "tool_result" and isinstance(
                            b.get("content"), str
                        ):
                            text_parts.append(str(b.get("content", "")))
                            source = ContentSource.TOOL_OUTPUT
                text_content = "\n".join(text_parts)
            else:
                val_type = type(content_val).__name__
                raise NormalizationError(
                    f"Anthropic message content must be string or list, got {val_type}",
                    provider=self.provider_name,
                    field=f"messages[{idx}].content",
                )

            norm_messages.append(
                NormalizedMessage(
                    role=norm_role,
                    content=text_content,
                    source=source,
                    metadata=meta,
                )
            )

        # Extract safe parameters
        safe_params: dict[str, Any] = {}
        for param_key in ANTHROPIC_SAFE_PARAMETERS:
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
        """Convert NormalizedAIRequest back to Anthropic Messages API JSON."""
        if original_request is not None:
            result = copy.deepcopy(original_request)
            result["model"] = request.model

            # Reconstruct system if present in normalized messages
            sys_msg = next((m for m in request.messages if m.role == "system"), None)
            if sys_msg is not None:
                orig_system = result.get("system")
                if isinstance(orig_system, list) and orig_system:
                    for b in orig_system:
                        if isinstance(b, dict) and b.get("type") == "text":
                            b["text"] = sys_msg.content
                            break
                    result["system"] = orig_system
                else:
                    result["system"] = sys_msg.content

            # Reconstruct conversational messages
            non_sys_messages = [m for m in request.messages if m.role != "system"]
            rebuilt_messages: list[dict[str, Any]] = []

            for idx, norm_msg in enumerate(non_sys_messages):
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

                rebuilt_messages.append(msg_dict)

            result["messages"] = rebuilt_messages
            return result

        # Construct from normalized fields
        sys_msg = next((m for m in request.messages if m.role == "system"), None)
        non_sys = [m for m in request.messages if m.role != "system"]

        messages_list: list[dict[str, Any]] = []
        for m in non_sys:
            item: dict[str, Any] = {"role": m.role}
            if m.metadata.get("is_multipart") and "blocks" in m.metadata:
                blocks = copy.deepcopy(m.metadata["blocks"])
                for b in blocks:
                    if isinstance(b, dict) and b.get("type") == "text":
                        b["text"] = m.content
                        break
                item["content"] = blocks
            else:
                item["content"] = m.content
            messages_list.append(item)

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages_list,
        }
        if sys_msg is not None:
            payload["system"] = sys_msg.content
        payload.update(copy.deepcopy(request.parameters))
        if "max_tokens" not in payload:
            payload["max_tokens"] = 1024  # Anthropic requires max_tokens
        return payload

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert Anthropic response JSON to NormalizedAIResponse."""
        if not isinstance(raw_response, dict):
            raise NormalizationError(
                "Anthropic response payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        content_blocks = raw_response.get("content")
        if not isinstance(content_blocks, list):
            if isinstance(content_blocks, str):
                text_content = content_blocks
            else:
                raise UnsupportedPayloadError(
                    "Anthropic response missing valid 'content' field.",
                    provider=self.provider_name,
                    field="content",
                )
        else:
            text_parts: list[str] = []
            for b in content_blocks:
                if isinstance(b, dict) and b.get("type") == "text":
                    text_parts.append(str(b.get("text", "")))
            text_content = "\n".join(text_parts)

        finish_reason = raw_response.get("stop_reason")
        model = str(raw_response.get("model", ""))
        resp_id = str(raw_response.get("id") or request_id)

        meta: dict[str, Any] = {"provider": self.provider_name}
        if "usage" in raw_response and isinstance(raw_response["usage"], dict):
            meta["usage"] = copy.deepcopy(raw_response["usage"])
        if "type" in raw_response:
            meta["type"] = str(raw_response["type"])

        return NormalizedAIResponse(
            request_id=resp_id,
            model=model,
            content=text_content,
            finish_reason=str(finish_reason) if finish_reason else None,
            metadata=meta,
        )

    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to Anthropic response JSON."""
        if original_response is not None:
            result = copy.deepcopy(original_response)
            if "content" in result and isinstance(result["content"], list):
                updated = False
                for b in result["content"]:
                    if isinstance(b, dict) and b.get("type") == "text":
                        b["text"] = response.content
                        updated = True
                        break
                if not updated:
                    result["content"] = [{"type": "text", "text": response.content}]
            else:
                result["content"] = [{"type": "text", "text": response.content}]
            return result

        return {
            "id": response.request_id,
            "type": "message",
            "role": "assistant",
            "model": response.model,
            "content": [{"type": "text", "text": response.content}],
            "stop_reason": response.finish_reason or "end_turn",
        }
