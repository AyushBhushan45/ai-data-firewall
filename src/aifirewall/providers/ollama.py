"""Ollama-compatible request and response adapter for AI Data Firewall.

Converts between Ollama API payloads (/api/chat and /api/generate)
and normalized domain models (NormalizedAIRequest, NormalizedAIResponse).

Architectural Rule:
- Translator only: no detection, no policy, no redaction.
- Supports both chat and raw completion endpoint families.
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

OLLAMA_SAFE_PARAMETERS: frozenset[str] = frozenset(
    {
        "options",
        "format",
        "keep_alive",
        "template",
    }
)


class OllamaAdapter(BaseProviderAdapter):
    """Adapter translating between Ollama JSON payloads and normalized models."""

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return "ollama"

    @property
    def adapter_version(self) -> str:
        """Adapter implementation version."""
        return "1.0.0"

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine if raw payload matches Ollama /api/chat or /api/generate."""
        if not isinstance(raw_request, dict):
            return False
        if "contents" in raw_request:
            return False
        model = raw_request.get("model")
        if not model or not isinstance(model, str):
            return False

        # /api/generate format has 'prompt'
        if "prompt" in raw_request and isinstance(raw_request["prompt"], str):
            return True

        # /api/chat format has 'messages'
        if "messages" in raw_request and isinstance(raw_request["messages"], list):
            # Ollama messages don't have 'function' or 'tool_calls' by default
            return True

        return False

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert Ollama chat or generate request to NormalizedAIRequest."""
        if not isinstance(raw_request, dict):
            raise NormalizationError(
                "Ollama request payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        if raw_request.get("stream") is True:
            raise UnsupportedStreamingError(
                "Ollama streaming (stream=True) is not supported.",
                provider=self.provider_name,
            )

        model = raw_request.get("model")
        if not model or not isinstance(model, str) or not model.strip():
            raise NormalizationError(
                "Ollama request missing required 'model' string.",
                provider=self.provider_name,
                field="model",
            )

        req_id = (
            request_id.strip()
            if request_id and request_id.strip()
            else f"req_{uuid.uuid4().hex[:16]}"
        )
        norm_messages: list[NormalizedMessage] = []
        endpoint_type = "chat"

        # 1. Format: /api/generate (prompt + optional system)
        if "prompt" in raw_request and isinstance(raw_request["prompt"], str):
            endpoint_type = "generate"
            raw_system = raw_request.get("system")
            if raw_system and isinstance(raw_system, str):
                norm_messages.append(
                    NormalizedMessage(
                        role="system",
                        content=raw_system,
                        source=ContentSource.SYSTEM,
                        metadata={"endpoint": "generate"},
                    )
                )

            norm_messages.append(
                NormalizedMessage(
                    role="user",
                    content=raw_request["prompt"],
                    source=ContentSource.USER,
                    metadata={"endpoint": "generate"},
                )
            )

        # 2. Format: /api/chat (messages list)
        elif "messages" in raw_request and isinstance(raw_request["messages"], list):
            for idx, raw_msg in enumerate(raw_request["messages"]):
                if not isinstance(raw_msg, dict):
                    raise NormalizationError(
                        f"Ollama message at index {idx} must be a dictionary.",
                        provider=self.provider_name,
                        field=f"messages[{idx}]",
                    )

                role = raw_msg.get("role", "user")
                if not isinstance(role, str) or not role.strip():
                    role = "user"

                content = str(raw_msg.get("content", ""))
                norm_role = role.strip().lower()
                source = self._map_role_to_source(norm_role)

                norm_messages.append(
                    NormalizedMessage(
                        role=norm_role,
                        content=content,
                        source=source,
                        metadata={"endpoint": "chat"},
                    )
                )

        else:
            raise NormalizationError(
                "Ollama request must specify either 'messages' or 'prompt'.",
                provider=self.provider_name,
            )

        safe_params: dict[str, Any] = {}
        for param_key in OLLAMA_SAFE_PARAMETERS:
            if param_key in raw_request:
                safe_params[param_key] = copy.deepcopy(raw_request[param_key])

        return NormalizedAIRequest(
            request_id=req_id,
            model=model.strip(),
            messages=norm_messages,
            parameters=safe_params,
            metadata={"provider": self.provider_name, "endpoint": endpoint_type},
        )

    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to Ollama API JSON."""
        if original_request is not None:
            result = copy.deepcopy(original_request)
            result["model"] = request.model

            if "prompt" in result:
                # /api/generate
                sys_msg = next(
                    (m for m in request.messages if m.role == "system"), None
                )
                user_msg = next((m for m in request.messages if m.role == "user"), None)
                if sys_msg is not None:
                    result["system"] = sys_msg.content
                if user_msg is not None:
                    result["prompt"] = user_msg.content
            else:
                # /api/chat
                result["messages"] = [
                    {"role": m.role, "content": m.content} for m in request.messages
                ]

            result["stream"] = False
            return result

        # Reconstruct without original
        endpoint = request.metadata.get("endpoint", "chat")
        if endpoint == "generate":
            sys_msg = next((m for m in request.messages if m.role == "system"), None)
            user_msg = next((m for m in request.messages if m.role == "user"), None)
            payload = {
                "model": request.model,
                "prompt": user_msg.content if user_msg else "",
                "stream": False,
            }
            if sys_msg:
                payload["system"] = sys_msg.content
            payload.update(copy.deepcopy(request.parameters))
            return payload

        # /api/chat
        payload = {
            "model": request.model,
            "messages": [
                {"role": m.role, "content": m.content} for m in request.messages
            ],
            "stream": False,
        }
        payload.update(copy.deepcopy(request.parameters))
        return payload

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert Ollama response JSON to NormalizedAIResponse."""
        if not isinstance(raw_response, dict):
            raise NormalizationError(
                "Ollama response payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        model = str(raw_response.get("model", ""))
        done = raw_response.get("done", True)
        done_reason = raw_response.get("done_reason") or ("stop" if done else None)

        if "message" in raw_response and isinstance(raw_response["message"], dict):
            # /api/chat response
            content = str(raw_response["message"].get("content", ""))
        elif "response" in raw_response:
            # /api/generate response
            content = str(raw_response.get("response", ""))
        else:
            raise UnsupportedPayloadError(
                "Ollama response missing both 'message' and 'response' fields.",
                provider=self.provider_name,
            )

        meta: dict[str, Any] = {"provider": self.provider_name}
        for k in (
            "total_duration",
            "load_duration",
            "prompt_eval_count",
            "eval_count",
            "created_at",
        ):
            if k in raw_response:
                meta[k] = raw_response[k]

        return NormalizedAIResponse(
            request_id=request_id,
            model=model,
            content=content,
            finish_reason=str(done_reason) if done_reason else None,
            metadata=meta,
        )

    def denormalize_response(
        self,
        response: NormalizedAIResponse,
        original_response: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIResponse back to Ollama response JSON."""
        if original_response is not None:
            result = copy.deepcopy(original_response)
            if "message" in result and isinstance(result["message"], dict):
                result["message"]["content"] = response.content
            elif "response" in result:
                result["response"] = response.content
            return result

        return {
            "model": response.model,
            "message": {
                "role": "assistant",
                "content": response.content,
            },
            "done": True,
            "done_reason": response.finish_reason or "stop",
        }

    @staticmethod
    def _map_role_to_source(role: str) -> ContentSource:
        """Map Ollama message role to ContentSource."""
        if role == "system":
            return ContentSource.SYSTEM
        if role == "user":
            return ContentSource.USER
        if role == "assistant":
            return ContentSource.ASSISTANT
        if role in ("tool", "function"):
            return ContentSource.TOOL_OUTPUT
        return ContentSource.UNKNOWN
