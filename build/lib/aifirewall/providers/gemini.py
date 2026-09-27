"""Google Gemini-compatible request and response adapter for AI Data Firewall.

Converts between Gemini REST API payloads (models/{model}:generateContent)
and normalized domain models (NormalizedAIRequest, NormalizedAIResponse).

Architectural Rule:
- Translator only: no detection, no policy, no redaction.
- Preserves parts structures, role mapping ('model' <-> 'assistant'),
  and safety settings.
- Safely rejects streaming requests.
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

GEMINI_SAFE_PARAMETERS: frozenset[str] = frozenset(
    {
        "generationConfig",
        "safetySettings",
        "tools",
        "toolConfig",
    }
)


class GeminiAdapter(BaseProviderAdapter):
    """Adapter translating between Gemini REST API JSON and normalized models."""

    @property
    def provider_name(self) -> str:
        """Provider identifier."""
        return "gemini"

    @property
    def adapter_version(self) -> str:
        """Adapter implementation version."""
        return "1.0.0"

    def can_handle_request(self, raw_request: dict[str, Any]) -> bool:
        """Determine if raw payload matches Gemini generateContent structure."""
        if not isinstance(raw_request, dict):
            return False
        # Gemini signature is top-level 'contents' list
        if "contents" in raw_request and isinstance(raw_request["contents"], list):
            return True
        return False

    def normalize_request(
        self, raw_request: dict[str, Any], request_id: str | None = None
    ) -> NormalizedAIRequest:
        """Convert Gemini generateContent request to NormalizedAIRequest."""
        if not isinstance(raw_request, dict):
            raise NormalizationError(
                "Gemini request payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        if raw_request.get("stream") is True:
            raise UnsupportedStreamingError(
                "Gemini streaming is not supported.",
                provider=self.provider_name,
            )

        raw_contents = raw_request.get("contents")
        if not isinstance(raw_contents, list):
            raise NormalizationError(
                "Gemini request missing required 'contents' list.",
                provider=self.provider_name,
                field="contents",
            )

        model = str(raw_request.get("model") or "gemini")
        req_id = (
            request_id.strip()
            if request_id and request_id.strip()
            else f"req_{uuid.uuid4().hex[:16]}"
        )
        norm_messages: list[NormalizedMessage] = []

        # 1. Normalize systemInstruction if present
        raw_system = raw_request.get("systemInstruction")
        if raw_system is not None:
            if isinstance(raw_system, dict):
                parts = raw_system.get("parts", [])
                text_parts = [
                    str(p.get("text", ""))
                    for p in parts
                    if isinstance(p, dict) and "text" in p
                ]
                sys_text = "\n".join(text_parts)
                sys_meta = {"is_gemini_system": True, "parts": copy.deepcopy(parts)}
            elif isinstance(raw_system, str):
                sys_text = raw_system
                sys_meta = {"is_gemini_system": True}
            else:
                raise NormalizationError(
                    f"Invalid systemInstruction type: {type(raw_system).__name__}",
                    provider=self.provider_name,
                    field="systemInstruction",
                )

            norm_messages.append(
                NormalizedMessage(
                    role="system",
                    content=sys_text,
                    source=ContentSource.SYSTEM,
                    metadata=sys_meta,
                )
            )

        # 2. Normalize contents turns
        for idx, turn in enumerate(raw_contents):
            if not isinstance(turn, dict):
                raise NormalizationError(
                    f"Gemini turn at index {idx} must be a dictionary.",
                    provider=self.provider_name,
                    field=f"contents[{idx}]",
                )

            raw_role = turn.get("role", "user")
            if not isinstance(raw_role, str):
                raw_role = "user"

            # Gemini uses 'model' for assistant turns
            norm_role = "assistant" if raw_role.strip().lower() == "model" else "user"
            source = (
                ContentSource.ASSISTANT
                if norm_role == "assistant"
                else ContentSource.USER
            )

            parts = turn.get("parts")
            if not isinstance(parts, list):
                raise NormalizationError(
                    f"Gemini turn at index {idx} missing 'parts' list.",
                    provider=self.provider_name,
                    field=f"contents[{idx}].parts",
                )

            text_parts = []
            has_non_text = False
            for part in parts:
                if isinstance(part, dict) and "text" in part:
                    text_parts.append(str(part["text"]))
                else:
                    has_non_text = True

            meta: dict[str, Any] = {"raw_role": raw_role}
            if has_non_text or len(parts) > 1:
                meta["has_parts"] = True
                meta["parts"] = copy.deepcopy(parts)

            norm_messages.append(
                NormalizedMessage(
                    role=norm_role,
                    content="\n".join(text_parts),
                    source=source,
                    metadata=meta,
                )
            )

        # Extract safe parameters
        safe_params: dict[str, Any] = {}
        for param_key in GEMINI_SAFE_PARAMETERS:
            if param_key in raw_request:
                safe_params[param_key] = copy.deepcopy(raw_request[param_key])

        return NormalizedAIRequest(
            request_id=req_id,
            model=model,
            messages=norm_messages,
            parameters=safe_params,
            metadata={"provider": self.provider_name},
        )

    def denormalize_request(
        self,
        request: NormalizedAIRequest,
        original_request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert NormalizedAIRequest back to Gemini REST API JSON."""
        if original_request is not None:
            result = copy.deepcopy(original_request)
            if request.model and request.model != "gemini":
                result["model"] = request.model

            # Reconstruct systemInstruction if present
            sys_msg = next((m for m in request.messages if m.role == "system"), None)
            if sys_msg is not None:
                orig_sys = result.setdefault(
                    "systemInstruction", {"role": "system", "parts": []}
                )
                if isinstance(orig_sys, dict):
                    orig_parts = orig_sys.get("parts", [])
                    if (
                        orig_parts
                        and isinstance(orig_parts[0], dict)
                        and "text" in orig_parts[0]
                    ):
                        orig_parts[0]["text"] = sys_msg.content
                    else:
                        orig_sys["parts"] = [{"text": sys_msg.content}]

            # Reconstruct non-system contents
            non_sys_messages = [m for m in request.messages if m.role != "system"]
            new_contents: list[dict[str, Any]] = []

            for idx, norm_msg in enumerate(non_sys_messages):
                orig_turn = (
                    result.get("contents", [])[idx]
                    if idx < len(result.get("contents", []))
                    else {}
                )
                turn_dict = (
                    copy.deepcopy(orig_turn) if isinstance(orig_turn, dict) else {}
                )
                gemini_role = "model" if norm_msg.role == "assistant" else "user"
                turn_dict["role"] = gemini_role

                if norm_msg.metadata.get("has_parts") and "parts" in norm_msg.metadata:
                    parts = copy.deepcopy(norm_msg.metadata["parts"])
                    updated = False
                    for part in parts:
                        if isinstance(part, dict) and "text" in part:
                            part["text"] = norm_msg.content
                            updated = True
                            break
                    if not updated:
                        parts.insert(0, {"text": norm_msg.content})
                    turn_dict["parts"] = parts
                else:
                    turn_dict["parts"] = [{"text": norm_msg.content}]

                new_contents.append(turn_dict)

            result["contents"] = new_contents
            return result

        # Reconstruct without original
        sys_msg = next((m for m in request.messages if m.role == "system"), None)
        non_sys = [m for m in request.messages if m.role != "system"]

        contents_list: list[dict[str, Any]] = []
        for m in non_sys:
            gemini_role = "model" if m.role == "assistant" else "user"
            turn: dict[str, Any] = {"role": gemini_role}
            if m.metadata.get("has_parts") and "parts" in m.metadata:
                parts = copy.deepcopy(m.metadata["parts"])
                for p in parts:
                    if isinstance(p, dict) and "text" in p:
                        p["text"] = m.content
                        break
                turn["parts"] = parts
            else:
                turn["parts"] = [{"text": m.content}]
            contents_list.append(turn)

        payload: dict[str, Any] = {"contents": contents_list}
        if sys_msg is not None:
            payload["systemInstruction"] = {
                "role": "system",
                "parts": [{"text": sys_msg.content}],
            }
        payload.update(copy.deepcopy(request.parameters))
        return payload

    def normalize_response(
        self, raw_response: dict[str, Any], request_id: str
    ) -> NormalizedAIResponse:
        """Convert Gemini response JSON to NormalizedAIResponse."""
        if not isinstance(raw_response, dict):
            raise NormalizationError(
                "Gemini response payload must be a JSON dictionary.",
                provider=self.provider_name,
            )

        candidates = raw_response.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise UnsupportedPayloadError(
                "Gemini response missing valid 'candidates' list.",
                provider=self.provider_name,
                field="candidates",
            )

        first_cand = candidates[0]
        if not isinstance(first_cand, dict):
            raise NormalizationError(
                "Gemini candidate must be a dictionary.",
                provider=self.provider_name,
                field="candidates[0]",
            )

        content_obj = first_cand.get("content", {})
        parts = content_obj.get("parts", []) if isinstance(content_obj, dict) else []
        text_parts = [
            str(p.get("text", "")) for p in parts if isinstance(p, dict) and "text" in p
        ]
        text_content = "\n".join(text_parts)

        finish_reason = first_cand.get("finishReason")
        model = str(raw_response.get("modelVersion", ""))

        meta: dict[str, Any] = {"provider": self.provider_name}
        if "usageMetadata" in raw_response:
            meta["usageMetadata"] = copy.deepcopy(raw_response["usageMetadata"])
        if "safetyRatings" in first_cand:
            meta["safetyRatings"] = copy.deepcopy(first_cand["safetyRatings"])

        return NormalizedAIResponse(
            request_id=request_id,
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
        """Convert NormalizedAIResponse back to Gemini response JSON."""
        if original_response is not None:
            result = copy.deepcopy(original_response)
            candidates = result.get("candidates")
            if isinstance(candidates, list) and candidates:
                cand = candidates[0]
                if isinstance(cand, dict):
                    content = cand.setdefault("content", {"role": "model", "parts": []})
                    if isinstance(content, dict):
                        parts = content.setdefault("parts", [])
                        updated = False
                        for p in parts:
                            if isinstance(p, dict) and "text" in p:
                                p["text"] = response.content
                                updated = True
                                break
                        if not updated:
                            parts.append({"text": response.content})
            return result

        return {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": response.content}],
                        "role": "model",
                    },
                    "finishReason": response.finish_reason or "STOP",
                    "index": 0,
                }
            ],
            "modelVersion": response.model,
        }
