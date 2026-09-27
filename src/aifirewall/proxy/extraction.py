"""Generic payload extraction and reconstruction for HTTP requests and responses.

Provides provider-agnostic semantic traversal for JSON and plain-text payloads,
extracting textual values for inspection while ensuring safe reconstruction without
corrupting non-string types, structural keys, or binary payloads.
"""

import json
from collections.abc import Mapping, Sequence
from typing import Any

from aifirewall.core.types import ContentDirection, ContentSource
from aifirewall.models.content import ContentLocation
from aifirewall.proxy.models import ExtractedItem, ExtractionResult


class PayloadExtractor:
    """Extracts inspectable text from HTTP bodies and reconstructs transformed payloads.

    Supported content types:
    - application/json (and *+json): Recursive traversal of dicts and lists.
    - text/plain (and text/*): Direct textual inspection.
    - Binary / unsupported: Preserves raw bytes without semantic modification.
    """

    @classmethod
    def extract(
        cls,
        raw_body: bytes,
        content_type_header: str | None,
        direction: ContentDirection,
    ) -> ExtractionResult:
        """Extract inspectable text items from an HTTP payload.

        Args:
            raw_body: Raw byte content of the request or response.
            content_type_header: Incoming Content-Type header string.
            direction: Traffic direction (REQUEST or RESPONSE).

        Returns:
            An ExtractionResult containing extracted items and metadata.
        """
        content_type = cls._normalize_content_type(content_type_header)
        default_source = (
            ContentSource.USER
            if direction == ContentDirection.REQUEST
            else ContentSource.ASSISTANT
        )

        if not raw_body:
            return ExtractionResult(
                content_type=content_type,
                is_inspectable=True,
                items=(),
                raw_bytes=raw_body,
            )

        # 1. JSON Payload
        if cls._is_json_content_type(content_type):
            try:
                text_content = raw_body.decode("utf-8")
                parsed_json = json.loads(text_content)
            except (UnicodeDecodeError, json.JSONDecodeError):
                # Malformed or non-UTF8 JSON; do not corrupt, treat as non-inspectable
                return ExtractionResult(
                    content_type=content_type,
                    is_inspectable=False,
                    items=(),
                    raw_bytes=raw_body,
                )

            items: list[ExtractedItem] = []
            cls._extract_json_strings(parsed_json, "", items, default_source)
            return ExtractionResult(
                content_type=content_type,
                is_inspectable=True,
                items=tuple(items),
                raw_bytes=raw_body,
            )

        # 2. Plain Text Payload
        if cls._is_text_content_type(content_type):
            try:
                text_content = raw_body.decode("utf-8")
            except UnicodeDecodeError:
                return ExtractionResult(
                    content_type=content_type,
                    is_inspectable=False,
                    items=(),
                    raw_bytes=raw_body,
                )

            location = ContentLocation(
                source=default_source,
                char_start=0,
                char_end=len(text_content),
                field_path="body",
            )
            item = ExtractedItem(
                item_id="item_0",
                path="body",
                text=text_content,
                location=location,
            )
            return ExtractionResult(
                content_type=content_type,
                is_inspectable=True,
                items=(item,),
                raw_bytes=raw_body,
            )

        # 3. Binary or unsupported payload
        return ExtractionResult(
            content_type=content_type,
            is_inspectable=False,
            items=(),
            raw_bytes=raw_body,
        )

    @classmethod
    def reconstruct(
        cls,
        extraction: ExtractionResult,
        replacements: Mapping[str, str],
    ) -> bytes:
        """Reconstruct transformed payload bytes using replacement strings.

        Args:
            extraction: The original ExtractionResult from `extract()`.
            replacements: Mapping from ExtractedItem.item_id to replaced string value.

        Returns:
            Reconstructed payload as UTF-8 bytes (or original bytes if untouched).
        """
        if not extraction.is_inspectable or not extraction.items or not replacements:
            return extraction.raw_bytes

        # Check if any replacement actually changed
        has_changes = any(
            item.item_id in replacements and replacements[item.item_id] != item.text
            for item in extraction.items
        )
        if not has_changes:
            return extraction.raw_bytes

        # 1. Reconstruct JSON
        if cls._is_json_content_type(extraction.content_type):
            try:
                parsed_json = json.loads(extraction.raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return extraction.raw_bytes

            item_map = {item.item_id: item for item in extraction.items}
            for item_id, new_text in replacements.items():
                if item_id in item_map:
                    target_item = item_map[item_id]
                    cls._set_json_value_at_path(parsed_json, target_item.path, new_text)

            return json.dumps(parsed_json, ensure_ascii=False).encode("utf-8")

        # 2. Reconstruct Plain Text
        if cls._is_text_content_type(extraction.content_type):
            for item in extraction.items:
                if item.item_id in replacements:
                    return replacements[item.item_id].encode("utf-8")

        return extraction.raw_bytes

    @classmethod
    def _extract_json_strings(
        cls,
        data: Any,
        current_path: str,
        results: list[ExtractedItem],
        source: ContentSource,
    ) -> None:
        """Recursively collect string values and paths from parsed JSON data."""
        if isinstance(data, str):
            item_id = f"item_{len(results)}"
            loc = ContentLocation(
                source=source,
                char_start=0,
                char_end=len(data),
                field_path=current_path,
            )
            results.append(
                ExtractedItem(
                    item_id=item_id,
                    path=current_path,
                    text=data,
                    location=loc,
                )
            )
        elif isinstance(data, dict):
            for key, val in data.items():
                path = f"{current_path}.{key}" if current_path else key
                cls._extract_json_strings(val, path, results, source)
        elif isinstance(data, list):
            for idx, val in enumerate(data):
                path = f"{current_path}[{idx}]" if current_path else f"[{idx}]"
                cls._extract_json_strings(val, path, results, source)

    @classmethod
    def _set_json_value_at_path(
        cls,
        root: Any,
        path: str,
        new_val: str,
    ) -> None:
        """Set a transformed string value in a nested JSON structure via path."""
        tokens = cls._tokenize_path(path)
        if not tokens:
            return

        current = root
        for token in tokens[:-1]:
            if isinstance(token, int) and isinstance(current, Sequence):
                current = current[token]
            elif isinstance(token, str) and isinstance(current, Mapping):
                current = current[token]
            else:
                return

        last_token = tokens[-1]
        if isinstance(last_token, int) and isinstance(current, list):
            current[last_token] = new_val
        elif isinstance(last_token, str) and isinstance(current, dict):
            current[last_token] = new_val

    @staticmethod
    def _tokenize_path(path: str) -> list[str | int]:
        """Convert a path like 'messages[0].content' or 'a.b[2]' into tokens."""
        tokens: list[str | int] = []
        part = ""
        i = 0
        while i < len(path):
            ch = path[i]
            if ch == ".":
                if part:
                    tokens.append(part)
                    part = ""
                i += 1
            elif ch == "[":
                if part:
                    tokens.append(part)
                    part = ""
                end_idx = path.find("]", i)
                if end_idx != -1:
                    index_str = path[i + 1 : end_idx]
                    try:
                        tokens.append(int(index_str))
                    except ValueError:
                        tokens.append(index_str)
                    i = end_idx + 1
                else:
                    i += 1
            else:
                part += ch
                i += 1

        if part:
            tokens.append(part)
        return tokens

    @staticmethod
    def _normalize_content_type(header: str | None) -> str:
        """Extract and normalize lowercase MIME type without charset or parameters."""
        if not header:
            return "application/octet-stream"
        raw_mime = header.split(";")[0].strip().lower()
        return raw_mime if raw_mime else "application/octet-stream"

    @classmethod
    def _is_json_content_type(cls, content_type: str) -> bool:
        """Determine if a MIME type represents a JSON payload."""
        return content_type == "application/json" or content_type.endswith("+json")

    @classmethod
    def _is_text_content_type(cls, content_type: str) -> bool:
        """Determine if a MIME type represents a plain-text payload."""
        return content_type.startswith("text/") and content_type != "text/event-stream"
