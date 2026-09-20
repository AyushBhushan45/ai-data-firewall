"""Unit tests for generic payload extraction and reconstruction."""

import json

from aifirewall.core.types import ContentDirection, ContentSource
from aifirewall.proxy.extraction import PayloadExtractor


class TestPayloadExtraction:
    """Test suite for extracting inspectable text from diverse payloads."""

    def test_extract_simple_json(self) -> None:
        """Verify extraction from top-level JSON fields."""
        payload = json.dumps({"prompt": "Hello AI", "max_tokens": 100}).encode("utf-8")
        result = PayloadExtractor.extract(
            payload, "application/json", ContentDirection.REQUEST
        )
        assert result.is_inspectable is True
        assert result.content_type == "application/json"
        assert len(result.items) == 1
        item = result.items[0]
        assert item.path == "prompt"
        assert item.text == "Hello AI"
        assert item.location.source == ContentSource.USER
        assert item.location.field_path == "prompt"

    def test_extract_nested_json(self) -> None:
        """Verify extraction from nested structures and arrays."""
        data = {
            "model": "test-llm",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "sk-secret123"},
            ],
            "stream": False,
            "temperature": 0.7,
            "null_field": None,
        }
        payload = json.dumps(data).encode("utf-8")
        result = PayloadExtractor.extract(
            payload, "application/json; charset=utf-8", ContentDirection.REQUEST
        )
        assert result.is_inspectable is True
        paths = [item.path for item in result.items]
        texts = [item.text for item in result.items]
        assert "model" in paths
        assert "messages[0].role" in paths
        assert "messages[0].content" in paths
        assert "messages[1].role" in paths
        assert "messages[1].content" in paths
        assert "sk-secret123" in texts

    def test_extract_plain_text(self) -> None:
        """Verify extraction from text/plain body."""
        body = b"Generate a summary of the quarterly financials."
        result = PayloadExtractor.extract(
            body, "text/plain", ContentDirection.REQUEST
        )
        assert result.is_inspectable is True
        assert len(result.items) == 1
        item = result.items[0]
        assert item.path == "body"
        assert item.text == "Generate a summary of the quarterly financials."
        assert item.location.char_start == 0
        assert item.location.char_end == len(item.text)

    def test_extract_unsupported_binary(self) -> None:
        """Verify binary types are not parsed and flagged as non-inspectable."""
        binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        result = PayloadExtractor.extract(
            binary_data, "image/png", ContentDirection.REQUEST
        )
        assert result.is_inspectable is False
        assert len(result.items) == 0
        assert result.raw_bytes == binary_data

    def test_extract_malformed_json(self) -> None:
        """Verify malformed JSON does not crash and is handled safely."""
        bad_json = b'{"unclosed": "brace"'
        result = PayloadExtractor.extract(
            bad_json, "application/json", ContentDirection.REQUEST
        )
        assert result.is_inspectable is False
        assert len(result.items) == 0
        assert result.raw_bytes == bad_json

    def test_extract_event_stream_deferred(self) -> None:
        """Verify text/event-stream is treated as non-inspectable in Step 8."""
        sse_data = b"data: {'chunk': 'hello'}\n\n"
        result = PayloadExtractor.extract(
            sse_data, "text/event-stream", ContentDirection.RESPONSE
        )
        assert result.is_inspectable is False
        assert len(result.items) == 0

    def test_extract_empty_payload(self) -> None:
        """Verify empty body produces empty items."""
        result = PayloadExtractor.extract(
            b"", "application/json", ContentDirection.REQUEST
        )
        assert result.is_inspectable is True
        assert len(result.items) == 0


class TestPayloadReconstruction:
    """Test suite for reconstructing payloads after redactions."""

    def test_reconstruct_json_preserves_structure_and_types(self) -> None:
        """Verify only targeted strings change; numbers and nulls stay intact."""
        original = {
            "id": 42,
            "active": True,
            "score": 3.1415,
            "meta": None,
            "messages": [
                {"role": "user", "content": "sk-secret-key-12345"},
                {"role": "assistant", "content": "Sure, I can help."},
            ],
            "tags": ["alpha", "beta"],
        }
        payload = json.dumps(original).encode("utf-8")
        extraction = PayloadExtractor.extract(
            payload, "application/json", ContentDirection.REQUEST
        )

        # Find the item for messages[0].content
        target_item = next(
            item for item in extraction.items if item.path == "messages[0].content"
        )
        replacements = {target_item.item_id: "[REDACTED_SECRET]"}

        reconstructed_bytes = PayloadExtractor.reconstruct(
            extraction, replacements
        )
        reconstructed = json.loads(reconstructed_bytes.decode("utf-8"))

        # Invariants
        assert reconstructed["id"] == 42
        assert isinstance(reconstructed["id"], int)
        assert reconstructed["active"] is True
        assert isinstance(reconstructed["active"], bool)
        assert reconstructed["score"] == 3.1415
        assert reconstructed["meta"] is None
        assert reconstructed["tags"] == ["alpha", "beta"]

        # Transformed field
        assert (
            reconstructed["messages"][0]["content"] == "[REDACTED_SECRET]"
        )
        assert (
            reconstructed["messages"][1]["content"] == "Sure, I can help."
        )

    def test_reconstruct_plain_text(self) -> None:
        """Verify plain text replacement."""
        body = b"Please contact sk-12345 for access."
        extraction = PayloadExtractor.extract(
            body, "text/plain", ContentDirection.REQUEST
        )
        item = extraction.items[0]
        replacements = {item.item_id: "Please contact [REDACTED_SECRET] for access."}
        reconstructed = PayloadExtractor.reconstruct(extraction, replacements)
        assert reconstructed == b"Please contact [REDACTED_SECRET] for access."

    def test_reconstruct_no_changes_returns_original_bytes(self) -> None:
        """If replacements match original or are empty, return unmodified bytes."""
        body = b'{"msg": "unchanged"}'
        extraction = PayloadExtractor.extract(
            body, "application/json", ContentDirection.REQUEST
        )
        reconstructed = PayloadExtractor.reconstruct(extraction, {})
        assert reconstructed is body
