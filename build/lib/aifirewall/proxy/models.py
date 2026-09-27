"""Domain models for payload extraction and pipeline execution in the reverse proxy."""

from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import ContentDirection, PolicyAction
from aifirewall.models.content import ContentLocation
from aifirewall.models.event import PolicyDecision


@dataclass(frozen=True)
class ExtractedItem:
    """An individual inspectable text item extracted from a payload.

    Attributes:
        item_id: Unique string identifying this item within the payload.
        path: Structural path (e.g. 'messages.0.content' for JSON, 'body' for text).
        text: The text string to run detectors against.
        location: ContentLocation with coordinates and field_path.
    """

    item_id: str
    path: str
    text: str
    location: ContentLocation

    def __post_init__(self) -> None:
        """Validate item integrity."""
        if not self.item_id or not self.item_id.strip():
            raise ValidationError("item_id must be a non-empty string")
        if not isinstance(self.text, str):
            raise ValidationError("text must be a string")


@dataclass(frozen=True)
class ExtractionResult:
    """Result of extracting inspectable content from an HTTP body.

    Attributes:
        content_type: The normalized MIME type (e.g. 'application/json').
        is_inspectable: Whether this payload is supported for semantic inspection.
        items: Tuple of ExtractedItem objects found in the payload.
        raw_bytes: The original untouched raw body bytes.
    """

    content_type: str
    is_inspectable: bool
    items: tuple[ExtractedItem, ...]
    raw_bytes: bytes


@dataclass(frozen=True)
class PipelineResult:
    """Execution summary of the security pipeline for an HTTP request or response.

    Security Rule: PipelineResult records only operational metadata and decisions.
    It NEVER stores raw request/response bodies, credentials, or secrets.

    Attributes:
        request_id: Correlation identifier for this transaction.
        direction: ContentDirection (REQUEST or RESPONSE).
        action: Final PolicyAction evaluated (ALLOW, WARN, REDACT, BLOCK).
        decision: The underlying PolicyDecision.
        detection_count: Total findings detected.
        transformed: Whether content redaction was executed.
        metadata: Additional non-sensitive operational properties.
    """

    request_id: str
    direction: ContentDirection
    action: PolicyAction
    decision: PolicyDecision
    detection_count: int
    transformed: bool
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Safe representation without secret disclosure."""
        return (
            f"PipelineResult(request_id={self.request_id!r}, "
            f"direction={str(self.direction)!r}, "
            f"action={str(self.action)!r}, "
            f"detections={self.detection_count}, "
            f"transformed={self.transformed})"
        )
