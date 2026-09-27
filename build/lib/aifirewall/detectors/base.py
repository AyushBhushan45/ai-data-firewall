"""Core detector interface protocol and inspection context.

Detectors are observational scanning units. They operate according to the rule:
DETECTION ≠ POLICY ≠ TRANSFORMATION.

A detector inspects content and returns what it found (`list[DetectionResult]`).
It never decides whether to block, warn, or redact traffic.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import ContentDirection, ContentSource, DetectionCategory
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult


@dataclass(frozen=True)
class DetectorContext:
    """Minimal contextual metadata provided to a detector during inspection.

    Security Rule: This context must NEVER contain sensitive API credentials,
    upstream provider keys, or user authorization tokens.
    """

    request_id: str
    direction: ContentDirection
    source: ContentSource = ContentSource.UNKNOWN
    model: str | None = None
    provider: str | None = None
    location: ContentLocation | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate context parameters."""
        if not self.request_id or not self.request_id.strip():
            raise ValidationError("request_id must be a non-empty string")


@runtime_checkable
class Detector(Protocol):
    """Structural protocol for security, privacy, and safety inspection modules.

    Detectors are pure observational components:
    - They inspect normalized content strings.
    - They produce zero or more `DetectionResult` objects.
    - They do NOT decide enforcement actions (ALLOW, WARN, REDACT, BLOCK).
    - They do NOT write directly to audit sinks.
    - They do NOT mutate application state or network buffers.
    """

    @property
    def name(self) -> str:
        """Unique identifier of the detector (e.g. 'secret_pattern_detector')."""
        ...

    @property
    def version(self) -> str:
        """Semantic version of the detector module."""
        ...

    @property
    def description(self) -> str:
        """Safe human-readable description of what this detector identifies."""
        ...

    @property
    def supported_categories(self) -> tuple[DetectionCategory | str, ...]:
        """Categories of findings this detector is capable of producing."""
        ...

    def detect(
        self,
        content: str,
        context: DetectorContext,
    ) -> list[DetectionResult]:
        """Inspect the given content string and return findings.

        Args:
            content: The text content segment to inspect.
            context: Safe execution context (request ID, direction, source).

        Returns:
            A list of zero or more `DetectionResult` findings.

        Raises:
            DetectorError: If the detector encounters an unrecoverable failure.
        """
        ...
