"""Security finding models produced by inspection detectors."""

from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import DetectionCategory, Severity
from aifirewall.models.content import ContentLocation


@dataclass(frozen=True)
class DetectionResult:
    """Represents a single security or privacy finding produced by a detector.

    Security Rule: This model must NEVER store raw sensitive values (e.g.
    actual API keys, passwords, or PII). It captures only classification,
    severity, confidence, coordinates, and a safe diagnostic description.

    Design Philosophy: DETECTION ≠ POLICY.
    This model answers "What did I find?", never "What action should be taken?".
    """

    detection_id: str
    detector_name: str
    category: DetectionCategory | str
    severity: Severity
    confidence: float
    location: ContentLocation
    description: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate finding parameters for sanity and privacy boundaries."""
        if not self.detection_id or not self.detection_id.strip():
            raise ValidationError("detection_id must be a non-empty string")

        if not self.detector_name or not self.detector_name.strip():
            raise ValidationError("detector_name must be a non-empty string")

        if not (0.0 <= self.confidence <= 1.0):
            raise ValidationError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

        if not self.description or not self.description.strip():
            raise ValidationError("description must be a non-empty safe string")

    def __repr__(self) -> str:
        """Return a clean, privacy-safe developer representation."""
        return (
            f"DetectionResult(id={self.detection_id!r}, "
            f"detector={self.detector_name!r}, "
            f"category={str(self.category)!r}, "
            f"severity={str(self.severity)!r}, "
            f"confidence={self.confidence:.2f}, "
            f"location={self.location!r}, "
            f"description={self.description!r})"
        )

    def __str__(self) -> str:
        """Return a human-readable safe summary."""
        prefix = (
            f"[{self.severity.upper()}] {self.category} "
            f"detected by {self.detector_name}"
        )
        return f"{prefix} (confidence: {self.confidence:.2f}): {self.description}"
