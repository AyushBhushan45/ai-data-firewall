"""Data models for content transformation and redaction results.

All models are privacy-preserving and audit-safe: they capture transformation
outcomes, counts, affected detection identifiers, and categories without
leaking sensitive values in string representations or diagnostic dumps.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import DetectionCategory


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of a content redaction transformation pass.

    Security & Privacy Rule:
    This model must NEVER expose raw secrets, sensitive substrings, or
    untransformed content in its __repr__ or __str__ representations.
    The `content` attribute holds the final text (transformed or original)
    and should only be accessed directly by the caller when handing off
    to downstream pipeline stages.

    Attributes:
        content: The resulting text content (transformed or original).
        changed: True if one or more sensitive spans were replaced.
        redaction_count: Number of unique replacement operations applied.
        redacted_detection_ids: Sorted tuple of detection IDs that contributed
            to applied redactions.
        categories: Sorted tuple of distinct finding categories that were redacted.
    """

    content: str
    changed: bool
    redaction_count: int
    redacted_detection_ids: tuple[str, ...] = field(default_factory=tuple)
    categories: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validate result invariants and normalize collection fields."""
        if not isinstance(self.content, str):
            raise ValidationError(
                f"content must be a string, got {type(self.content).__name__}"
            )

        if not isinstance(self.changed, bool):
            raise ValidationError(
                f"changed must be a bool, got {type(self.changed).__name__}"
            )

        if (
            not isinstance(self.redaction_count, int)
            or isinstance(self.redaction_count, bool)
            or self.redaction_count < 0
        ):
            msg = (
                f"redaction_count must be a non-negative integer, "
                f"got {self.redaction_count}"
            )
            raise ValidationError(msg)

        # Normalize redacted_detection_ids to an immutable tuple of strings
        raw_ids: Any = self.redacted_detection_ids
        if not isinstance(raw_ids, tuple):
            if isinstance(raw_ids, Sequence):
                object.__setattr__(
                    self,
                    "redacted_detection_ids",
                    tuple(str(d) for d in raw_ids),
                )
            else:
                raise ValidationError("redacted_detection_ids must be a sequence")

        # Normalize categories to an immutable tuple of strings
        raw_cats: Any = self.categories
        if not isinstance(raw_cats, tuple):
            if isinstance(raw_cats, Sequence):
                norm_cats: list[str] = []
                for c in raw_cats:
                    if isinstance(c, DetectionCategory):
                        norm_cats.append(c.value)
                    else:
                        norm_cats.append(str(c))
                object.__setattr__(self, "categories", tuple(norm_cats))
            else:
                raise ValidationError("categories must be a sequence")

    def __repr__(self) -> str:
        """Return a privacy-safe developer representation without raw content."""
        return (
            f"RedactionResult(changed={self.changed!r}, "
            f"redaction_count={self.redaction_count!r}, "
            f"redacted_detection_ids={self.redacted_detection_ids!r}, "
            f"categories={self.categories!r})"
        )

    def __str__(self) -> str:
        """Return a human-readable, safe audit summary."""
        return (
            f"RedactionResult(changed={self.changed}, "
            f"count={self.redaction_count}, "
            f"categories={list(self.categories)})"
        )
