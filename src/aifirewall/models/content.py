"""Content location and coordinate models for inspected text segments."""

from dataclasses import dataclass

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import ContentSource


@dataclass(frozen=True)
class ContentLocation:
    """Specifies the location coordinates of an inspected content span.

    Supports simple text offset tracking as well as structured/multimodal
    location pointers (message indices, block indices, and field paths).
    """

    source: ContentSource
    message_index: int | None = None
    block_index: int | None = None
    char_start: int | None = None
    char_end: int | None = None
    field_path: str | None = None

    def __post_init__(self) -> None:
        """Validate offset boundaries and indices."""
        if self.message_index is not None and self.message_index < 0:
            raise ValidationError(
                f"message_index cannot be negative: {self.message_index}"
            )
        if self.block_index is not None and self.block_index < 0:
            raise ValidationError(f"block_index cannot be negative: {self.block_index}")
        if self.char_start is not None and self.char_start < 0:
            raise ValidationError(f"char_start cannot be negative: {self.char_start}")
        if self.char_end is not None and self.char_end < 0:
            raise ValidationError(f"char_end cannot be negative: {self.char_end}")
        if (
            self.char_start is not None
            and self.char_end is not None
            and self.char_start > self.char_end
        ):
            msg = (
                f"char_start ({self.char_start}) cannot "
                f"exceed char_end ({self.char_end})"
            )
            raise ValidationError(msg)
