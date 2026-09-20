"""Tests for DetectionResult, confidence validation, offsets, and privacy guarantees."""

from dataclasses import FrozenInstanceError

import pytest

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import ContentSource, DetectionCategory, Severity
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult


def test_detection_result_valid_creation():
    """Verify DetectionResult initialization with valid inputs."""
    loc = ContentLocation(
        source=ContentSource.USER,
        message_index=0,
        char_start=15,
        char_end=35,
    )
    result = DetectionResult(
        detection_id="det-001",
        detector_name="entropy_detector",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
        confidence=0.88,
        location=loc,
        description="High-entropy token sequence identified",
        metadata={"token_length": 20},
    )
    assert result.detection_id == "det-001"
    assert result.detector_name == "entropy_detector"
    assert result.category == DetectionCategory.SECRET
    assert result.severity == Severity.HIGH
    assert result.confidence == 0.88
    assert result.location == loc
    assert result.description == "High-entropy token sequence identified"
    assert result.metadata["token_length"] == 20


def test_detection_result_immutability():
    """Verify DetectionResult cannot be modified after creation."""
    loc = ContentLocation(source=ContentSource.USER)
    result = DetectionResult(
        detection_id="det-001",
        detector_name="test_detector",
        category=DetectionCategory.SECRET,
        severity=Severity.LOW,
        confidence=0.5,
        location=loc,
        description="Test finding",
    )
    with pytest.raises(FrozenInstanceError):
        result.confidence = 0.9  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        result.description = "Altered"  # type: ignore[misc]


@pytest.mark.parametrize("valid_conf", [0.0, 0.01, 0.5, 0.99, 1.0])
def test_confidence_validation_valid_values(valid_conf: float):
    """Verify confidence values between 0.0 and 1.0 are accepted."""
    loc = ContentLocation(source=ContentSource.USER)
    result = DetectionResult(
        detection_id="det-001",
        detector_name="test_detector",
        category=DetectionCategory.SECRET,
        severity=Severity.MEDIUM,
        confidence=valid_conf,
        location=loc,
        description="Confidence boundary test",
    )
    assert result.confidence == valid_conf


@pytest.mark.parametrize("invalid_conf", [-0.1, -1.0, 1.01, 1.5, 100.0])
def test_confidence_validation_invalid_values(invalid_conf: float):
    """Verify confidence values outside [0.0, 1.0] raise ValidationError."""
    loc = ContentLocation(source=ContentSource.USER)
    with pytest.raises(ValidationError, match="confidence must be between 0.0 and 1.0"):
        DetectionResult(
            detection_id="det-001",
            detector_name="test_detector",
            category=DetectionCategory.SECRET,
            severity=Severity.MEDIUM,
            confidence=invalid_conf,
            location=loc,
            description="Invalid confidence",
        )


@pytest.mark.parametrize("empty_id", ["", "   "])
def test_detection_result_empty_id_rejected(empty_id: str):
    """Verify empty or whitespace-only detection_id raises ValidationError."""
    loc = ContentLocation(source=ContentSource.USER)
    with pytest.raises(ValidationError, match="detection_id"):
        DetectionResult(
            detection_id=empty_id,
            detector_name="test_detector",
            category=DetectionCategory.SECRET,
            severity=Severity.MEDIUM,
            confidence=0.5,
            location=loc,
            description="Safe description",
        )


@pytest.mark.parametrize("empty_name", ["", "   "])
def test_detection_result_empty_detector_name_rejected(empty_name: str):
    """Verify empty or whitespace-only detector_name raises ValidationError."""
    loc = ContentLocation(source=ContentSource.USER)
    with pytest.raises(ValidationError, match="detector_name"):
        DetectionResult(
            detection_id="det-001",
            detector_name=empty_name,
            category=DetectionCategory.SECRET,
            severity=Severity.MEDIUM,
            confidence=0.5,
            location=loc,
            description="Safe description",
        )


@pytest.mark.parametrize("empty_desc", ["", "   "])
def test_detection_result_empty_description_rejected(empty_desc: str):
    """Verify empty or whitespace-only description raises ValidationError."""
    loc = ContentLocation(source=ContentSource.USER)
    with pytest.raises(ValidationError, match="description"):
        DetectionResult(
            detection_id="det-001",
            detector_name="test_detector",
            category=DetectionCategory.SECRET,
            severity=Severity.MEDIUM,
            confidence=0.5,
            location=loc,
            description=empty_desc,
        )


def test_location_offset_validation():
    """Verify ContentLocation raises ValidationError on invalid coordinates."""
    # Negative char_start
    with pytest.raises(ValidationError, match="char_start cannot be negative"):
        ContentLocation(source=ContentSource.USER, char_start=-1)

    # Negative char_end
    with pytest.raises(ValidationError, match="char_end cannot be negative"):
        ContentLocation(source=ContentSource.USER, char_end=-5)

    # char_start > char_end
    with pytest.raises(ValidationError, match="char_start .* cannot exceed char_end"):
        ContentLocation(source=ContentSource.USER, char_start=50, char_end=20)

    # Negative message_index
    with pytest.raises(ValidationError, match="message_index cannot be negative"):
        ContentLocation(source=ContentSource.USER, message_index=-1)

    # Negative block_index
    with pytest.raises(ValidationError, match="block_index cannot be negative"):
        ContentLocation(source=ContentSource.USER, block_index=-2)


def test_privacy_guarantees_no_raw_secrets():
    """Verify DetectionResult never has raw secret storage fields and is safe."""
    loc = ContentLocation(source=ContentSource.USER, char_start=10, char_end=30)
    finding = DetectionResult(
        detection_id="det-safe-01",
        detector_name="mock_scanner",
        category=DetectionCategory.SECRET,
        severity=Severity.CRITICAL,
        confidence=0.99,
        location=loc,
        description="Possible API credential detected",
    )

    # Verify no raw secret fields exist on the model
    forbidden_attributes = [
        "raw_content",
        "raw_secret",
        "secret_value",
        "detected_value",
        "original_prompt",
        "plaintext",
    ]
    for attr in forbidden_attributes:
        assert not hasattr(finding, attr)

    # Verify string and repr outputs are privacy-safe
    repr_str = repr(finding)
    assert "det-safe-01" in repr_str
    assert "mock_scanner" in repr_str
    assert "CRITICAL" in repr_str.upper()
    assert "Possible API credential detected" in repr_str

    str_summary = str(finding)
    assert "[CRITICAL]" in str_summary
    assert "Possible API credential detected" in str_summary
