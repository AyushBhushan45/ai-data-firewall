"""Tests for the Detector protocol, DetectorContext, and failure isolation."""

from dataclasses import FrozenInstanceError

import pytest

from aifirewall.core.errors import DetectorError, ValidationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    Severity,
)
from aifirewall.detectors.base import Detector, DetectorContext
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult


class FakeBenignDetector:
    """A clean test detector that produces zero findings."""

    @property
    def name(self) -> str:
        return "fake_benign_detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "A test detector that scans for simulated patterns."

    @property
    def supported_categories(self) -> tuple[DetectionCategory, ...]:
        return (DetectionCategory.SECRET,)

    def detect(
        self, content: str, context: DetectorContext
    ) -> list[DetectionResult]:
        return []


class FakeFindingDetector:
    """A test detector that identifies a simulated trigger word."""

    @property
    def name(self) -> str:
        return "fake_finding_detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Flags occurrences of 'TRIGGER' safely."

    @property
    def supported_categories(self) -> tuple[DetectionCategory, ...]:
        return (DetectionCategory.SECRET,)

    def detect(
        self, content: str, context: DetectorContext
    ) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        needle = "TRIGGER"
        idx = content.find(needle)
        if idx != -1:
            loc = ContentLocation(
                source=context.source,
                char_start=idx,
                char_end=idx + len(needle),
            )
            results.append(
                DetectionResult(
                    detection_id="det-test-01",
                    detector_name=self.name,
                    category=DetectionCategory.SECRET,
                    severity=Severity.HIGH,
                    confidence=0.99,
                    location=loc,
                    description="Simulated finding pattern identified",
                )
            )
        return results


class FakeFailingDetector:
    """A test detector that simulates an unhandled internal exception."""

    @property
    def name(self) -> str:
        return "fake_failing_detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Simulates an operational failure."

    @property
    def supported_categories(self) -> tuple[DetectionCategory, ...]:
        return (DetectionCategory.OTHER,)

    def detect(
        self, content: str, context: DetectorContext
    ) -> list[DetectionResult]:
        raise DetectorError(self.name, "Failed to inspect content due to syntax error")


def test_detector_context_valid():
    """Verify DetectorContext attributes, defaults, and immutability."""
    loc = ContentLocation(source=ContentSource.USER, char_start=0, char_end=10)
    ctx = DetectorContext(
        request_id="req-ctx-001",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
        model="gpt-4o",
        provider="openai",
        location=loc,
        metadata={"tenant": "test_corp"},
    )
    assert ctx.request_id == "req-ctx-001"
    assert ctx.direction == ContentDirection.REQUEST
    assert ctx.source == ContentSource.USER
    assert ctx.model == "gpt-4o"
    assert ctx.provider == "openai"
    assert ctx.location == loc
    assert ctx.metadata["tenant"] == "test_corp"

    with pytest.raises(FrozenInstanceError):
        ctx.model = "claude"  # type: ignore[misc]


def test_detector_context_validation():
    """Verify DetectorContext rejects empty request IDs."""
    with pytest.raises(ValidationError, match="request_id"):
        DetectorContext(
            request_id="",
            direction=ContentDirection.REQUEST,
        )

    with pytest.raises(ValidationError, match="request_id"):
        DetectorContext(
            request_id="   ",
            direction=ContentDirection.REQUEST,
        )


def test_detector_protocol_conformance():
    """Verify that conforming classes satisfy the Detector protocol."""
    benign = FakeBenignDetector()
    finding = FakeFindingDetector()
    failing = FakeFailingDetector()

    assert isinstance(benign, Detector)
    assert isinstance(finding, Detector)
    assert isinstance(failing, Detector)


def test_detector_clean_content_returns_empty_list():
    """Verify detector returns an empty list when no patterns match."""
    detector = FakeBenignDetector()
    ctx = DetectorContext(
        request_id="req-001",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )
    findings = detector.detect("Hello world, this is normal text.", ctx)
    assert findings == []
    assert isinstance(findings, list)


def test_detector_matching_content_returns_detection_results():
    """Verify detector returns properly formed DetectionResult findings."""
    detector = FakeFindingDetector()
    ctx = DetectorContext(
        request_id="req-002",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )
    content = "Sensitive TRIGGER contained here."
    findings = detector.detect(content, ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_name == "fake_finding_detector"
    assert finding.category == DetectionCategory.SECRET
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.99
    assert finding.location.char_start == 10
    assert finding.location.char_end == 17
    assert finding.description == "Simulated finding pattern identified"


def test_detector_failure_isolation():
    """Verify that detector errors raise DetectorError with safe messages."""
    detector = FakeFailingDetector()
    ctx = DetectorContext(
        request_id="req-003",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )
    with pytest.raises(DetectorError) as exc_info:
        detector.detect("Any text", ctx)

    err = exc_info.value
    assert err.detector_name == "fake_failing_detector"
    assert "Detector 'fake_failing_detector' failed" in str(err)
    assert "syntax error" in str(err)
