"""Comprehensive test suite for the Content Transformation / Redaction Engine.

Covers all requirements for Step 7:
- Basic lifecycle and no-op conditions (clean content, empty string)
- Policy-action governance (ALLOW, WARN, BLOCK, REDACT)
- Secret span redaction and safe semantic placeholder substitution
- Immutability and privacy guarantees (repr, str, exception messages)
- Multiple spans, reverse textual order, and input-order invariance
- Offset boundaries (beginning, middle, end, multiline, Unicode)
- Overlapping, nested, adjacent, and duplicate spans with deterministic resolution
- Span coordinate validation (negative, inverted, out-of-bounds, empty spans)
- Architectural boundary enforcement (zero detector or policy engine calls)
- End-to-end integration: SecretDetector -> PolicyEngine -> RedactionEngine
"""

from unittest.mock import patch

import pytest

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)
from aifirewall.detectors.base import DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyRule
from aifirewall.protocols import ContentTransformer
from aifirewall.transform import RedactionEngine as AliasedRedactionEngine
from aifirewall.transformation import (
    RedactionEngine,
)


def make_test_detection(
    detection_id: str = "det-001",
    category: DetectionCategory | str = DetectionCategory.SECRET,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.95,
    detector_name: str = "test_detector",
    source: ContentSource = ContentSource.USER,
    char_start: int = 0,
    char_end: int = 10,
    description: str = "Synthetic test secret finding",
    metadata: dict | None = None,
) -> DetectionResult:
    """Helper to construct synthetic, privacy-safe DetectionResult instances."""
    return DetectionResult(
        detection_id=detection_id,
        detector_name=detector_name,
        category=category,
        severity=severity,
        confidence=confidence,
        location=ContentLocation(
            source=source,
            char_start=char_start,
            char_end=char_end,
        ),
        description=description,
        metadata=metadata or {},
    )


def make_decision(
    action: PolicyAction = PolicyAction.REDACT,
    detections: list[DetectionResult] | None = None,
    rule_id: str = "rule-redact-all",
) -> PolicyDecision:
    """Helper to construct a deterministic PolicyDecision."""
    dets = detections or []
    return PolicyDecision(
        action=action,
        reason=f"Action {action} triggered by {rule_id}.",
        matched_rules=[rule_id],
        detections=dets,
    )


# ==============================================================================
# 1. BASIC ENGINE LIFECYCLE & PROTOCOL
# ==============================================================================


def test_redaction_engine_instantiation():
    """Verify RedactionEngine can be instantiated with default and custom mappings."""
    engine = RedactionEngine()
    assert isinstance(engine, RedactionEngine)
    assert engine.get_placeholder(DetectionCategory.SECRET) == "[REDACTED_SECRET]"
    assert engine.get_placeholder(DetectionCategory.PII) == "[REDACTED_PII]"

    # Protocol conformance
    assert isinstance(engine, ContentTransformer)


def test_aliased_import():
    """Verify RedactionEngine is accessible via both packages."""
    engine = AliasedRedactionEngine()
    assert isinstance(engine, RedactionEngine)


def test_clean_content_remains_unchanged():
    """Verify clean content returns unchanged string with changed=False."""
    engine = RedactionEngine()
    content = "Hello, this is a clean query without any credentials."
    decision = make_decision(action=PolicyAction.REDACT, detections=[])

    result = engine.redact(content=content, detections=[], decision=decision)
    assert result.content == content
    assert result.changed is False
    assert result.redaction_count == 0
    assert result.redacted_detection_ids == ()
    assert result.categories == ()


def test_empty_content_remains_unchanged():
    """Verify empty string returns empty string with changed=False."""
    engine = RedactionEngine()
    decision = make_decision(action=PolicyAction.REDACT, detections=[])

    result = engine.redact(content="", detections=[], decision=decision)
    assert result.content == ""
    assert result.changed is False
    assert result.redaction_count == 0


def test_result_reports_changed_false_on_noop():
    """Verify changed is False whenever no modifications occur."""
    engine = RedactionEngine()
    content = "Some text"
    det = make_test_detection(char_start=0, char_end=4)
    # Decision is ALLOW, so no modification occurs
    decision = make_decision(action=PolicyAction.ALLOW, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.changed is False
    assert result.redaction_count == 0
    assert result.content == content


# ==============================================================================
# 2. POLICY ACTIONS GOVERNANCE
# ==============================================================================


def test_allow_leaves_content_unchanged():
    """Verify PolicyAction.ALLOW returns original content unmodified."""
    engine = RedactionEngine()
    content = "My token is sk-mock-1234567890abcdef"
    det = make_test_detection(char_start=12, char_end=36)
    decision = make_decision(action=PolicyAction.ALLOW, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.content == content
    assert result.changed is False
    assert result.redaction_count == 0


def test_warn_leaves_content_unchanged():
    """Verify PolicyAction.WARN returns original content unmodified."""
    engine = RedactionEngine()
    content = "My token is sk-mock-1234567890abcdef"
    det = make_test_detection(char_start=12, char_end=36)
    decision = make_decision(action=PolicyAction.WARN, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.content == content
    assert result.changed is False
    assert result.redaction_count == 0


def test_block_leaves_content_unchanged():
    """Verify PolicyAction.BLOCK returns original content unmodified in Step 7."""
    engine = RedactionEngine()
    content = "My token is sk-mock-1234567890abcdef"
    det = make_test_detection(char_start=12, char_end=36)
    decision = make_decision(action=PolicyAction.BLOCK, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.content == content
    assert result.changed is False
    assert result.redaction_count == 0


def test_redact_transforms_content():
    """Verify PolicyAction.REDACT performs content transformation."""
    engine = RedactionEngine()
    content = "My token is sk-mock-1234567890abcdef"
    det = make_test_detection(char_start=12, char_end=36)
    decision = make_decision(action=PolicyAction.REDACT, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.changed is True
    assert result.redaction_count == 1
    assert result.content == "My token is [REDACTED_SECRET]"


# ==============================================================================
# 3. SECRET REDACTION & PRIVACY GUARANTEES
# ==============================================================================


def test_single_secret_span_replaced_with_safe_placeholder():
    """Verify a single secret span is replaced with expected placeholder."""
    engine = RedactionEngine()
    raw_secret = "ghp_dummytoken12345678901234567890"
    content = f"Authorization: {raw_secret}"
    start = content.index(raw_secret)
    end = start + len(raw_secret)
    det = make_test_detection(
        detection_id="det-gh-token",
        category=DetectionCategory.SECRET,
        char_start=start,
        char_end=end,
    )
    decision = make_decision(action=PolicyAction.REDACT, detections=[det])

    result = engine.redact(content=content, detections=[det], decision=decision)
    assert result.content == "Authorization: [REDACTED_SECRET]"
    assert raw_secret not in result.content
    assert result.redacted_detection_ids == ("det-gh-token",)
    assert result.categories == ("secret",)


def test_raw_secret_absent_from_repr_and_str():
    """Verify RedactionResult __repr__ and __str__ never contain raw secrets."""
    raw_secret = "super_secret_password_1234"
    content = f"password={raw_secret}"
    det = make_test_detection(char_start=9, char_end=9 + len(raw_secret))
    decision = make_decision(action=PolicyAction.REDACT, detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content=content, detections=[det], decision=decision)

    repr_str = repr(result)
    str_summary = str(result)

    assert raw_secret not in repr_str
    assert raw_secret not in str_summary
    assert "RedactionResult" in repr_str
    assert "RedactionResult" in str_summary


def test_untransformed_secret_absent_from_repr_under_allow_or_block():
    """Verify __repr__ and __str__ do not leak content even when unmodified."""
    raw_secret = "sensitive_unredacted_key_9999"
    content = f"api_key={raw_secret}"
    det = make_test_detection(char_start=8, char_end=8 + len(raw_secret))
    decision = make_decision(action=PolicyAction.BLOCK, detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content=content, detections=[det], decision=decision)

    assert raw_secret not in repr(result)
    assert raw_secret not in str(result)


# ==============================================================================
# 4. MULTIPLE SPANS & ORDER INVARIANCE
# ==============================================================================


def test_multiple_non_overlapping_spans_redacted():
    """Verify multiple disjoint sensitive spans are all redacted."""
    content = "First key sk-proj-1111111111 and second key sk-proj-2222222222 here."
    sec1 = "sk-proj-1111111111"
    sec2 = "sk-proj-2222222222"
    det1 = make_test_detection(
        detection_id="det-1",
        char_start=content.index(sec1),
        char_end=content.index(sec1) + len(sec1),
    )
    det2 = make_test_detection(
        detection_id="det-2",
        char_start=content.index(sec2),
        char_end=content.index(sec2) + len(sec2),
    )
    decision = make_decision(action=PolicyAction.REDACT, detections=[det1, det2])

    engine = RedactionEngine()
    result = engine.redact(content=content, detections=[det1, det2], decision=decision)

    expected = "First key [REDACTED_SECRET] and second key [REDACTED_SECRET] here."
    assert result.content == expected
    assert result.redaction_count == 2
    assert set(result.redacted_detection_ids) == {"det-1", "det-2"}


def test_reverse_textual_order_input():
    """Verify redaction succeeds when detections are passed in reverse order."""
    content = "A: 111111, B: 222222, C: 333333"
    det1 = make_test_detection(detection_id="det-1", char_start=3, char_end=9)
    det2 = make_test_detection(detection_id="det-2", char_start=14, char_end=20)
    det3 = make_test_detection(detection_id="det-3", char_start=25, char_end=31)

    engine = RedactionEngine()
    decision_fwd = make_decision(detections=[det1, det2, det3])
    decision_rev = make_decision(detections=[det3, det2, det1])

    res_fwd = engine.redact(content, [det1, det2, det3], decision_fwd)
    res_rev = engine.redact(content, [det3, det2, det1], decision_rev)

    assert res_fwd.content == res_rev.content
    assert (
        res_fwd.content
        == "A: [REDACTED_SECRET], B: [REDACTED_SECRET], C: [REDACTED_SECRET]"
    )
    assert res_fwd.redaction_count == 3
    assert res_fwd.redacted_detection_ids == res_rev.redacted_detection_ids


def test_output_independent_of_detection_input_order():
    """Verify permuting detection order results in deterministic, identical output."""
    content = "Alpha AAA, Beta BBB, Gamma CCC"
    det_a = make_test_detection(detection_id="det-a", char_start=6, char_end=9)
    det_b = make_test_detection(detection_id="det-b", char_start=16, char_end=19)
    det_c = make_test_detection(detection_id="det-c", char_start=27, char_end=30)

    engine = RedactionEngine()
    decision = make_decision(detections=[det_a, det_b, det_c])

    import itertools

    permutations = list(itertools.permutations([det_a, det_b, det_c]))
    results = [engine.redact(content, p, decision) for p in permutations]

    expected_content = (
        "Alpha [REDACTED_SECRET], Beta [REDACTED_SECRET], Gamma [REDACTED_SECRET]"
    )
    for r in results:
        assert r.content == expected_content
        assert r.redaction_count == 3
        assert r.redacted_detection_ids == ("det-a", "det-b", "det-c")


def test_repeated_identical_secrets_independently_redacted():
    """Verify identical secrets appearing repeatedly are independently redacted."""
    content = "token=SAME_SECRET and again token=SAME_SECRET in prompt"
    # SAME_SECRET is 11 chars
    start1 = content.index("SAME_SECRET")
    end1 = start1 + 11
    start2 = content.rindex("SAME_SECRET")
    end2 = start2 + 11

    det1 = make_test_detection(
        detection_id="det-occ-1", char_start=start1, char_end=end1
    )
    det2 = make_test_detection(
        detection_id="det-occ-2", char_start=start2, char_end=end2
    )
    decision = make_decision(detections=[det1, det2])

    engine = RedactionEngine()
    result = engine.redact(content, [det1, det2], decision)

    assert (
        result.content
        == "token=[REDACTED_SECRET] and again token=[REDACTED_SECRET] in prompt"
    )
    assert result.redaction_count == 2
    assert result.redacted_detection_ids == ("det-occ-1", "det-occ-2")


# ==============================================================================
# 5. OFFSETS & SPECIAL TEXT STRUCTURES
# ==============================================================================


def test_beginning_of_string_span():
    """Verify redaction of a span starting at index 0."""
    content = "SECRET_AT_START is here"
    det = make_test_detection(char_start=0, char_end=15)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    assert result.content == "[REDACTED_SECRET] is here"
    assert result.redaction_count == 1


def test_middle_of_string_span():
    """Verify redaction of a span strictly in the middle."""
    content = "prefix SECRET suffix"
    det = make_test_detection(char_start=7, char_end=13)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    assert result.content == "prefix [REDACTED_SECRET] suffix"


def test_end_of_string_span():
    """Verify redaction of a span ending at len(content)."""
    content = "Ends with SECRET"
    start = content.index("SECRET")
    det = make_test_detection(char_start=start, char_end=len(content))
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    assert result.content == "Ends with [REDACTED_SECRET]"


def test_entire_string_span():
    """Verify redaction when the span covers the entire string."""
    content = "WHOLE_STRING_SECRET"
    det = make_test_detection(char_start=0, char_end=len(content))
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    assert result.content == "[REDACTED_SECRET]"
    assert result.redaction_count == 1


def test_multiline_span():
    """Verify character offsets across newline boundaries work accurately."""
    content = "Line 1: safe\nLine 2: SECRET_KEY_VAL\nLine 3: safe"
    start = content.index("SECRET_KEY_VAL")
    end = start + len("SECRET_KEY_VAL")
    det = make_test_detection(char_start=start, char_end=end)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    expected = "Line 1: safe\nLine 2: [REDACTED_SECRET]\nLine 3: safe"
    assert result.content == expected


def test_unicode_surrounding_text_preservation():
    """Verify non-ASCII Unicode characters surrounding sensitive spans remain intact."""
    content = "Prompt with 日本語 and emojis 🛡️ secret_code_12345 🚀 and accents café"
    sec = "secret_code_12345"
    start = content.index(sec)
    end = start + len(sec)
    det = make_test_detection(char_start=start, char_end=end)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)
    expected = "Prompt with 日本語 and emojis 🛡️ [REDACTED_SECRET] 🚀 and accents café"
    assert result.content == expected


# ==============================================================================
# 6. OVERLAPPING, NESTED & DUPLICATE SPANS
# ==============================================================================


def test_overlapping_spans_merged_into_single_replacement():
    """Verify partially overlapping detections are merged into one union span."""
    # Indexes: 012345678901234567890123456789
    # Content: "Prefix ABCDEFGHIJKLMNOP Suffix"
    # Det 1: [7, 18]  ("ABCDEFGHIJK")
    # Det 2: [14, 23] ("HIJKLMNOP")
    # Overlap region: [14, 18]
    # Union span: [7, 23] ("ABCDEFGHIJKLMNOP")
    content = "Prefix ABCDEFGHIJKLMNOP Suffix"
    det1 = make_test_detection(
        detection_id="det-1",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
        confidence=0.90,
        char_start=7,
        char_end=18,
    )
    det2 = make_test_detection(
        detection_id="det-2",
        category=DetectionCategory.SECRET,
        severity=Severity.MEDIUM,
        confidence=0.85,
        char_start=14,
        char_end=23,
    )
    decision = make_decision(detections=[det1, det2])

    engine = RedactionEngine()
    result = engine.redact(content, [det1, det2], decision)

    assert result.content == "Prefix [REDACTED_SECRET] Suffix"
    assert result.redaction_count == 1
    assert result.redacted_detection_ids == ("det-1", "det-2")


def test_nested_span_merged():
    """Verify an inner span contained entirely within a larger span is merged."""
    content = "Data: BIGGER_OUTER_SECRET_WRAPPER end"
    outer = "BIGGER_OUTER_SECRET_WRAPPER"
    inner = "OUTER_SECRET"
    start_outer = content.index(outer)
    end_outer = start_outer + len(outer)
    start_inner = content.index(inner)
    end_inner = start_inner + len(inner)

    det_outer = make_test_detection(
        detection_id="det-outer",
        char_start=start_outer,
        char_end=end_outer,
        severity=Severity.HIGH,
    )
    det_inner = make_test_detection(
        detection_id="det-inner",
        char_start=start_inner,
        char_end=end_inner,
        severity=Severity.LOW,
    )
    decision = make_decision(detections=[det_outer, det_inner])

    engine = RedactionEngine()
    result = engine.redact(content, [det_outer, det_inner], decision)

    assert result.content == "Data: [REDACTED_SECRET] end"
    assert result.redaction_count == 1
    assert set(result.redacted_detection_ids) == {"det-inner", "det-outer"}


def test_overlap_resolution_deterministic_by_severity():
    """Verify higher severity takes precedence in determining cluster placeholder."""
    content = "Item [OVERLAPPING_SECRET_AND_PII] Done"
    start = content.index("OVERLAPPING_SECRET_AND_PII")
    end = start + len("OVERLAPPING_SECRET_AND_PII")

    det_pii = make_test_detection(
        detection_id="det-pii",
        category=DetectionCategory.PII,
        severity=Severity.MEDIUM,
        confidence=0.99,
        char_start=start,
        char_end=end - 5,
    )
    det_secret = make_test_detection(
        detection_id="det-sec",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,  # High > Medium
        confidence=0.70,
        char_start=start + 5,
        char_end=end,
    )

    engine = RedactionEngine()
    decision = make_decision(detections=[det_pii, det_secret])

    # Irrespective of order, Secret (HIGH) beats PII (MEDIUM)
    res1 = engine.redact(content, [det_pii, det_secret], decision)
    res2 = engine.redact(content, [det_secret, det_pii], decision)

    assert res1.content == "Item [[REDACTED_SECRET]] Done"
    assert res2.content == res1.content
    assert res1.redaction_count == 1


def test_overlap_resolution_tie_breaking_confidence_length_id():
    """Verify deterministic tie-breaking when severities are equal."""
    content = "Base 012345678901234 End"

    # Same category, same severity, different confidence
    det_a = make_test_detection(
        detection_id="det-a",
        category=DetectionCategory.PII,
        severity=Severity.HIGH,
        confidence=0.95,
        char_start=5,
        char_end=15,
    )
    det_b = make_test_detection(
        detection_id="det-b",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
        confidence=0.80,
        char_start=10,
        char_end=20,
    )

    engine = RedactionEngine()
    decision = make_decision(detections=[det_a, det_b])

    # det_a has higher confidence (0.95 vs 0.80), so PII placeholder is selected
    res = engine.redact(content, [det_a, det_b], decision)
    assert res.content == "Base [REDACTED_PII] End"
    assert res.redaction_count == 1


def test_duplicate_identical_spans_handled_predictably():
    """Verify duplicate identical spans are consolidated into 1 replacement."""
    content = "Token is DUMMY_KEY_VAL_12345"
    det1 = make_test_detection(
        detection_id="det-dup-1",
        char_start=9,
        char_end=28,
    )
    det2 = make_test_detection(
        detection_id="det-dup-2",
        char_start=9,
        char_end=28,
    )
    decision = make_decision(detections=[det1, det2])

    engine = RedactionEngine()
    res = engine.redact(content, [det1, det2], decision)

    assert res.content == "Token is [REDACTED_SECRET]"
    assert res.redaction_count == 1
    assert res.redacted_detection_ids == ("det-dup-1", "det-dup-2")


def test_adjacent_spans_replaced_independently():
    """Verify adjacent spans that touch at boundaries are replaced separately."""
    content = "AAAABBBB"
    det1 = make_test_detection(detection_id="d1", char_start=0, char_end=4)
    det2 = make_test_detection(detection_id="d2", char_start=4, char_end=8)
    decision = make_decision(detections=[det1, det2])

    engine = RedactionEngine()
    res = engine.redact(content, [det1, det2], decision)

    assert res.content == "[REDACTED_SECRET][REDACTED_SECRET]"
    assert res.redaction_count == 2
    assert res.redacted_detection_ids == ("d1", "d2")


# ==============================================================================
# 7. SPAN VALIDATION & ERROR HANDLING
# ==============================================================================


def test_negative_char_start_rejected():
    """Verify negative char_start raises ValidationError."""
    engine = RedactionEngine()
    # Construct invalid location to bypass ContentLocation validation
    det = make_test_detection()
    object.__setattr__(det.location, "char_start", -5)
    decision = make_decision(detections=[det])

    with pytest.raises(ValidationError, match="Invalid negative char_start"):
        engine.redact("Sample text", [det], decision)


def test_negative_char_end_rejected():
    """Verify negative char_end raises ValidationError."""
    engine = RedactionEngine()
    det = make_test_detection()
    object.__setattr__(det.location, "char_end", -1)
    decision = make_decision(detections=[det])

    with pytest.raises(ValidationError, match="Invalid negative char_end"):
        engine.redact("Sample text", [det], decision)


def test_inverted_offsets_rejected():
    """Verify char_start > char_end raises ValidationError."""
    engine = RedactionEngine()
    det = make_test_detection()
    object.__setattr__(det.location, "char_start", 20)
    object.__setattr__(det.location, "char_end", 10)
    decision = make_decision(detections=[det])

    with pytest.raises(ValidationError, match="Invalid inverted offsets"):
        engine.redact("Sample text", [det], decision)


def test_char_end_exceeds_content_length_rejected():
    """Verify char_end > len(content) raises ValidationError."""
    content = "Short"  # len 5
    det = make_test_detection(char_start=0, char_end=50)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    with pytest.raises(ValidationError, match="exceeds content length"):
        engine.redact(content, [det], decision)


def test_missing_offsets_rejected():
    """Verify None offsets raise ValidationError."""
    content = "Short content"
    det = make_test_detection()
    object.__setattr__(det.location, "char_start", None)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    with pytest.raises(ValidationError, match="Missing character offsets"):
        engine.redact(content, [det], decision)


def test_invalid_span_error_does_not_reveal_content():
    """Verify validation error messages are strictly non-sensitive."""
    secret_text = "sk-super-secret-production-key-9999"
    content = f"Auth {secret_text}"
    det = make_test_detection(char_start=5, char_end=500)  # out of bounds
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    with pytest.raises(ValidationError) as exc_info:
        engine.redact(content, [det], decision)

    err_msg = str(exc_info.value)
    assert secret_text not in err_msg
    assert "sk-super" not in err_msg


def test_empty_span_is_safely_skipped():
    """Verify zero-width empty spans are ignored without mutating text."""
    content = "Original text content"
    det = make_test_detection(char_start=5, char_end=5)
    decision = make_decision(detections=[det])

    engine = RedactionEngine()
    result = engine.redact(content, [det], decision)

    assert result.content == content
    assert result.changed is False
    assert result.redaction_count == 0


def test_invalid_parameter_types_rejected():
    """Verify invalid input types raise ValidationError."""
    engine = RedactionEngine()
    decision = make_decision()

    with pytest.raises(ValidationError, match="content must be a string"):
        engine.redact(123, [], decision)  # type: ignore[arg-type]

    with pytest.raises(ValidationError, match="decision must be a PolicyDecision"):
        engine.redact("text", [], "ALLOW")  # type: ignore[arg-type]

    with pytest.raises(ValidationError, match="detections must be a sequence"):
        engine.redact("text", None, decision)  # type: ignore[arg-type]


# ==============================================================================
# 8. CALLER-OWNED ARGUMENT IMMUTABILITY
# ==============================================================================


def test_original_content_and_models_are_immutable():
    """Verify calling redact() does not mutate caller objects."""
    content = "Immutable content with SECRET"
    loc = ContentLocation(source=ContentSource.USER, char_start=23, char_end=29)
    det = DetectionResult(
        detection_id="det-imm",
        detector_name="detector",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
        confidence=0.9,
        location=loc,
        description="Immutable finding",
    )
    detections = [det]
    decision = make_decision(detections=detections)

    engine = RedactionEngine()
    engine.redact(content, detections, decision)

    assert det.location.char_start == 23
    assert det.location.char_end == 29
    assert len(detections) == 1
    assert decision.action == PolicyAction.REDACT


# ==============================================================================
# 9. CATEGORY-AWARE EXTENSIBILITY
# ==============================================================================


def test_category_aware_placeholders():
    """Verify each category resolves to its semantic placeholder."""
    engine = RedactionEngine()
    assert engine.get_placeholder(DetectionCategory.SECRET) == "[REDACTED_SECRET]"
    assert engine.get_placeholder(DetectionCategory.PII) == "[REDACTED_PII]"
    assert (
        engine.get_placeholder(DetectionCategory.PROMPT_INJECTION)
        == "[REDACTED_PROMPT_INJECTION]"
    )
    assert engine.get_placeholder(DetectionCategory.OTHER) == "[REDACTED]"
    assert engine.get_placeholder("unknown_custom_category") == "[REDACTED]"


def test_custom_placeholders_and_fallback():
    """Verify custom placeholder overrides in constructor."""
    custom = {
        DetectionCategory.SECRET: "<HIDDEN_KEY>",
        "custom_cat": "<HIDDEN_CUSTOM>",
    }
    engine = RedactionEngine(placeholders=custom, default_placeholder="<SAFE>")

    assert engine.get_placeholder(DetectionCategory.SECRET) == "<HIDDEN_KEY>"
    assert engine.get_placeholder("custom_cat") == "<HIDDEN_CUSTOM>"
    assert engine.get_placeholder(DetectionCategory.PII) == "<SAFE>"

    content = "Key: 1234567890"
    det = make_test_detection(
        category=DetectionCategory.SECRET, char_start=5, char_end=15
    )
    decision = make_decision(detections=[det])
    res = engine.redact(content, [det], decision)
    assert res.content == "Key: <HIDDEN_KEY>"


# ==============================================================================
# 10. ARCHITECTURAL BOUNDARY (NO SECRET DETECTOR OR POLICY RE-EVALUATION)
# ==============================================================================


def test_redaction_engine_does_not_invoke_detectors_or_policy():
    """Verify RedactionEngine does not call SecretDetector or PolicyEngine."""
    content = "Authorization: Bearer mock_bearer_token_1234567890"
    det = make_test_detection(char_start=15, char_end=len(content))
    decision = make_decision(detections=[det])

    engine = RedactionEngine()

    with (
        patch.object(
            SecretDetector, "detect", side_effect=RuntimeError("DETECTOR CALLED")
        ),
        patch.object(
            PolicyEngine, "evaluate", side_effect=RuntimeError("POLICY CALLED")
        ),
    ):
        # Must succeed without calling SecretDetector.detect or PolicyEngine.evaluate
        result = engine.redact(content, [det], decision)

    assert result.changed is True
    assert "[REDACTED_SECRET]" in result.content


# ==============================================================================
# 11. DETERMINISM
# ==============================================================================


def test_determinism_identical_runs():
    """Verify multiple executions with identical inputs produce identical outputs."""
    content = "User prompt with TOKEN_A and TOKEN_B and TOKEN_C"
    det1 = make_test_detection(detection_id="d1", char_start=17, char_end=24)
    det2 = make_test_detection(detection_id="d2", char_start=29, char_end=36)
    det3 = make_test_detection(detection_id="d3", char_start=41, char_end=48)
    decision = make_decision(detections=[det1, det2, det3])

    engine = RedactionEngine()
    results = [engine.redact(content, [det1, det2, det3], decision) for _ in range(5)]

    first = results[0]
    for r in results[1:]:
        assert r.content == first.content
        assert r.changed == first.changed
        assert r.redaction_count == first.redaction_count
        assert r.redacted_detection_ids == first.redacted_detection_ids
        assert r.categories == first.categories


# ==============================================================================
# 12. END-TO-END LOCAL INTEGRATION
# ==============================================================================


def test_integration_secret_detector_to_policy_engine_to_redaction_engine():
    """Verify end-to-end flow: SecretDetector -> PolicyEngine -> RedactionEngine."""
    # 1. Prepare synthetic prompt with OpenAI-style test token
    raw_secret = "sk-proj-999988887777666655554444"
    prompt = f"Please use my key {raw_secret} to query the weather."

    # 2. Step 5: Detector execution
    detector = SecretDetector()
    context = DetectorContext(
        request_id="req-integ-001",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )
    findings = detector.detect(prompt, context)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == DetectionCategory.SECRET
    assert finding.location.char_start == prompt.index(raw_secret)
    assert finding.location.char_end == prompt.index(raw_secret) + len(raw_secret)

    # 3. Step 6: Policy evaluation
    rule = PolicyRule(
        rule_id="redact_all_secrets",
        action=PolicyAction.REDACT,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
    )
    policy_engine = PolicyEngine(rules=[rule])
    decision = policy_engine.evaluate(findings)
    assert decision.action == PolicyAction.REDACT
    assert "redact_all_secrets" in decision.matched_rules

    # 4. Step 7: Content transformation
    transformer = RedactionEngine()
    redaction_result = transformer.redact(
        content=prompt,
        detections=findings,
        decision=decision,
    )

    # 5. Verify transformed output
    assert redaction_result.changed is True
    assert redaction_result.redaction_count == 1
    assert raw_secret not in redaction_result.content
    assert (
        redaction_result.content
        == "Please use my key [REDACTED_SECRET] to query the weather."
    )
    assert redaction_result.redacted_detection_ids == (finding.detection_id,)
    assert redaction_result.categories == ("secret",)

    # Verify original prompt was never altered
    assert raw_secret in prompt


def test_integration_warn_policy_leaves_prompt_unmodified():
    """Verify end-to-end flow where policy mandates WARN produces unchanged output."""
    raw_secret = "sk-proj-123451234512345123451234"
    prompt = f"Using {raw_secret}"

    detector = SecretDetector()
    findings = detector.detect(
        prompt,
        DetectorContext(
            request_id="req-warn",
            direction=ContentDirection.REQUEST,
        ),
    )
    assert len(findings) == 1

    rule = PolicyRule(
        rule_id="warn_on_secrets",
        action=PolicyAction.WARN,
        category=DetectionCategory.SECRET,
    )
    decision = PolicyEngine(rules=[rule]).evaluate(findings)
    assert decision.action == PolicyAction.WARN

    transformer = RedactionEngine()
    result = transformer.redact(prompt, findings, decision)
    assert result.content == prompt
    assert result.changed is False
    assert result.redaction_count == 0


def test_integration_block_policy_leaves_prompt_unmodified():
    """Verify end-to-end flow where policy mandates BLOCK leaves content unmodified."""
    raw_secret = "ghp_123456789012345678901234567890123456"
    prompt = f"Token: {raw_secret}"

    detector = SecretDetector()
    findings = detector.detect(
        prompt,
        DetectorContext(
            request_id="req-block",
            direction=ContentDirection.REQUEST,
        ),
    )
    assert len(findings) == 1

    rule = PolicyRule(
        rule_id="block_github_tokens",
        action=PolicyAction.BLOCK,
        category=DetectionCategory.SECRET,
    )
    decision = PolicyEngine(rules=[rule]).evaluate(findings)
    assert decision.action == PolicyAction.BLOCK

    transformer = RedactionEngine()
    result = transformer.redact(prompt, findings, decision)
    assert result.content == prompt
    assert result.changed is False
    assert result.redaction_count == 0


def test_content_transformer_protocol_direct_transform():
    """Verify direct transform() invocation fulfilling ContentTransformer protocol."""
    engine = RedactionEngine()
    content = "Key: sk-proj-1234567890abcdef1234"
    det = make_test_detection(char_start=5, char_end=len(content))

    transformed = engine.transform(content, [det])
    assert transformed == "Key: [REDACTED_SECRET]"
