"""Deterministic, policy-controlled content redaction engine for AI Data Firewall.

Enforces the core architectural separation:
    DETECTION ≠ POLICY ≠ TRANSFORMATION

The RedactionEngine is the ONLY component in the architecture permitted to
mutate content. It consumes:
1. Original text content
2. Normalized detection findings (DetectionResult[])
3. Evaluated policy decision (PolicyDecision)

When policy requires REDACT, it safely replaces sensitive spans with semantic
placeholders while guaranteeing:
- Offset safety via right-to-left replacement
- Deterministic overlap and nesting resolution
- Comprehensive span validation without information disclosure
- Complete caller-argument immutability
- Zero detector or policy re-evaluation
"""

from collections.abc import Sequence
from dataclasses import dataclass

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import DetectionCategory, PolicyAction, Severity
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision
from aifirewall.policy.models import SEVERITY_ORDER
from aifirewall.transformation.models import RedactionResult

# Standard semantic placeholders mapped by finding category
DEFAULT_PLACEHOLDERS: dict[DetectionCategory | str, str] = {
    DetectionCategory.SECRET: "[REDACTED_SECRET]",
    DetectionCategory.PII: "[REDACTED_PII]",
    DetectionCategory.PROMPT_INJECTION: "[REDACTED_PROMPT_INJECTION]",
    DetectionCategory.OTHER: "[REDACTED]",
}

DEFAULT_FALLBACK_PLACEHOLDER: str = "[REDACTED]"


@dataclass(frozen=True)
class _OverlapCluster:
    """Internal cluster representing one or more overlapping detection spans.

    Attributes:
        start: Inclusive character start of the merged replacement span.
        end: Exclusive character end of the merged replacement span.
        placeholder: Safe semantic placeholder selected for this span.
        category: Category label of the winning detection.
        detection_ids: Tuple of all detection IDs encompassed by this cluster.
    """

    start: int
    end: int
    placeholder: str
    category: str
    detection_ids: tuple[str, ...]


class RedactionEngine:
    """Deterministic, policy-controlled text transformation and redaction engine.

    The engine operates strictly on pre-computed finding coordinates and an
    evaluated PolicyDecision. It does not perform detection or evaluate rules.

    Replacement Strategy:
    - Candidate spans are validated strictly against content bounds.
    - Zero-width / empty spans (char_start == char_end) are ignored.
    - Overlapping and nested spans are merged into maximal contiguous spans.
    - Overlap tie-breaking is 100% deterministic (Severity > Confidence >
      Span Length > ID).
    - Replacements are applied strictly from right to left (char_start descending)
      to guarantee offset stability without index recalculation.
    """

    def __init__(
        self,
        placeholders: dict[DetectionCategory | str, str] | None = None,
        default_placeholder: str = DEFAULT_FALLBACK_PLACEHOLDER,
    ) -> None:
        """Initialize RedactionEngine with optional custom placeholder mapping.

        Args:
            placeholders: Mapping from DetectionCategory or category strings to
                replacement placeholder text.
            default_placeholder: Fallback placeholder when a category is unrecognized.
        """
        self._placeholders: dict[DetectionCategory | str, str] = (
            dict(placeholders)
            if placeholders is not None
            else dict(DEFAULT_PLACEHOLDERS)
        )
        self._default_placeholder: str = default_placeholder

    def get_placeholder(self, category: DetectionCategory | str) -> str:
        """Return the safe semantic placeholder for a given finding category.

        Args:
            category: DetectionCategory enum or string representation.

        Returns:
            Safe placeholder string (e.g. '[REDACTED_SECRET]').
        """
        # 1. Direct lookup
        if category in self._placeholders:
            return self._placeholders[category]

        # 2. Enum conversion lookup
        if isinstance(category, str):
            try:
                enum_cat = DetectionCategory(category)
                if enum_cat in self._placeholders:
                    return self._placeholders[enum_cat]
            except ValueError:
                pass
        elif isinstance(category, DetectionCategory):
            str_cat = category.value
            if str_cat in self._placeholders:
                return self._placeholders[str_cat]

        return self._default_placeholder

    def redact(
        self,
        content: str,
        detections: Sequence[DetectionResult],
        decision: PolicyDecision,
    ) -> RedactionResult:
        """Transform content by redacting sensitive spans when policy mandates REDACT.

        Args:
            content: Original text content to inspect and transform.
            detections: Sequence of DetectionResult findings produced by detectors.
            decision: PolicyDecision produced by the PolicyEngine.

        Returns:
            A RedactionResult containing transformed content and safe audit metadata.

        Raises:
            ValidationError: If parameters are invalid or detection spans are
                out-of-bounds, inverted, or malformed.
        """
        # 1. Input type validation
        if not isinstance(content, str):
            raise ValidationError(
                f"content must be a string, got {type(content).__name__}"
            )
        if not isinstance(decision, PolicyDecision):
            raise ValidationError(
                f"decision must be a PolicyDecision, got {type(decision).__name__}"
            )
        if not isinstance(detections, Sequence):
            raise ValidationError("detections must be a sequence of DetectionResult")

        # 2. Policy-Controlled Enforcement:
        # Transformation MUST NOT occur unless the policy explicitly demands REDACT.
        # ALLOW, WARN, and BLOCK all leave the content unmodified in Step 7.
        if decision.action != PolicyAction.REDACT:
            return RedactionResult(
                content=content,
                changed=False,
                redaction_count=0,
                redacted_detection_ids=(),
                categories=(),
            )

        # 3. Handle trivial cases (empty content or no detections)
        if not content:
            return RedactionResult(
                content="",
                changed=False,
                redaction_count=0,
                redacted_detection_ids=(),
                categories=(),
            )

        if not detections:
            return RedactionResult(
                content=content,
                changed=False,
                redaction_count=0,
                redacted_detection_ids=(),
                categories=(),
            )

        # 4. Resolve candidate detections
        # If the policy decision specifies evaluated detections, filter to those
        # that contributed to or match the decision to avoid redacting
        # unrelated findings.
        candidate_detections = self._resolve_target_detections(detections, decision)
        if not candidate_detections:
            return RedactionResult(
                content=content,
                changed=False,
                redaction_count=0,
                redacted_detection_ids=(),
                categories=(),
            )

        # 5. Span validation & empty span filtering
        # Empty spans (char_start == char_end) contain zero characters and are skipped.
        valid_detections: list[DetectionResult] = []
        for det in candidate_detections:
            self._validate_span(det, len(content))
            loc = det.location
            # Note: _validate_span guarantees char_start and char_end are not None
            assert loc.char_start is not None
            assert loc.char_end is not None
            if loc.char_start < loc.char_end:
                valid_detections.append(det)

        if not valid_detections:
            return RedactionResult(
                content=content,
                changed=False,
                redaction_count=0,
                redacted_detection_ids=(),
                categories=(),
            )

        # 6. Sort candidate detections deterministically
        # Independent of input order:
        # - Primary: char_start ascending
        # - Secondary: char_end descending (longer span first)
        # - Tertiary: detection_id ascending
        valid_detections.sort(
            key=lambda d: (
                d.location.char_start or 0,
                -(d.location.char_end or 0),
                d.detection_id,
            )
        )

        # 7. Cluster overlapping and nested spans
        clusters = self._cluster_overlapping_spans(valid_detections)

        # 8. Apply replacements from RIGHT TO LEFT (char_start descending)
        # Replacing right-to-left guarantees that earlier character offsets remain
        # exactly valid without requiring offset adjustment calculations.
        clusters.sort(key=lambda c: c.start, reverse=True)

        transformed = content
        for cluster in clusters:
            transformed = (
                transformed[: cluster.start]
                + cluster.placeholder
                + transformed[cluster.end :]
            )

        # 9. Aggregate audit-safe result summaries
        all_affected_ids = sorted(
            {det_id for cluster in clusters for det_id in cluster.detection_ids}
        )
        all_categories = sorted({cluster.category for cluster in clusters})

        return RedactionResult(
            content=transformed,
            changed=len(clusters) > 0,
            redaction_count=len(clusters),
            redacted_detection_ids=tuple(all_affected_ids),
            categories=tuple(all_categories),
        )

    def transform(
        self,
        content: str,
        detections: Sequence[DetectionResult] | list[DetectionResult],
    ) -> str:
        """Direct transformation fulfilling the ContentTransformer protocol.

        Args:
            content: Text to redact.
            detections: List or sequence of findings to mask.

        Returns:
            Transformed text string.
        """
        synthetic_decision = PolicyDecision(
            action=PolicyAction.REDACT,
            reason="Direct transformation via ContentTransformer protocol.",
            matched_rules=[],
            detections=list(detections),
        )
        return self.redact(
            content=content,
            detections=detections,
            decision=synthetic_decision,
        ).content

    @staticmethod
    def _resolve_target_detections(
        detections: Sequence[DetectionResult],
        decision: PolicyDecision,
    ) -> list[DetectionResult]:
        """Identify which detections are targeted for redaction by the decision."""
        if decision.detections:
            decision_ids = {d.detection_id for d in decision.detections}
            matched = [d for d in detections if d.detection_id in decision_ids]
            if matched:
                return matched
            # Fallback if caller passed decision.detections directly or with
            # differing objects
            return list(decision.detections)
        return list(detections)

    @staticmethod
    def _validate_span(detection: DetectionResult, content_len: int) -> None:
        """Validate detection location coordinates strictly without revealing content.

        Raises:
            ValidationError: With a privacy-safe diagnostic message on invalid
                coordinates.
        """
        loc = detection.location
        det_id = detection.detection_id

        if loc.char_start is None or loc.char_end is None:
            raise ValidationError(
                f"Missing character offsets for detection '{det_id}'."
            )

        if loc.char_start < 0:
            msg = (
                f"Invalid negative char_start ({loc.char_start}) for "
                f"detection '{det_id}'."
            )
            raise ValidationError(msg)

        if loc.char_end < 0:
            raise ValidationError(
                f"Invalid negative char_end ({loc.char_end}) for detection '{det_id}'."
            )

        if loc.char_start > loc.char_end:
            raise ValidationError(
                f"Invalid inverted offsets: char_start ({loc.char_start}) > "
                f"char_end ({loc.char_end}) for detection '{det_id}'."
            )

        if loc.char_end > content_len:
            raise ValidationError(
                f"Character offset end ({loc.char_end}) exceeds content length "
                f"({content_len}) for detection '{det_id}'."
            )

    def _cluster_overlapping_spans(
        self, sorted_detections: list[DetectionResult]
    ) -> list[_OverlapCluster]:
        """Group overlapping and nested spans into unified maximal replacement spans.

        Overlapping definition:
            Span B overlaps Span A if: B.char_start < A.char_end.
            Adjacent spans (B.char_start == A.char_end) do NOT overlap.
        """
        if not sorted_detections:
            return []

        clusters: list[list[DetectionResult]] = []
        current_cluster: list[DetectionResult] = [sorted_detections[0]]
        current_max_end = sorted_detections[0].location.char_end or 0

        for det in sorted_detections[1:]:
            start = det.location.char_start or 0
            end = det.location.char_end or 0

            # If finding begins before the previous cluster finishes, it overlaps
            if start < current_max_end:
                current_cluster.append(det)
                if end > current_max_end:
                    current_max_end = end
            else:
                clusters.append(current_cluster)
                current_cluster = [det]
                current_max_end = end

        if current_cluster:
            clusters.append(current_cluster)

        # Convert each cluster of findings into an _OverlapCluster
        resolved_clusters: list[_OverlapCluster] = []
        for cluster in clusters:
            merged_start = min(d.location.char_start or 0 for d in cluster)
            merged_end = max(d.location.char_end or 0 for d in cluster)

            # Deterministically select the winning detection to determine
            # placeholder & category
            winner = self._select_winning_detection(cluster)
            placeholder = self.get_placeholder(winner.category)
            category_str = (
                winner.category.value
                if isinstance(winner.category, DetectionCategory)
                else str(winner.category)
            )
            det_ids = tuple(sorted(d.detection_id for d in cluster))

            resolved_clusters.append(
                _OverlapCluster(
                    start=merged_start,
                    end=merged_end,
                    placeholder=placeholder,
                    category=category_str,
                    detection_ids=det_ids,
                )
            )

        return resolved_clusters

    @staticmethod
    def _select_winning_detection(
        cluster: list[DetectionResult],
    ) -> DetectionResult:
        """Select the highest-priority detection in an overlapping cluster.

        Deterministic 4-tier comparison:
        1. Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO
        2. Confidence: descending float
        3. Span length: (char_end - char_start) descending
        4. Detection ID: lexicographical ascending
        """

        def sort_key(d: DetectionResult) -> tuple[int, float, int, str]:
            sev = (
                d.severity if isinstance(d.severity, Severity) else Severity(d.severity)
            )
            sev_rank = SEVERITY_ORDER.get(sev, 0)
            conf = d.confidence
            start = d.location.char_start or 0
            end = d.location.char_end or 0
            span_len = end - start
            # For ascending ID tie-break with negative ranks, ID is positive
            return (-sev_rank, -conf, -span_len, d.detection_id)

        sorted_candidates = sorted(cluster, key=sort_key)
        return sorted_candidates[0]
