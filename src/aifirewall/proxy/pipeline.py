"""Security pipeline orchestrating detection, policy evaluation, and redaction.

Strict Architectural Separation:
    DETECTION ≠ POLICY ≠ TRANSFORMATION

The pipeline coordinates:
1. PayloadExtractor (generic text extraction)
2. DetectorRegistry (runs SecretDetector and future detectors)
3. PolicyEngine (evaluates rules to determine ALLOW / WARN / REDACT / BLOCK)
4. RedactionEngine (executes masking only when policy requires REDACT)
"""

from collections.abc import Sequence

from aifirewall.core.types import ContentDirection, ContentSource, PolicyAction
from aifirewall.detectors.base import Detector, DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyContext
from aifirewall.proxy.config import ProxyConfig
from aifirewall.proxy.errors import (
    BlockedRequestError,
    BlockedResponseError,
    PayloadTooLargeError,
)
from aifirewall.proxy.extraction import PayloadExtractor
from aifirewall.proxy.models import ExtractionResult, PipelineResult
from aifirewall.transformation.redaction import RedactionEngine


class DetectorRegistry:
    """Registry maintaining an ordered sequence of inspection detectors."""

    def __init__(self, detectors: Sequence[Detector] | None = None) -> None:
        """Initialize registry with given detectors (defaults to [SecretDetector()])."""
        if detectors is not None:
            self._detectors = tuple(detectors)
        else:
            self._detectors = (SecretDetector(),)

    @property
    def detectors(self) -> tuple[Detector, ...]:
        """Return registered detectors."""
        return self._detectors

    def detect(
        self, content: str, context: DetectorContext
    ) -> list[DetectionResult]:
        """Run all registered detectors sequentially and combine findings."""
        findings: list[DetectionResult] = []
        for detector in self._detectors:
            results = detector.detect(content, context)
            findings.extend(results)
        return findings


class SecurityPipeline:
    """Orchestrates security inspection for inbound requests and outbound responses."""

    def __init__(
        self,
        config: ProxyConfig,
        policy_engine: PolicyEngine | None = None,
        detector_registry: DetectorRegistry | None = None,
        redaction_engine: RedactionEngine | None = None,
    ) -> None:
        """Initialize the security pipeline with its cooperating sub-engines.

        Args:
            config: Validated ProxyConfig.
            policy_engine: PolicyEngine instance (defaults to empty/allow).
            detector_registry: DetectorRegistry (defaults to [SecretDetector()]).
            redaction_engine: RedactionEngine instance (defaults to standard).
        """
        self._config = config
        self._detectors = (
            detector_registry
            if detector_registry is not None
            else DetectorRegistry()
        )
        self._policy = (
            policy_engine
            if policy_engine is not None
            else PolicyEngine(PolicyConfig())
        )
        self._redactor = (
            redaction_engine
            if redaction_engine is not None
            else RedactionEngine()
        )

    @property
    def config(self) -> ProxyConfig:
        """Return pipeline proxy configuration."""
        return self._config

    @property
    def policy_engine(self) -> PolicyEngine:
        """Return the underlying PolicyEngine."""
        return self._policy

    @property
    def detector_registry(self) -> DetectorRegistry:
        """Return the detector registry."""
        return self._detectors

    @property
    def redaction_engine(self) -> RedactionEngine:
        """Return the redaction engine."""
        return self._redactor

    def process_request(
        self,
        raw_body: bytes,
        content_type_header: str | None,
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Inspect and enforce policy on an inbound HTTP request body.

        Args:
            raw_body: Raw request body bytes.
            content_type_header: Content-Type header string.
            request_id: Unique request trace identifier.

        Returns:
            Tuple of (sanitized_body_bytes, PipelineResult).

        Raises:
            PayloadTooLargeError: If body exceeds max_request_body_bytes.
            BlockedRequestError: If evaluated policy returns BLOCK.
        """
        # 1. Enforce body size limit
        if len(raw_body) > self._config.max_request_body_bytes:
            raise PayloadTooLargeError(
                "Request body exceeds configured maximum limit of "
                f"{self._config.max_request_body_bytes} bytes."
            )

        # 2. Check if inspection is enabled
        if not self._config.request_inspection_enabled:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Request inspection is disabled by configuration.",
                matched_rules=[],
                detections=[],
            )
            return raw_body, PipelineResult(
                request_id=request_id,
                direction=ContentDirection.REQUEST,
                action=PolicyAction.ALLOW,
                decision=decision,
                detection_count=0,
                transformed=False,
            )

        # 3. Extract inspectable items
        extraction = PayloadExtractor.extract(
            raw_body, content_type_header, ContentDirection.REQUEST
        )
        if not extraction.is_inspectable or not extraction.items:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Payload is non-inspectable or contains no textual items.",
                matched_rules=[],
                detections=[],
            )
            return raw_body, PipelineResult(
                request_id=request_id,
                direction=ContentDirection.REQUEST,
                action=PolicyAction.ALLOW,
                decision=decision,
                detection_count=0,
                transformed=False,
            )

        # 4. Run detectors and evaluate policy
        return self._evaluate_and_transform(
            extraction=extraction,
            direction=ContentDirection.REQUEST,
            source=ContentSource.USER,
            request_id=request_id,
        )

    def process_response(
        self,
        raw_body: bytes,
        content_type_header: str | None,
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Inspect and enforce policy on an outbound HTTP response body.

        Args:
            raw_body: Raw upstream response body bytes.
            content_type_header: Upstream Content-Type header string.
            request_id: Unique request trace identifier.

        Returns:
            Tuple of (sanitized_body_bytes, PipelineResult).

        Raises:
            PayloadTooLargeError: If response exceeds max_response_body_bytes.
            BlockedResponseError: If evaluated policy returns BLOCK.
        """
        # 1. Enforce body size limit
        if len(raw_body) > self._config.max_response_body_bytes:
            raise PayloadTooLargeError(
                "Response body exceeds configured maximum limit of "
                f"{self._config.max_response_body_bytes} bytes."
            )

        # 2. Check if inspection is enabled
        if not self._config.response_inspection_enabled:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Response inspection is disabled by configuration.",
                matched_rules=[],
                detections=[],
            )
            return raw_body, PipelineResult(
                request_id=request_id,
                direction=ContentDirection.RESPONSE,
                action=PolicyAction.ALLOW,
                decision=decision,
                detection_count=0,
                transformed=False,
            )

        # 3. Extract inspectable items
        extraction = PayloadExtractor.extract(
            raw_body, content_type_header, ContentDirection.RESPONSE
        )
        if not extraction.is_inspectable or not extraction.items:
            decision = PolicyDecision(
                action=PolicyAction.ALLOW,
                reason="Response is non-inspectable or contains no textual items.",
                matched_rules=[],
                detections=[],
            )
            return raw_body, PipelineResult(
                request_id=request_id,
                direction=ContentDirection.RESPONSE,
                action=PolicyAction.ALLOW,
                decision=decision,
                detection_count=0,
                transformed=False,
            )

        # 4. Run detectors and evaluate policy
        return self._evaluate_and_transform(
            extraction=extraction,
            direction=ContentDirection.RESPONSE,
            source=ContentSource.ASSISTANT,
            request_id=request_id,
        )

    def _evaluate_and_transform(
        self,
        extraction: ExtractionResult,
        direction: ContentDirection,
        source: ContentSource,
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Run detectors, policy evaluation, and redaction across extracted items."""
        item_findings: dict[str, list[DetectionResult]] = {}
        all_detections: list[DetectionResult] = []

        for item in extraction.items:
            ctx = DetectorContext(
                request_id=request_id,
                direction=direction,
                source=source,
                location=item.location,
            )
            findings = self._detectors.detect(item.text, ctx)
            if findings:
                item_findings[item.item_id] = findings
                all_detections.extend(findings)

        # Evaluate policy
        policy_ctx = PolicyContext(direction=direction, source=source)
        decision = self._policy.evaluate(all_detections, policy_ctx)

        # Enforce action
        if decision.action == PolicyAction.BLOCK:
            if direction == ContentDirection.REQUEST:
                raise BlockedRequestError(decision.reason)
            raise BlockedResponseError(decision.reason)

        transformed = False
        final_body = extraction.raw_bytes

        if decision.action == PolicyAction.REDACT and item_findings:
            replacements: dict[str, str] = {}
            for item in extraction.items:
                if item.item_id in item_findings:
                    red_res = self._redactor.redact(
                        item.text, item_findings[item.item_id], decision
                    )
                    if red_res.changed:
                        replacements[item.item_id] = red_res.content
                        transformed = True

            if transformed:
                final_body = PayloadExtractor.reconstruct(
                    extraction, replacements
                )

        result = PipelineResult(
            request_id=request_id,
            direction=direction,
            action=decision.action,
            decision=decision,
            detection_count=len(all_detections),
            transformed=transformed,
        )
        return final_body, result
