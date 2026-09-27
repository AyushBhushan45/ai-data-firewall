"""Security pipeline orchestrating detection, policy evaluation, and redaction.

Strict Architectural Separation:
    PROVIDER SCHEMA ≠ NORMALIZED MODEL ≠ DETECTION ≠ POLICY ≠ TRANSFORMATION

The pipeline coordinates:
1. ProviderAdapter / ProviderRegistry (converts provider payloads <-> normalized models)
2. PayloadExtractor (generic text extraction fallback for unadapted payloads)
3. DetectorRegistry (runs SecretDetector and future detectors on normalized text)
4. PolicyEngine (evaluates rules to determine ALLOW / WARN / REDACT / BLOCK)
5. RedactionEngine (executes masking only when policy requires REDACT)
"""

import json
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from aifirewall.core.types import ContentDirection, ContentSource, PolicyAction
from aifirewall.detectors.base import Detector, DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision
from aifirewall.models.request import NormalizedMessage
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyContext
from aifirewall.providers.base import ProviderAdapter
from aifirewall.providers.registry import ProviderRegistry, create_default_registry
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

    def detect(self, content: str, context: DetectorContext) -> list[DetectionResult]:
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
        provider_registry: ProviderRegistry | None = None,
    ) -> None:
        """Initialize the security pipeline with its cooperating sub-engines.

        Args:
            config: Validated ProxyConfig.
            policy_engine: PolicyEngine instance (defaults to empty/allow).
            detector_registry: DetectorRegistry (defaults to [SecretDetector()]).
            redaction_engine: RedactionEngine instance (defaults to standard).
            provider_registry: ProviderRegistry instance (defaults to default registry).
        """
        self._config = config
        self._detectors = (
            detector_registry if detector_registry is not None else DetectorRegistry()
        )
        self._policy = (
            policy_engine if policy_engine is not None else PolicyEngine(PolicyConfig())
        )
        self._redactor = (
            redaction_engine if redaction_engine is not None else RedactionEngine()
        )
        self._providers = (
            provider_registry
            if provider_registry is not None
            else create_default_registry()
        )
        self._configured_adapter: ProviderAdapter | None = (
            self._providers.get_or_raise(self._config.provider)
            if self._config.provider
            else None
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

    @property
    def provider_registry(self) -> ProviderRegistry:
        """Return the provider adapter registry."""
        return self._providers

    @property
    def configured_provider(self) -> str | None:
        """Return the configured provider identifier, if set."""
        return self._config.provider

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

        # 3. Check for JSON and Provider Adapter routing
        raw_json = self._try_parse_json(raw_body, content_type_header)
        adapter = self._resolve_request_adapter(raw_json)

        if adapter is not None and raw_json is not None:
            return self._process_provider_request(
                adapter=adapter,
                raw_body=raw_body,
                raw_json=raw_json,
                request_id=request_id,
            )

        # 4. Fallback: Generic Extraction Pipeline (for plain-text or unadapted JSON)
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

        return self._evaluate_and_transform_generic(
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

        # 3. Check for JSON and Provider Adapter routing
        raw_json = self._try_parse_json(raw_body, content_type_header)
        adapter = self._resolve_response_adapter(raw_json)

        if adapter is not None and raw_json is not None:
            return self._process_provider_response(
                adapter=adapter,
                raw_body=raw_body,
                raw_json=raw_json,
                request_id=request_id,
            )

        # 4. Fallback: Generic Extraction Pipeline
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

        return self._evaluate_and_transform_generic(
            extraction=extraction,
            direction=ContentDirection.RESPONSE,
            source=ContentSource.ASSISTANT,
            request_id=request_id,
        )

    def _resolve_request_adapter(
        self, raw_json: dict[str, Any] | None
    ) -> ProviderAdapter | None:
        """Resolve adapter from explicit proxy config or safe auto-detection."""
        if self._configured_adapter is not None:
            return self._configured_adapter
        if raw_json is not None and isinstance(raw_json, dict):
            return self._providers.auto_detect(raw_json)
        return None

    def _resolve_response_adapter(
        self, raw_json: dict[str, Any] | None
    ) -> ProviderAdapter | None:
        """Resolve adapter for response from config or response payload structure."""
        if self._configured_adapter is not None:
            return self._configured_adapter
        if raw_json is not None and isinstance(raw_json, dict):
            # Detect response signature
            if "choices" in raw_json:
                return self._providers.get("openai")
            if "candidates" in raw_json:
                return self._providers.get("gemini")
            if "content" in raw_json and (
                "stop_reason" in raw_json or raw_json.get("type") == "message"
            ):
                return self._providers.get("anthropic")
            if "done" in raw_json and ("message" in raw_json or "response" in raw_json):
                return self._providers.get("ollama")
        return None

    def _process_provider_request(
        self,
        adapter: ProviderAdapter,
        raw_body: bytes,
        raw_json: dict[str, Any],
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Inspect and transform request using provider adapter."""
        # 1. Normalize provider request
        normalized_request = adapter.normalize_request(raw_json, request_id=request_id)

        # 2. Inspect each message independently with stable coordinates
        all_detections: list[DetectionResult] = []
        msg_findings: dict[int, list[DetectionResult]] = {}

        for idx, msg in enumerate(normalized_request.messages):
            if not msg.content:
                continue
            loc = ContentLocation(
                source=msg.source,
                message_index=idx,
                char_start=0,
                char_end=len(msg.content),
                field_path=f"messages[{idx}].content",
            )
            ctx = DetectorContext(
                request_id=request_id,
                direction=ContentDirection.REQUEST,
                source=msg.source,
                model=normalized_request.model,
                provider=adapter.provider_name,
                location=loc,
            )
            findings = self._detectors.detect(msg.content, ctx)
            if findings:
                msg_findings[idx] = findings
                all_detections.extend(findings)

        # 3. Evaluate policy
        policy_ctx = PolicyContext(
            direction=ContentDirection.REQUEST,
            source=ContentSource.USER,
            model=normalized_request.model,
            provider=adapter.provider_name,
        )
        decision = self._policy.evaluate(all_detections, policy_ctx, normalized_request)

        # 4. Enforce action
        if decision.action == PolicyAction.BLOCK:
            raise BlockedRequestError(decision.reason)

        transformed = False
        final_body = raw_body

        if decision.action == PolicyAction.REDACT and msg_findings:
            new_messages: list[NormalizedMessage] = []
            for idx, msg in enumerate(normalized_request.messages):
                if idx in msg_findings:
                    red_res = self._redactor.redact(
                        msg.content, msg_findings[idx], decision
                    )
                    if red_res.changed:
                        new_messages.append(replace(msg, content=red_res.content))
                        transformed = True
                    else:
                        new_messages.append(msg)
                else:
                    new_messages.append(msg)

            if transformed:
                transformed_request = replace(normalized_request, messages=new_messages)
                transformed_payload = adapter.denormalize_request(
                    transformed_request, original_request=raw_json
                )
                final_body = json.dumps(transformed_payload, ensure_ascii=False).encode(
                    "utf-8"
                )

        result = PipelineResult(
            request_id=request_id,
            direction=ContentDirection.REQUEST,
            action=decision.action,
            decision=decision,
            detection_count=len(all_detections),
            transformed=transformed,
            metadata={"provider": adapter.provider_name},
        )
        return final_body, result

    def _process_provider_response(
        self,
        adapter: ProviderAdapter,
        raw_body: bytes,
        raw_json: dict[str, Any],
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Inspect and transform response using provider adapter."""
        # 1. Normalize provider response
        normalized_response = adapter.normalize_response(
            raw_json, request_id=request_id
        )

        # 2. Inspect normalized response content
        all_detections: list[DetectionResult] = []
        if normalized_response.content:
            loc = ContentLocation(
                source=ContentSource.ASSISTANT,
                char_start=0,
                char_end=len(normalized_response.content),
                field_path="content",
            )
            ctx = DetectorContext(
                request_id=request_id,
                direction=ContentDirection.RESPONSE,
                source=ContentSource.ASSISTANT,
                model=normalized_response.model,
                provider=adapter.provider_name,
                location=loc,
            )
            all_detections = self._detectors.detect(normalized_response.content, ctx)

        # 3. Evaluate policy
        policy_ctx = PolicyContext(
            direction=ContentDirection.RESPONSE,
            source=ContentSource.ASSISTANT,
            model=normalized_response.model,
            provider=adapter.provider_name,
        )
        decision = self._policy.evaluate(all_detections, policy_ctx)

        # 4. Enforce action
        if decision.action == PolicyAction.BLOCK:
            raise BlockedResponseError(decision.reason)

        transformed = False
        final_body = raw_body

        if decision.action == PolicyAction.REDACT and all_detections:
            red_res = self._redactor.redact(
                normalized_response.content, all_detections, decision
            )
            if red_res.changed:
                transformed = True
                transformed_response = replace(
                    normalized_response, content=red_res.content
                )
                transformed_payload = adapter.denormalize_response(
                    transformed_response, original_response=raw_json
                )
                final_body = json.dumps(transformed_payload, ensure_ascii=False).encode(
                    "utf-8"
                )

        result = PipelineResult(
            request_id=request_id,
            direction=ContentDirection.RESPONSE,
            action=decision.action,
            decision=decision,
            detection_count=len(all_detections),
            transformed=transformed,
            metadata={"provider": adapter.provider_name},
        )
        return final_body, result

    def _evaluate_and_transform_generic(
        self,
        extraction: ExtractionResult,
        direction: ContentDirection,
        source: ContentSource,
        request_id: str,
    ) -> tuple[bytes, PipelineResult]:
        """Fallback evaluation using generic PayloadExtractor (Step 8 behavior)."""
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
                final_body = PayloadExtractor.reconstruct(extraction, replacements)

        result = PipelineResult(
            request_id=request_id,
            direction=direction,
            action=decision.action,
            decision=decision,
            detection_count=len(all_detections),
            transformed=transformed,
        )
        return final_body, result

    @staticmethod
    def _try_parse_json(
        raw_body: bytes, content_type_header: str | None
    ) -> dict[str, Any] | None:
        """Attempt to parse bytes as JSON dictionary if content type matches."""
        if not raw_body:
            return None
        content_type = PayloadExtractor._normalize_content_type(content_type_header)
        if not PayloadExtractor._is_json_content_type(content_type):
            return None
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
