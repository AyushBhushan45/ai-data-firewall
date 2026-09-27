"""Stateless, deterministic Policy Engine for AI Data Firewall.

Evaluates normalized detection findings against declarative PolicyRules to
produce explainable, privacy-preserving PolicyDecisions (ALLOW, WARN, REDACT, BLOCK).
"""

from collections.abc import Sequence

from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision
from aifirewall.models.request import NormalizedAIRequest
from aifirewall.policy.models import (
    ACTION_PRECEDENCE,
    PolicyConfig,
    PolicyContext,
    PolicyRule,
    severity_at_least,
)


class PolicyEngine:
    """Evaluates detector findings against security policies.

    The Policy Engine operates strictly on normalized findings (DetectionResult[]).
    It never inspects raw prompts or completions directly (DETECTION ≠ POLICY).

    Evaluation is completely deterministic:
    - Conditions within a rule are evaluated with strict AND semantics.
    - Multiple matches are resolved by rule priority (higher numeric value wins).
    - Equal-priority conflicts are resolved by action precedence:
      BLOCK > REDACT > WARN > ALLOW, with deterministic tie-breaking on rule_id.
    - Evaluates multiple detections independently and selects the overall highest
      priority outcome.
    - Defaults to ALLOW if no rules match or no detections are present.
    """

    def __init__(
        self,
        rules: Sequence[PolicyRule] | PolicyConfig | None = None,
        default_action: PolicyAction = PolicyAction.ALLOW,
    ) -> None:
        """Initialize the PolicyEngine with rules or a PolicyConfig.

        Args:
            rules: Sequence of PolicyRule objects or an existing PolicyConfig.
            default_action: Action to return when no rules match (default: ALLOW).
        """
        if isinstance(rules, PolicyConfig):
            self._config = rules
        elif rules is not None:
            self._config = PolicyConfig(
                rules=list(rules), default_action=default_action
            )
        else:
            self._config = PolicyConfig(rules=[], default_action=default_action)

    @property
    def config(self) -> PolicyConfig:
        """Return the immutable policy configuration."""
        return self._config

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        """Return the tuple of configured policy rules."""
        return tuple(self._config.rules)

    @property
    def default_action(self) -> PolicyAction:
        """Return the default action applied when no rules match."""
        return self._config.default_action

    def evaluate(
        self,
        detections: Sequence[DetectionResult],
        context: PolicyContext | None = None,
        request: NormalizedAIRequest | None = None,
    ) -> PolicyDecision:
        """Evaluate findings against configured policy rules.

        Args:
            detections: Sequence of DetectionResult objects produced by detectors.
            context: Optional non-sensitive contextual metadata.
            request: Optional NormalizedAIRequest (unused in evaluation, preserves
                     protocol compatibility).

        Returns:
            A deterministic PolicyDecision with action, safe reason, matched rules,
            and evaluated detections.
        """
        # 1. Handle empty findings list
        if not detections:
            return PolicyDecision(
                action=self.default_action,
                reason="No detections to evaluate.",
                matched_rules=[],
                detections=[],
            )

        # 2. Collect all matching (rule, detection) pairs
        matches: list[tuple[PolicyRule, DetectionResult]] = []
        for detection in detections:
            for rule in self._config.rules:
                if not rule.enabled:
                    continue
                if self._rule_matches(rule, detection, context):
                    matches.append((rule, detection))

        # 3. Handle case where no rules matched any detection
        if not matches:
            return PolicyDecision(
                action=self.default_action,
                reason="No policy rules matched.",
                matched_rules=[],
                detections=list(detections),
            )

        # 4. Deterministic conflict resolution across all matches:
        # Sort key:
        # - Primary: rule.priority (descending, higher numeric priority wins)
        # - Secondary: ACTION_PRECEDENCE[rule.action] (descending:
        #   BLOCK > REDACT > WARN > ALLOW)
        # - Tertiary: rule.rule_id (ascending lexicographical order)
        # - Quaternary: detection.detection_id (ascending lexicographical order)
        matches.sort(
            key=lambda item: (
                -item[0].priority,
                -ACTION_PRECEDENCE[item[0].action],
                item[0].rule_id,
                item[1].detection_id,
            )
        )

        winning_rule, winning_detection = matches[0]

        # 5. Extract unique matched rule IDs in priority-resolved order
        seen_rules: set[str] = set()
        ordered_matched_rules: list[str] = []
        for r, _ in matches:
            if r.rule_id not in seen_rules:
                seen_rules.add(r.rule_id)
                ordered_matched_rules.append(r.rule_id)

        # 6. Generate a privacy-safe, non-sensitive explanation
        safe_reason = self._format_decision_reason(winning_rule, winning_detection)

        return PolicyDecision(
            action=winning_rule.action,
            reason=safe_reason,
            matched_rules=ordered_matched_rules,
            detections=list(detections),
        )

    def _rule_matches(
        self,
        rule: PolicyRule,
        detection: DetectionResult,
        context: PolicyContext | None,
    ) -> bool:
        """Check if a rule satisfies all conditions for a given finding (strict AND)."""
        # Category condition
        if rule.category is not None:
            det_category = (
                detection.category
                if isinstance(detection.category, DetectionCategory)
                else DetectionCategory(detection.category)
            )
            if det_category != rule.category:
                return False

        # Minimum severity condition
        if rule.minimum_severity is not None:
            if not severity_at_least(detection.severity, rule.minimum_severity):
                return False

        # Minimum confidence condition (inclusive)
        if rule.minimum_confidence is not None:
            if detection.confidence < rule.minimum_confidence:
                return False

        # Detector name condition
        if rule.detector_name is not None:
            if detection.detector_name != rule.detector_name:
                return False

        # Content source condition
        if rule.source is not None:
            # Source can be specified on the finding's location or context
            effective_source = detection.location.source
            if effective_source == ContentSource.UNKNOWN and context and context.source:
                effective_source = (
                    context.source
                    if isinstance(context.source, ContentSource)
                    else ContentSource(context.source)
                )
            if effective_source != rule.source:
                return False

        # Content direction condition
        if rule.direction is not None:
            effective_direction: ContentDirection | None = None
            if context and context.direction is not None:
                effective_direction = (
                    context.direction
                    if isinstance(context.direction, ContentDirection)
                    else ContentDirection(context.direction)
                )
            elif "direction" in detection.metadata:
                raw_dir = detection.metadata["direction"]
                effective_direction = (
                    raw_dir
                    if isinstance(raw_dir, ContentDirection)
                    else ContentDirection(raw_dir)
                )

            if effective_direction != rule.direction:
                return False

        return True

    @staticmethod
    def _format_decision_reason(rule: PolicyRule, detection: DetectionResult) -> str:
        """Generate a privacy-safe diagnostic explanation for the policy decision.

        Security Rule: Never include raw secrets, unredacted prompts, or sensitive
        tokens in policy reasons.
        """
        action_verbs = {
            PolicyAction.BLOCK: "Blocked",
            PolicyAction.REDACT: "Redaction required",
            PolicyAction.WARN: "Warning issued",
            PolicyAction.ALLOW: "Allowed",
        }
        verb = action_verbs.get(rule.action, "Action applied")
        det_sev = (
            detection.severity.value
            if isinstance(detection.severity, Severity)
            else str(detection.severity)
        )
        det_cat = (
            detection.category.value
            if isinstance(detection.category, DetectionCategory)
            else str(detection.category)
        )

        if rule.description:
            return (
                f"{verb} because {det_sev}-severity {det_cat} "
                f"matched rule '{rule.rule_id}' ({rule.description})."
            )
        return (
            f"{verb} because {det_sev}-severity {det_cat} "
            f"matched rule '{rule.rule_id}'."
        )
