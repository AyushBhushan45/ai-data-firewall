"""Policy rule, configuration, and context models for AI Data Firewall.

Defines the declarative domain models used by the Policy Engine to match
findings produced by detectors and evaluate deterministic actions.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from aifirewall.core.errors import ConfigurationError, ValidationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)

# Centralized, testable severity ranking: INFO < LOW < MEDIUM < HIGH < CRITICAL
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Centralized action precedence for conflict resolution: ALLOW < WARN < REDACT < BLOCK
ACTION_PRECEDENCE: dict[PolicyAction, int] = {
    PolicyAction.ALLOW: 0,
    PolicyAction.WARN: 1,
    PolicyAction.REDACT: 2,
    PolicyAction.BLOCK: 3,
}


def severity_at_least(
    finding_severity: Severity | str, minimum_severity: Severity | str
) -> bool:
    """Check if finding_severity meets or exceeds minimum_severity."""
    try:
        f_sev = (
            finding_severity
            if isinstance(finding_severity, Severity)
            else Severity(finding_severity)
        )
    except ValueError as err:
        raise ValidationError(f"Invalid finding severity: {finding_severity}") from err

    try:
        m_sev = (
            minimum_severity
            if isinstance(minimum_severity, Severity)
            else Severity(minimum_severity)
        )
    except ValueError as err:
        raise ValidationError(f"Invalid minimum severity: {minimum_severity}") from err

    return SEVERITY_ORDER[f_sev] >= SEVERITY_ORDER[m_sev]


@dataclass(frozen=True)
class PolicyRule:
    """Declarative rule specifying conditions under which an action is triggered.

    Design Rule: A rule matches a DetectionResult only if ALL specified
    conditions are satisfied (strict AND semantics).

    Attributes:
        rule_id: Unique, non-empty identifier for the rule.
        action: Prescribed PolicyAction upon match (ALLOW, WARN, REDACT, BLOCK).
        description: Safe human-readable description of the rule intent.
        category: Optional DetectionCategory filter.
        minimum_severity: Optional minimum Severity threshold (inclusive).
        minimum_confidence: Optional minimum confidence float [0.0, 1.0] (inclusive).
        detector_name: Optional detector name filter.
        source: Optional ContentSource filter.
        direction: Optional ContentDirection filter.
        enabled: Whether this rule is evaluated (default: True).
        priority: Precedence rank (higher number = higher priority, default: 100).
    """

    rule_id: str
    action: PolicyAction
    description: str = ""
    category: DetectionCategory | str | None = None
    minimum_severity: Severity | str | None = None
    minimum_confidence: float | None = None
    detector_name: str | None = None
    source: ContentSource | str | None = None
    direction: ContentDirection | str | None = None
    enabled: bool = True
    priority: int = 100

    def __post_init__(self) -> None:
        """Validate rule invariants and normalize types."""
        # 1. Validate rule_id
        if (
            not self.rule_id
            or not isinstance(self.rule_id, str)
            or not self.rule_id.strip()
        ):
            raise ValidationError("rule_id must be a non-empty string")

        # 2. Validate and normalize action
        if not isinstance(self.action, PolicyAction):
            try:
                object.__setattr__(self, "action", PolicyAction(self.action))
            except (ValueError, TypeError) as err:
                raise ValidationError(f"Invalid policy action: {self.action}") from err

        # 3. Validate and normalize priority
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise ValidationError(
                f"priority must be an integer, got {type(self.priority).__name__}"
            )
        if self.priority < 0:
            raise ValidationError(
                f"priority must be a non-negative integer, got {self.priority}"
            )

        # 4. Validate confidence threshold
        if self.minimum_confidence is not None:
            if not isinstance(self.minimum_confidence, (int, float)) or isinstance(
                self.minimum_confidence, bool
            ):
                cls_name = type(self.minimum_confidence).__name__
                raise ValidationError(
                    f"minimum_confidence must be a float, got {cls_name}"
                )
            if not (0.0 <= float(self.minimum_confidence) <= 1.0):
                msg = (
                    "minimum_confidence must be between 0.0 and 1.0, "
                    f"got {self.minimum_confidence}"
                )
                raise ValidationError(msg)
            object.__setattr__(
                self, "minimum_confidence", float(self.minimum_confidence)
            )

        # 5. Validate and normalize category
        if self.category is not None and not isinstance(
            self.category, DetectionCategory
        ):
            try:
                object.__setattr__(
                    self, "category", DetectionCategory(self.category)
                )
            except (ValueError, TypeError) as err:
                raise ValidationError(
                    f"Invalid detection category: {self.category}"
                ) from err

        # 6. Validate and normalize minimum_severity
        if self.minimum_severity is not None and not isinstance(
            self.minimum_severity, Severity
        ):
            try:
                object.__setattr__(
                    self, "minimum_severity", Severity(self.minimum_severity)
                )
            except (ValueError, TypeError) as err:
                raise ValidationError(
                    f"Invalid minimum severity: {self.minimum_severity}"
                ) from err

        # 7. Validate and normalize source
        if self.source is not None and not isinstance(self.source, ContentSource):
            try:
                object.__setattr__(self, "source", ContentSource(self.source))
            except (ValueError, TypeError) as err:
                raise ValidationError(f"Invalid content source: {self.source}") from err

        # 8. Validate and normalize direction
        if self.direction is not None and not isinstance(
            self.direction, ContentDirection
        ):
            try:
                object.__setattr__(
                    self, "direction", ContentDirection(self.direction)
                )
            except (ValueError, TypeError) as err:
                raise ValidationError(
                    f"Invalid content direction: {self.direction}"
                ) from err


@dataclass(frozen=True)
class PolicyConfig:
    """Aggregated policy configuration holding active rules and defaults.

    Attributes:
        rules: Sequence of PolicyRule objects.
        default_action: PolicyAction applied when no rules match (default: ALLOW).
    """

    rules: Sequence[PolicyRule] = field(default_factory=list)
    default_action: PolicyAction = PolicyAction.ALLOW

    def __post_init__(self) -> None:
        """Validate configuration integrity and rule uniqueness."""
        if not isinstance(self.default_action, PolicyAction):
            try:
                object.__setattr__(
                    self, "default_action", PolicyAction(self.default_action)
                )
            except (ValueError, TypeError) as err:
                raise ConfigurationError(
                    f"Invalid default action: {self.default_action}"
                ) from err

        # Ensure all items in rules are PolicyRule instances
        seen_ids: set[str] = set()
        for idx, rule in enumerate(self.rules):
            if not isinstance(rule, PolicyRule):
                cls_name = type(rule).__name__
                raise ConfigurationError(
                    f"Rule at index {idx} is not a PolicyRule instance: {cls_name}"
                )
            if rule.rule_id in seen_ids:
                raise ConfigurationError(
                    f"Duplicate rule_id found in policy config: {rule.rule_id!r}"
                )
            seen_ids.add(rule.rule_id)

        # Freeze rules as tuple
        object.__setattr__(self, "rules", tuple(self.rules))


@dataclass(frozen=True)
class PolicyContext:
    """Non-sensitive contextual metadata provided to the PolicyEngine.

    Security Rule: Never place raw prompt strings, model completions,
    credentials, or HTTP request objects in PolicyContext.
    """

    direction: ContentDirection | str | None = None
    source: ContentSource | str | None = None
    model: str | None = None
    provider: str | None = None

    def __post_init__(self) -> None:
        """Normalize enums and validate parameters."""
        if self.direction is not None and not isinstance(
            self.direction, ContentDirection
        ):
            try:
                object.__setattr__(
                    self, "direction", ContentDirection(self.direction)
                )
            except (ValueError, TypeError) as err:
                raise ValidationError(
                    f"Invalid context direction: {self.direction}"
                ) from err

        if self.source is not None and not isinstance(self.source, ContentSource):
            try:
                object.__setattr__(self, "source", ContentSource(self.source))
            except (ValueError, TypeError) as err:
                raise ValidationError(
                    f"Invalid context source: {self.source}"
                ) from err
