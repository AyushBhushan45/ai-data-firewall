"""Comprehensive test suite for the AI Data Firewall Policy Engine.

Covers:
- Basic engine lifecycle and defaults (ALLOW on empty/no match)
- Severity threshold matching (INFO < LOW < MEDIUM < HIGH < CRITICAL)
- Confidence threshold matching ([0.0, 1.0] inclusive boundary)
- Category matching (SECRET vs PII vs PROMPT_INJECTION)
- Detector-specific and global rule matching
- Source and direction filtering
- All policy actions (ALLOW, WARN, REDACT, BLOCK)
- Multiple detections and independent evaluation
- Priority resolution and deterministic conflict resolution
- Privacy and non-exposure of raw secrets in reasons/repr/str
- Determinism and idempotency
- Rule and configuration validation
- Local integration test (SecretDetector -> findings -> engine -> decision)
"""

import pytest

from aifirewall.core.errors import ConfigurationError, ValidationError
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
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import (
    ACTION_PRECEDENCE,
    SEVERITY_ORDER,
    PolicyConfig,
    PolicyContext,
    PolicyRule,
    severity_at_least,
)


def make_detection(
    detection_id: str = "det-1",
    category: DetectionCategory | str = DetectionCategory.SECRET,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.95,
    detector_name: str = "test_detector",
    source: ContentSource = ContentSource.USER,
    char_start: int = 0,
    char_end: int = 20,
    description: str = "Synthetic security finding",
    metadata: dict | None = None,
) -> DetectionResult:
    """Helper to construct synthetic, privacy-safe DetectionResult objects."""
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


# =====================================================================
# 1. BASIC ENGINE
# =====================================================================


def test_1_policy_engine_can_be_instantiated():
    """1. PolicyEngine can be instantiated with or without rules."""
    engine_empty = PolicyEngine()
    assert len(engine_empty.rules) == 0
    assert engine_empty.default_action == PolicyAction.ALLOW

    rule = PolicyRule(rule_id="r1", action=PolicyAction.BLOCK)
    engine_with_rules = PolicyEngine(rules=[rule])
    assert len(engine_with_rules.rules) == 1
    assert engine_with_rules.rules[0].rule_id == "r1"


def test_2_empty_detection_list_returns_allow():
    """2. Empty detection list returns default ALLOW decision."""
    engine = PolicyEngine(
        rules=[PolicyRule(rule_id="r1", action=PolicyAction.BLOCK)]
    )
    decision = engine.evaluate([])
    assert decision.action == PolicyAction.ALLOW
    assert decision.reason == "No detections to evaluate."
    assert decision.matched_rules == []
    assert decision.detections == []


def test_3_no_matching_rule_returns_allow():
    """3. Findings that match no configured rules return default ALLOW."""
    engine = PolicyEngine(
        rules=[
            PolicyRule(
                rule_id="block_critical",
                category=DetectionCategory.SECRET,
                minimum_severity=Severity.CRITICAL,
                action=PolicyAction.BLOCK,
            )
        ]
    )
    det = make_detection(severity=Severity.LOW)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.reason == "No policy rules matched."
    assert decision.matched_rules == []
    assert len(decision.detections) == 1


def test_4_disabled_rules_never_match():
    """4. Disabled rules are ignored during evaluation."""
    engine = PolicyEngine(
        rules=[
            PolicyRule(
                rule_id="disabled_block",
                category=DetectionCategory.SECRET,
                action=PolicyAction.BLOCK,
                enabled=False,
            )
        ]
    )
    det = make_detection(category=DetectionCategory.SECRET)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


# =====================================================================
# 2. SEVERITY ORDERING
# =====================================================================


def test_5_severity_high_minimum_matches_high():
    """5. HIGH minimum matches HIGH finding."""
    rule = PolicyRule(
        rule_id="rule_high",
        minimum_severity=Severity.HIGH,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(severity=Severity.HIGH)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "rule_high" in decision.matched_rules


def test_6_severity_high_minimum_matches_critical():
    """6. HIGH minimum matches CRITICAL finding."""
    rule = PolicyRule(
        rule_id="rule_high",
        minimum_severity=Severity.HIGH,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(severity=Severity.CRITICAL)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "rule_high" in decision.matched_rules


def test_7_severity_high_minimum_does_not_match_medium():
    """7. HIGH minimum does not match MEDIUM finding."""
    rule = PolicyRule(
        rule_id="rule_high",
        minimum_severity=Severity.HIGH,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(severity=Severity.MEDIUM)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


def test_8_severity_critical_minimum_does_not_match_high():
    """8. CRITICAL minimum does not match HIGH finding."""
    rule = PolicyRule(
        rule_id="rule_crit",
        minimum_severity=Severity.CRITICAL,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(severity=Severity.HIGH)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


def test_severity_ordering_helper():
    """Verify SEVERITY_ORDER helper function behavior across all levels."""
    assert severity_at_least(Severity.CRITICAL, Severity.INFO)
    assert severity_at_least(Severity.CRITICAL, Severity.CRITICAL)
    assert not severity_at_least(Severity.INFO, Severity.LOW)
    assert not severity_at_least(Severity.MEDIUM, Severity.HIGH)
    assert SEVERITY_ORDER[Severity.INFO] < SEVERITY_ORDER[Severity.LOW]
    assert SEVERITY_ORDER[Severity.LOW] < SEVERITY_ORDER[Severity.MEDIUM]
    assert SEVERITY_ORDER[Severity.MEDIUM] < SEVERITY_ORDER[Severity.HIGH]
    assert SEVERITY_ORDER[Severity.HIGH] < SEVERITY_ORDER[Severity.CRITICAL]


# =====================================================================
# 3. CONFIDENCE MATCHING
# =====================================================================


def test_9_confidence_threshold_matches_exact():
    """9. 0.90 threshold matches finding with confidence exactly 0.90."""
    rule = PolicyRule(
        rule_id="conf_90",
        minimum_confidence=0.90,
        action=PolicyAction.WARN,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(confidence=0.90)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.WARN
    assert "conf_90" in decision.matched_rules


def test_10_confidence_threshold_rejects_below():
    """10. 0.90 threshold rejects finding with confidence 0.89."""
    rule = PolicyRule(
        rule_id="conf_90",
        minimum_confidence=0.90,
        action=PolicyAction.WARN,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(confidence=0.89)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


def test_11_confidence_threshold_one_matches_exact():
    """11. 1.0 threshold matches finding with confidence exactly 1.0."""
    rule = PolicyRule(
        rule_id="conf_100",
        minimum_confidence=1.0,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(confidence=1.0)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "conf_100" in decision.matched_rules


def test_12_invalid_confidence_configuration_rejected():
    """12. Invalid confidence values outside [0.0, 1.0] are rejected."""
    with pytest.raises(ValidationError, match="between 0.0 and 1.0"):
        PolicyRule(
            rule_id="r_bad",
            action=PolicyAction.WARN,
            minimum_confidence=1.05,
        )

    with pytest.raises(ValidationError, match="between 0.0 and 1.0"):
        PolicyRule(
            rule_id="r_bad",
            action=PolicyAction.WARN,
            minimum_confidence=-0.01,
        )


# =====================================================================
# 4. CATEGORY MATCHING
# =====================================================================


def test_13_secret_rule_matches_secret():
    """13. Rule with category SECRET matches SECRET finding."""
    rule = PolicyRule(
        rule_id="secret_rule",
        category=DetectionCategory.SECRET,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(category=DetectionCategory.SECRET)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "secret_rule" in decision.matched_rules


def test_14_secret_rule_does_not_match_pii():
    """14. Rule with category SECRET does not match PII finding."""
    rule = PolicyRule(
        rule_id="secret_rule",
        category=DetectionCategory.SECRET,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(category=DetectionCategory.PII)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


def test_15_pii_rule_does_not_match_secret():
    """15. Rule with category PII does not match SECRET finding."""
    rule = PolicyRule(
        rule_id="pii_rule",
        category=DetectionCategory.PII,
        action=PolicyAction.REDACT,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(category=DetectionCategory.SECRET)
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


# =====================================================================
# 5. DETECTOR MATCHING
# =====================================================================


def test_16_detector_specific_rule_matches_target():
    """16. Rule targeting 'secret_detector' matches finding from that detector."""
    rule = PolicyRule(
        rule_id="sd_rule",
        detector_name="secret_detector",
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(detector_name="secret_detector")
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "sd_rule" in decision.matched_rules


def test_17_detector_specific_rule_rejects_other_detector():
    """17. Rule targeting 'secret_detector' does not match 'pii_scanner'."""
    rule = PolicyRule(
        rule_id="sd_rule",
        detector_name="secret_detector",
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(detector_name="pii_scanner")
    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules == []


def test_18_rule_without_detector_filter_matches_any_detector():
    """18. Rule without detector_name applies across all detectors."""
    rule = PolicyRule(
        rule_id="universal_rule",
        minimum_severity=Severity.HIGH,
        action=PolicyAction.WARN,
    )
    engine = PolicyEngine(rules=[rule])
    det1 = make_detection(detector_name="detector_a", severity=Severity.HIGH)
    det2 = make_detection(detector_name="detector_b", severity=Severity.HIGH)
    assert engine.evaluate([det1]).action == PolicyAction.WARN
    assert engine.evaluate([det2]).action == PolicyAction.WARN


# =====================================================================
# 6. SOURCE AND DIRECTION
# =====================================================================


def test_19_source_filter_matches_and_rejects():
    """19. Source filter matches specified ContentSource and rejects others."""
    rule = PolicyRule(
        rule_id="user_only",
        source=ContentSource.USER,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])

    det_user = make_detection(source=ContentSource.USER)
    decision_user = engine.evaluate([det_user])
    assert decision_user.action == PolicyAction.BLOCK

    det_system = make_detection(source=ContentSource.SYSTEM)
    decision_system = engine.evaluate([det_system])
    assert decision_system.action == PolicyAction.ALLOW


def test_20_direction_filter_matches_and_rejects():
    """20. Direction filter matches specified ContentDirection."""
    rule = PolicyRule(
        rule_id="request_only",
        direction=ContentDirection.REQUEST,
        action=PolicyAction.BLOCK,
    )
    engine = PolicyEngine(rules=[rule])

    det = make_detection()
    # Matching direction in PolicyContext
    ctx_req = PolicyContext(direction=ContentDirection.REQUEST)
    assert engine.evaluate([det], context=ctx_req).action == PolicyAction.BLOCK

    # Non-matching direction in PolicyContext
    ctx_resp = PolicyContext(direction=ContentDirection.RESPONSE)
    assert engine.evaluate([det], context=ctx_resp).action == PolicyAction.ALLOW

    # Direction specified via finding metadata
    det_meta_req = make_detection(metadata={"direction": ContentDirection.REQUEST})
    assert engine.evaluate([det_meta_req]).action == PolicyAction.BLOCK

    det_meta_resp = make_detection(metadata={"direction": ContentDirection.RESPONSE})
    assert engine.evaluate([det_meta_resp]).action == PolicyAction.ALLOW


def test_21_absent_optional_filters_remain_global():
    """21. When optional filters are omitted, rules apply globally."""
    rule = PolicyRule(rule_id="global_rule", action=PolicyAction.WARN)
    engine = PolicyEngine(rules=[rule])

    for src in [ContentSource.USER, ContentSource.SYSTEM, ContentSource.TOOL_OUTPUT]:
        det = make_detection(source=src)
        assert engine.evaluate([det]).action == PolicyAction.WARN


# =====================================================================
# 7. POLICY ACTIONS
# =====================================================================


def test_22_matching_warn_rule_returns_warn():
    """22. Matching WARN rule returns PolicyAction.WARN."""
    engine = PolicyEngine(
        rules=[PolicyRule(rule_id="warn_r", action=PolicyAction.WARN)]
    )
    decision = engine.evaluate([make_detection()])
    assert decision.action == PolicyAction.WARN
    assert "Warning issued" in decision.reason


def test_23_matching_redact_rule_returns_redact():
    """23. Matching REDACT rule returns PolicyAction.REDACT."""
    engine = PolicyEngine(
        rules=[PolicyRule(rule_id="redact_r", action=PolicyAction.REDACT)]
    )
    decision = engine.evaluate([make_detection()])
    assert decision.action == PolicyAction.REDACT
    assert "Redaction required" in decision.reason


def test_24_matching_block_rule_returns_block():
    """24. Matching BLOCK rule returns PolicyAction.BLOCK."""
    engine = PolicyEngine(
        rules=[PolicyRule(rule_id="block_r", action=PolicyAction.BLOCK)]
    )
    decision = engine.evaluate([make_detection()])
    assert decision.action == PolicyAction.BLOCK
    assert "Blocked" in decision.reason


def test_25_matching_allow_rule_returns_allow():
    """25. Matching explicit ALLOW rule returns PolicyAction.ALLOW."""
    engine = PolicyEngine(
        rules=[PolicyRule(rule_id="allow_r", action=PolicyAction.ALLOW)]
    )
    decision = engine.evaluate([make_detection()])
    assert decision.action == PolicyAction.ALLOW
    assert "allow_r" in decision.matched_rules


# =====================================================================
# 8. MULTIPLE DETECTIONS & CONFLICT RESOLUTION
# =====================================================================


def test_26_multiple_detections_are_evaluated():
    """26. Multiple detections are evaluated independently."""
    rule_crit = PolicyRule(
        rule_id="block_crit",
        minimum_severity=Severity.CRITICAL,
        action=PolicyAction.BLOCK,
        priority=100,
    )
    rule_med = PolicyRule(
        rule_id="warn_med",
        minimum_severity=Severity.MEDIUM,
        action=PolicyAction.WARN,
        priority=50,
    )
    engine = PolicyEngine(rules=[rule_crit, rule_med])

    det_med = make_detection(detection_id="d1", severity=Severity.MEDIUM)
    det_crit = make_detection(detection_id="d2", severity=Severity.CRITICAL)

    decision = engine.evaluate([det_med, det_crit])
    assert decision.action == PolicyAction.BLOCK
    assert "block_crit" in decision.matched_rules
    assert "warn_med" in decision.matched_rules


def test_27_strongest_decision_wins_according_to_priority():
    """27. Higher priority outcome wins across multiple findings."""
    rule_p100 = PolicyRule(
        rule_id="p100_block",
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
        action=PolicyAction.BLOCK,
        priority=100,
    )
    rule_p50 = PolicyRule(
        rule_id="p50_warn",
        category=DetectionCategory.PII,
        action=PolicyAction.WARN,
        priority=50,
    )
    engine = PolicyEngine(rules=[rule_p100, rule_p50])

    det1 = make_detection(detection_id="d1", category=DetectionCategory.PII)
    det2 = make_detection(
        detection_id="d2",
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
    )

    decision = engine.evaluate([det1, det2])
    assert decision.action == PolicyAction.BLOCK
    assert decision.matched_rules[0] == "p100_block"


def test_28_result_does_not_depend_on_detection_input_ordering():
    """28. Evaluation result is invariant under permutation of input findings."""
    rule_block = PolicyRule(
        rule_id="rule_block",
        minimum_severity=Severity.HIGH,
        action=PolicyAction.BLOCK,
        priority=100,
    )
    rule_warn = PolicyRule(
        rule_id="rule_warn",
        minimum_severity=Severity.LOW,
        action=PolicyAction.WARN,
        priority=50,
    )
    engine = PolicyEngine(rules=[rule_block, rule_warn])

    det_a = make_detection(detection_id="d_low", severity=Severity.LOW)
    det_b = make_detection(detection_id="d_high", severity=Severity.HIGH)

    decision_order1 = engine.evaluate([det_a, det_b])
    decision_order2 = engine.evaluate([det_b, det_a])

    assert decision_order1.action == decision_order2.action
    assert decision_order1.matched_rules == decision_order2.matched_rules
    assert decision_order1.reason == decision_order2.reason


# =====================================================================
# 9. PRIORITY AND CONFLICTS
# =====================================================================


def test_29_high_priority_beats_lower_priority_conflicting_rule():
    """29. Higher numeric priority overrides conflicting lower priority rule."""
    rule_override = PolicyRule(
        rule_id="allow_exception",
        category=DetectionCategory.SECRET,
        action=PolicyAction.ALLOW,
        priority=200,  # Explicit higher priority
    )
    rule_block = PolicyRule(
        rule_id="default_block",
        category=DetectionCategory.SECRET,
        action=PolicyAction.BLOCK,
        priority=100,
    )
    engine = PolicyEngine(rules=[rule_override, rule_block])
    det = make_detection(category=DetectionCategory.SECRET)

    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.ALLOW
    assert decision.matched_rules[0] == "allow_exception"


def test_30_equal_priority_conflicts_resolved_by_action_precedence():
    """30. Equal priority conflicts resolved by BLOCK > REDACT > WARN > ALLOW."""
    rule_warn = PolicyRule(
        rule_id="rule_warn",
        action=PolicyAction.WARN,
        priority=100,
    )
    rule_block = PolicyRule(
        rule_id="rule_block",
        action=PolicyAction.BLOCK,
        priority=100,
    )
    rule_redact = PolicyRule(
        rule_id="rule_redact",
        action=PolicyAction.REDACT,
        priority=100,
    )
    engine = PolicyEngine(rules=[rule_warn, rule_block, rule_redact])
    det = make_detection()

    decision = engine.evaluate([det])
    # BLOCK has highest action precedence (BLOCK > REDACT > WARN > ALLOW)
    assert decision.action == PolicyAction.BLOCK
    assert decision.matched_rules[0] == "rule_block"

    # Now verify REDACT beats WARN at equal priority
    engine_sub = PolicyEngine(rules=[rule_warn, rule_redact])
    decision_sub = engine_sub.evaluate([det])
    assert decision_sub.action == PolicyAction.REDACT
    assert decision_sub.matched_rules[0] == "rule_redact"


def test_31_disabled_high_priority_does_not_override():
    """31. Disabled high priority rule does not override enabled lower priority rule."""
    disabled_high = PolicyRule(
        rule_id="disabled_allow",
        action=PolicyAction.ALLOW,
        priority=999,
        enabled=False,
    )
    enabled_block = PolicyRule(
        rule_id="enabled_block",
        action=PolicyAction.BLOCK,
        priority=100,
        enabled=True,
    )
    engine = PolicyEngine(rules=[disabled_high, enabled_block])
    det = make_detection()

    decision = engine.evaluate([det])
    assert decision.action == PolicyAction.BLOCK
    assert "disabled_allow" not in decision.matched_rules
    assert decision.matched_rules == ["enabled_block"]


# =====================================================================
# 10. PRIVACY AND NON-LEAKAGE
# =====================================================================


def test_32_policy_decision_does_not_expose_raw_secret():
    """32. PolicyDecision fields strictly exclude raw secret values."""
    rule = PolicyRule(
        rule_id="block_secrets",
        action=PolicyAction.BLOCK,
        description="Block all detected secrets",
    )
    engine = PolicyEngine(rules=[rule])
    # Finding containing synthetic description without secrets
    det = make_detection(description="Possible secret token detected")
    decision = engine.evaluate([det])

    # Ensure no arbitrary raw token strings exist anywhere in attributes
    raw_key = "sk-live-1234567890abcdef"
    assert raw_key not in decision.reason
    assert raw_key not in str(decision.matched_rules)


def test_33_policy_reason_contains_no_raw_secret():
    """33. Policy reason is formatted using safe, non-sensitive tokens."""
    rule = PolicyRule(
        rule_id="block_high_secrets",
        action=PolicyAction.BLOCK,
        category=DetectionCategory.SECRET,
        minimum_severity=Severity.HIGH,
        description="Prevent credential leakage",
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection(
        category=DetectionCategory.SECRET,
        severity=Severity.HIGH,
    )
    decision = engine.evaluate([det])

    expected_msg = (
        "Blocked because high-severity secret matched rule 'block_high_secrets'"
    )
    assert expected_msg in decision.reason
    # Verify no secret keywords or sensitive data
    assert "sk-" not in decision.reason
    assert "password" not in decision.reason.lower()


def test_34_repr_and_str_of_decision_remains_safe():
    """34. repr() and str() of PolicyDecision are safe to log."""
    rule = PolicyRule(rule_id="warn_rule", action=PolicyAction.WARN)
    engine = PolicyEngine(rules=[rule])
    det = make_detection()
    decision = engine.evaluate([det])

    decision_repr = repr(decision)
    decision_str = str(decision)

    assert "PolicyDecision" in decision_repr
    assert "warn" in decision_repr.lower()
    assert "warn_rule" in decision_repr
    assert "warn" in decision_str.lower()


# =====================================================================
# 11. DETERMINISM
# =====================================================================


def test_35_same_input_produces_same_decision():
    """35. Identical input produces identical PolicyDecision."""
    rule = PolicyRule(
        rule_id="rule_redact",
        action=PolicyAction.REDACT,
        priority=100,
    )
    engine = PolicyEngine(rules=[rule])
    det = make_detection()

    d1 = engine.evaluate([det])
    d2 = engine.evaluate([det])

    assert d1.action == d2.action
    assert d1.reason == d2.reason
    assert d1.matched_rules == d2.matched_rules


def test_36_repeated_evaluation_produces_identical_results():
    """36. Stateless engine produces identical results across 50 repeated runs."""
    rule1 = PolicyRule(rule_id="r1", action=PolicyAction.WARN, priority=50)
    rule2 = PolicyRule(rule_id="r2", action=PolicyAction.BLOCK, priority=100)
    engine = PolicyEngine(rules=[rule1, rule2])
    det = make_detection()

    baseline = engine.evaluate([det])
    for _ in range(50):
        result = engine.evaluate([det])
        assert result.action == baseline.action
        assert result.reason == baseline.reason
        assert result.matched_rules == baseline.matched_rules


# =====================================================================
# 12. RULE AND CONFIGURATION VALIDATION
# =====================================================================


def test_37_empty_rule_id_rejected():
    """37. Empty or whitespace-only rule_id is rejected."""
    with pytest.raises(ValidationError, match="non-empty string"):
        PolicyRule(rule_id="", action=PolicyAction.BLOCK)

    with pytest.raises(ValidationError, match="non-empty string"):
        PolicyRule(rule_id="   ", action=PolicyAction.BLOCK)


def test_38_invalid_action_rejected():
    """38. Invalid policy action string or type is rejected."""
    with pytest.raises(ValidationError, match="Invalid policy action"):
        PolicyRule(rule_id="r", action="INVALID_ACTION")  # type: ignore[arg-type]


def test_39_invalid_priority_rejected():
    """39. Negative or non-integer priority is rejected."""
    with pytest.raises(ValidationError, match="non-negative integer"):
        PolicyRule(rule_id="r", action=PolicyAction.BLOCK, priority=-1)

    with pytest.raises(ValidationError, match="must be an integer"):
        PolicyRule(rule_id="r", action=PolicyAction.BLOCK, priority="100")  # type: ignore[arg-type]


def test_40_invalid_confidence_rejected():
    """40. Invalid confidence values (< 0 or > 1) are rejected."""
    with pytest.raises(ValidationError, match="between 0.0 and 1.0"):
        PolicyRule(
            rule_id="r",
            action=PolicyAction.BLOCK,
            minimum_confidence=1.1,
        )


def test_41_invalid_configuration_rejected_safely():
    """41. Configuration validation rejects duplicate rule IDs and non-rules."""
    r1 = PolicyRule(rule_id="dup_id", action=PolicyAction.ALLOW)
    r2 = PolicyRule(rule_id="dup_id", action=PolicyAction.BLOCK)

    with pytest.raises(ConfigurationError, match="Duplicate rule_id"):
        PolicyConfig(rules=[r1, r2])

    with pytest.raises(ConfigurationError, match="not a PolicyRule instance"):
        PolicyConfig(rules=["not_a_rule"])  # type: ignore[list-item]


# =====================================================================
# 13. LOCAL INTEGRATION TEST (SecretDetector -> Engine -> Decision)
# =====================================================================


def test_integration_secret_detector_to_policy_engine():
    """Integration: SecretDetector produces findings evaluated by PolicyEngine.

    Demonstrates the complete decoupled pipeline:
    SecretDetector -> DetectionResult[] -> PolicyEngine -> PolicyDecision
    """
    detector = SecretDetector()
    context = DetectorContext(
        request_id="req-integ-1",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )

    # Text containing a synthetic GitHub token
    content = "Deploying with token: ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
    detections = detector.detect(content, context)

    assert len(detections) >= 1
    assert detections[0].category == DetectionCategory.SECRET
    assert detections[0].severity == Severity.HIGH
    assert detections[0].confidence >= 0.90

    # Policy 1: High severity secrets -> BLOCK
    block_policy = PolicyEngine(
        rules=[
            PolicyRule(
                rule_id="block_high_secrets",
                category=DetectionCategory.SECRET,
                minimum_severity=Severity.HIGH,
                action=PolicyAction.BLOCK,
                description="Block dangerous API keys and credentials",
            )
        ]
    )

    decision = block_policy.evaluate(detections)
    assert decision.action == PolicyAction.BLOCK
    assert "block_high_secrets" in decision.matched_rules
    expected_msg = (
        "Blocked because high-severity secret matched rule 'block_high_secrets'"
    )
    assert expected_msg in decision.reason
    assert len(decision.detections) == len(detections)

    # Policy 2: User override in development mode -> WARN
    dev_policy = PolicyEngine(
        rules=[
            PolicyRule(
                rule_id="dev_warn_secrets",
                category=DetectionCategory.SECRET,
                action=PolicyAction.WARN,
                description="Warn only in development mode",
            )
        ]
    )

    dev_decision = dev_policy.evaluate(detections)
    assert dev_decision.action == PolicyAction.WARN
    assert "dev_warn_secrets" in dev_decision.matched_rules


def test_action_precedence_ranking():
    """Verify action precedence hierarchy ranking."""
    assert ACTION_PRECEDENCE[PolicyAction.ALLOW] < ACTION_PRECEDENCE[PolicyAction.WARN]
    assert ACTION_PRECEDENCE[PolicyAction.WARN] < ACTION_PRECEDENCE[PolicyAction.REDACT]
    assert (
        ACTION_PRECEDENCE[PolicyAction.REDACT] < ACTION_PRECEDENCE[PolicyAction.BLOCK]
    )
