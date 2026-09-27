"""Core domain enums and type definitions for AI Data Firewall.

Establishes the fundamental vocabulary for content direction, content origin,
finding classification, severity grading, policy enforcement, and audit events.
"""

from enum import StrEnum


class ContentDirection(StrEnum):
    """Direction of traffic being inspected across the firewall.

    Allows the same inspection interfaces and policies to operate on both
    inbound client requests and outbound model completions.
    """

    REQUEST = "request"
    RESPONSE = "response"


class ContentSource(StrEnum):
    """Identifies the trust boundary and origin of inspected content.

    Distinguishes user-submitted text from retrieved context, system instructions,
    and tool outputs to enable context-aware security policies.
    """

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_CONTENT = "retrieved_content"
    UNKNOWN = "unknown"

    # Backward compatibility aliases
    USER_INPUT = "user"
    SYSTEM_INSTRUCTION = "system"
    ASSISTANT_HISTORY = "assistant"
    RETRIEVED_DOCUMENT = "retrieved_content"
    MODEL_OUTPUT = "assistant"


class Severity(StrEnum):
    """Classification of the security, privacy, or safety severity of a finding.

    Severity is an observational property of a finding; it does NOT directly
    determine whether traffic is blocked. Enforcement is decided by the policy engine.

    Levels:
    - INFO: Informational finding with minimal or no direct security risk.
    - LOW: Minor anomaly or low-risk exposure; often logged or monitored.
    - MEDIUM: Notable policy violation or moderately sensitive exposure.
    - HIGH: Severe risk requiring mitigation (e.g. credential or sensitive PII).
    - CRITICAL: Maximum risk threat (e.g. root secret leak, injection exploit).
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionCategory(StrEnum):
    """Broad classification of security, privacy, and safety detections."""

    SECRET = "secret"
    PII = "pii"
    PROMPT_INJECTION = "prompt_injection"
    OTHER = "other"


class PolicyAction(StrEnum):
    """Actions that a policy engine may execute upon evaluating findings.

    - ALLOW: Permit the traffic to proceed unaltered.
    - WARN: Permit the traffic but record warning diagnostic events.
    - REDACT: Transform the content (e.g. mask secrets) before forwarding.
    - BLOCK: Halt request processing immediately and return a safe error.
    """

    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


class EventType(StrEnum):
    """Types of events recorded in the security audit pipeline."""

    DETECTION = "detection"
    WARNING = "warning"
    REDACTION = "redaction"
    BLOCK = "block"
    ERROR = "error"
