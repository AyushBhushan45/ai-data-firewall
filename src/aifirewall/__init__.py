"""AI Data Firewall: An open-source, local-first security layer for AI applications."""

from aifirewall.core.errors import (
    AIFirewallError,
    ConfigurationError,
    DetectorError,
    ProcessingError,
    ValidationError,
)
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    EventType,
    PolicyAction,
    Severity,
)
from aifirewall.detectors.base import (
    Detector,
    DetectorContext,
)
from aifirewall.detectors.secret import SecretDetector
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult
from aifirewall.models.event import PolicyDecision, SecurityEvent
from aifirewall.models.request import NormalizedAIRequest, NormalizedMessage
from aifirewall.models.response import NormalizedAIResponse
from aifirewall.policy import (
    PolicyConfig,
    PolicyContext,
    PolicyEngine,
    PolicyRule,
)
from aifirewall.protocols import (
    AuditSink,
    ContentTransformer,
    ProviderAdapter,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Core types & enums
    "ContentDirection",
    "ContentSource",
    "DetectionCategory",
    "EventType",
    "PolicyAction",
    "Severity",
    # Error hierarchy
    "AIFirewallError",
    "ConfigurationError",
    "DetectorError",
    "ProcessingError",
    "ValidationError",
    # Domain models
    "ContentLocation",
    "DetectionResult",
    "NormalizedAIRequest",
    "NormalizedAIResponse",
    "NormalizedMessage",
    "PolicyDecision",
    "SecurityEvent",
    # Detector protocol, context & implementations
    "Detector",
    "DetectorContext",
    "SecretDetector",
    # Policy engine, rules & configuration
    "PolicyConfig",
    "PolicyContext",
    "PolicyEngine",
    "PolicyRule",
    # Architectural protocols
    "AuditSink",
    "ContentTransformer",
    "ProviderAdapter",
]
