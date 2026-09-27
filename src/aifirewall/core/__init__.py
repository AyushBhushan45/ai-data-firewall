"""Core primitives, types, and error hierarchy for AI Data Firewall."""

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
from aifirewall.core.utils import sanitize_url_for_display

__all__ = [
    "AIFirewallError",
    "ValidationError",
    "DetectorError",
    "ConfigurationError",
    "ProcessingError",
    "ContentDirection",
    "ContentSource",
    "Severity",
    "DetectionCategory",
    "PolicyAction",
    "EventType",
    "sanitize_url_for_display",
]
