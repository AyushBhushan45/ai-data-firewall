"""Core exception hierarchy for AI Data Firewall.

Privacy Rule: Exception messages must NEVER contain raw secrets, credentials,
sensitive PII, or complete user prompts. Exceptions provide safe diagnostic
descriptions for operators and developers.
"""


class AIFirewallError(Exception):
    """Base exception for all AI Data Firewall errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r})"


class ValidationError(AIFirewallError):
    """Raised when data model validation fails.

    Examples: confidence outside [0.0, 1.0], inverted character offsets,
    or empty mandatory identifiers.
    """


class DetectorError(AIFirewallError):
    """Raised when a detector encounters an unhandled runtime error.

    Carries the detector name and a safe failure message without exposing
    the content being inspected.
    """

    def __init__(self, detector_name: str, message: str) -> None:
        safe_msg = f"Detector '{detector_name}' failed: {message}"
        super().__init__(safe_msg)
        self.detector_name = detector_name


class ConfigurationError(AIFirewallError):
    """Raised when configuration parsing, syntax, or schema validation fails."""


class ProcessingError(AIFirewallError):
    """Raised when request or response processing in the pipeline fails."""
