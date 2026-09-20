"""Secret and credential detector for AI Data Firewall.

Inspects content for common API keys, personal access tokens, and explicit
credential assignments. Adheres strictly to:
DETECTION ≠ POLICY ≠ TRANSFORMATION.
"""

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aifirewall.core.errors import DetectorError, ValidationError
from aifirewall.core.types import DetectionCategory, Severity
from aifirewall.detectors.base import DetectorContext
from aifirewall.models.content import ContentLocation
from aifirewall.models.detection import DetectionResult

# Common placeholder substrings that indicate dummy / non-secret values
_COMMON_PLACEHOLDERS: frozenset[str] = frozenset({
    "your_api_key",
    "your_token",
    "your_secret",
    "your_key",
    "your_password",
    "replace_me",
    "replace-me",
    "changeme",
    "change_me",
    "change-me",
    "<api_key>",
    "<your_secret>",
    "<your_token>",
    "<your_api_key>",
    "example-token",
    "example_token",
    "dummy-token",
    "dummy_token",
    "test-token",
    "test_token",
    "fake_token",
    "sample_token",
    "my_secret_key",
    "insert_key_here",
    "xxxx",
    "yyyy",
    "zzzz",
})


def _is_placeholder(val: str) -> bool:
    """Return True if the extracted value is an obvious placeholder."""
    cleaned = val.strip().lower()
    if cleaned in _COMMON_PLACEHOLDERS:
        return True
    # Strip enclosing angle brackets, quotes, braces
    stripped = cleaned.strip("<>{}[]()\"'")
    if stripped in _COMMON_PLACEHOLDERS:
        return True
    if "your_" in stripped or "replace_" in stripped or "example_" in stripped:
        return True
    if "your-" in stripped or "replace-" in stripped or "example-" in stripped:
        return True
    return False


@dataclass(frozen=True)
class SecretPattern:
    """Definition for a named secret or credential pattern recognizer."""

    name: str
    regex: re.Pattern[str]
    description: str
    severity: Severity
    confidence: float
    match_type: str
    validator: Callable[[re.Match[str]], tuple[int, int] | None] | None = None


def _span_from_group(
    match: re.Match[str], group_index: int = 0
) -> tuple[int, int] | None:
    """Return character start and end offsets for a specific match group."""
    val = match.group(group_index)
    if not val or _is_placeholder(val):
        return None
    return match.start(group_index), match.end(group_index)


def _validate_bearer(match: re.Match[str]) -> tuple[int, int] | None:
    """Validate a Bearer token match and return token span."""
    token = match.group(1)
    if not token or len(token) < 20 or _is_placeholder(token):
        return None
    # Ensure it's not ordinary prose (e.g. "Bearer authentication is commonly...")
    # Tokens must not contain whitespace and typically contain alphanumeric chars
    if any(c.isspace() for c in token):
        return None
    return match.start(1), match.end(1)


def _validate_jwt(match: re.Match[str]) -> tuple[int, int] | None:
    """Validate 3-part JWT structure without decoding payloads."""
    raw = match.group(0)
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    # Standard JWT header usually begins with 'ey' (e.g. {"alg":...})
    if not header.startswith("ey") or len(payload) < 8 or len(signature) < 8:
        return None
    return match.start(0), match.end(0)


def _validate_assignment(match: re.Match[str]) -> tuple[int, int] | None:
    """Validate explicit credential assignment (key = val)."""
    # Group 1: field name
    # Group 2: quote char (optional)
    # Group 3: quoted value (if quoted)
    # Group 4: unquoted value (if unquoted)
    quoted_val = match.group(3)
    unquoted_val = match.group(4)
    val = quoted_val if quoted_val is not None else unquoted_val
    if not val:
        return None

    # Strip whitespace from candidate value
    val_clean = val.strip()
    if len(val_clean) < 8 or _is_placeholder(val_clean):
        return None

    if quoted_val is not None:
        # Offsets inside quotes
        start = match.start(3)
        end = match.end(3)
    else:
        start = match.start(4)
        end = match.end(4)

    return start, end


class SecretDetector:
    """Observational scanner for detecting secrets and credentials in text.

    Conforms to the Detector protocol.
    Identifies common API keys, access tokens, and credential assignments.
    """

    def __init__(self) -> None:
        self._patterns: list[SecretPattern] = self._compile_patterns()

    @property
    def name(self) -> str:
        """Unique identifier of the detector."""
        return "secret-detector"

    @property
    def version(self) -> str:
        """Semantic version of the detector."""
        return "1.0.0"

    @property
    def description(self) -> str:
        """Safe human-readable description of what this detector identifies."""
        return (
            "Pattern-based detector for common API keys, access tokens, "
            "and credential assignments."
        )

    @property
    def supported_categories(self) -> tuple[DetectionCategory, ...]:
        """Categories of findings produced by this detector."""
        return (DetectionCategory.SECRET,)

    def _compile_patterns(self) -> list[SecretPattern]:
        """Compile and return the ordered sequence of secret recognizers."""
        patterns: list[SecretPattern] = [
            # 1. OpenAI-style API keys (standard sk-... or sk-proj-...)
            SecretPattern(
                name="openai_api_key",
                regex=re.compile(
                    r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"
                ),
                description="Possible OpenAI API key detected.",
                severity=Severity.HIGH,
                confidence=0.95,
                match_type="structured_token",
                validator=lambda m: _span_from_group(m, 1),
            ),
            # 2. GitHub personal access tokens
            SecretPattern(
                name="github_token",
                regex=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"),
                description="Possible GitHub access token detected.",
                severity=Severity.HIGH,
                confidence=0.95,
                match_type="structured_token",
                validator=lambda m: _span_from_group(m, 1),
            ),
            # 3. Google API keys
            SecretPattern(
                name="google_api_key",
                regex=re.compile(r"\b(AIza[0-9A-Za-z-_]{33,40})\b"),
                description="Possible Google API key detected.",
                severity=Severity.HIGH,
                confidence=0.95,
                match_type="structured_token",
                validator=lambda m: _span_from_group(m, 1),
            ),
            # 4. AWS access key IDs
            SecretPattern(
                name="aws_access_key_id",
                regex=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
                description="Possible AWS access key ID detected.",
                severity=Severity.HIGH,
                confidence=0.90,
                match_type="structured_token",
                validator=lambda m: _span_from_group(m, 1),
            ),
            # 5. Slack-style tokens
            SecretPattern(
                name="slack_token",
                regex=re.compile(r"\b(xox[bpar]-[0-9A-Za-z-]{10,})\b"),
                description="Possible Slack token detected.",
                severity=Severity.HIGH,
                confidence=0.95,
                match_type="structured_token",
                validator=lambda m: _span_from_group(m, 1),
            ),
            # 6. JSON Web Tokens (3-segment Base64URL)
            SecretPattern(
                name="jwt",
                regex=re.compile(
                    r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
                ),
                description="Possible JWT detected.",
                severity=Severity.HIGH,
                confidence=0.85,
                match_type="structured_token",
                validator=_validate_jwt,
            ),
            # 7. Bearer authentication tokens
            SecretPattern(
                name="bearer_token",
                regex=re.compile(
                    r"(?:Authorization\s*:\s*)?Bearer\s+([A-Za-z0-9._~+/-]{20,})",
                    re.IGNORECASE,
                ),
                description="Possible Bearer token detected.",
                severity=Severity.HIGH,
                confidence=0.85,
                match_type="header_or_auth",
                validator=_validate_bearer,
            ),
            # 8. Explicit credential assignments
            SecretPattern(
                name="credential_assignment",
                regex=re.compile(
                    r"\b(api[_-]?key|access[_-]?token|auth[_-]?token|"
                    r"client[_-]?secret|private[_-]?key|password|secret)\s*[:=]\s*"
                    r"(?:(['\"])(.*?)\2|([^\s,;'\"`\r\n]{8,}))",
                    re.IGNORECASE,
                ),
                description="Possible credential assignment detected.",
                severity=Severity.HIGH,
                confidence=0.80,
                match_type="assignment",
                validator=_validate_assignment,
            ),
        ]
        return patterns

    def detect(
        self,
        content: str,
        context: DetectorContext,
    ) -> list[DetectionResult]:
        """Inspect the given content string and return detected secret findings.

        Args:
            content: The text content segment to inspect.
            context: Execution context containing request ID, direction, source.

        Returns:
            A list of zero or more DetectionResult objects sorted by location.

        Raises:
            ValidationError: If content is not a string.
            DetectorError: If regex execution fails unexpectedly.
        """
        if not isinstance(content, str):
            raise ValidationError(
                f"content must be a string, got {type(content).__name__}"
            )

        if not content:
            return []

        findings: list[DetectionResult] = []
        # Track seen spans (start, end) to avoid redundant duplicate matches
        seen_spans: set[tuple[int, int]] = set()

        try:
            for pat in self._patterns:
                for match in pat.regex.finditer(content):
                    span: tuple[int, int] | None
                    if pat.validator is not None:
                        span = pat.validator(match)
                    else:
                        span = match.start(), match.end()

                    if span is None:
                        continue

                    start, end = span
                    if start < 0 or end > len(content) or start >= end:
                        continue

                    # If this exact span was already identified by a more specific
                    # pattern, skip duplicate generic assignment
                    if (start, end) in seen_spans:
                        continue

                    seen_spans.add((start, end))

                    # Build safe metadata without storing the secret value
                    meta: dict[str, Any] = {
                        "pattern": pat.name,
                        "match_type": pat.match_type,
                    }
                    if pat.name == "credential_assignment":
                        field_name = match.group(1).lower()
                        meta["field"] = field_name
                        desc = f"Possible credential assigned to {field_name}."
                    else:
                        desc = pat.description

                    loc = ContentLocation(
                        source=context.source,
                        char_start=start,
                        char_end=end,
                    )
                    finding = DetectionResult(
                        detection_id=f"det-{uuid.uuid4().hex[:12]}",
                        detector_name=self.name,
                        category=DetectionCategory.SECRET,
                        severity=pat.severity,
                        confidence=pat.confidence,
                        location=loc,
                        description=desc,
                        metadata=meta,
                    )
                    findings.append(finding)

        except Exception as exc:
            # Wrap unexpected internal exceptions safely without leaking content
            if isinstance(exc, ValidationError):
                raise
            raise DetectorError(
                self.name, f"Regex evaluation error: {type(exc).__name__}"
            ) from exc

        # Deterministic sorting by character start then end
        findings.sort(
            key=lambda d: (
                d.location.char_start if d.location.char_start is not None else 0,
                d.location.char_end if d.location.char_end is not None else 0,
            )
        )
        return findings
