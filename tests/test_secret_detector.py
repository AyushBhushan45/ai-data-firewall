"""Comprehensive unit tests for SecretDetector.

Verifies pattern recognition, character coordinates, false-positive protection,
privacy non-exposure, and protocol conformance.
All test secrets are synthetic and fake.
"""

import pytest

from aifirewall.core.errors import ValidationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    Severity,
)
from aifirewall.detectors.base import Detector, DetectorContext
from aifirewall.detectors.secret import SecretDetector


@pytest.fixture
def detector() -> SecretDetector:
    """Fixture providing a fresh SecretDetector instance."""
    return SecretDetector()


@pytest.fixture
def context() -> DetectorContext:
    """Fixture providing standard test DetectorContext."""
    return DetectorContext(
        request_id="req-test-123",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
        model="gpt-4o",
    )


# -------------------------------------------------------------------------
# Basic Behavior & Protocol Conformance
# -------------------------------------------------------------------------


def test_instantiation_and_protocol(detector: SecretDetector):
    """Verify SecretDetector instantiates and satisfies Detector protocol."""
    assert isinstance(detector, Detector)
    assert detector.name == "secret-detector"
    assert detector.version == "1.0.0"
    assert "Pattern-based" in detector.description
    assert detector.supported_categories == (DetectionCategory.SECRET,)


def test_empty_string_returns_empty_list(
    detector: SecretDetector, context: DetectorContext
):
    """Verify empty input content produces zero findings."""
    assert detector.detect("", context) == []


def test_clean_text_returns_empty_list(
    detector: SecretDetector, context: DetectorContext
):
    """Verify benign text without credentials produces zero findings."""
    text = "Hello world! This is a standard conversational query without tokens."
    assert detector.detect(text, context) == []


def test_ordinary_prose_does_not_trigger(
    detector: SecretDetector, context: DetectorContext
):
    """Verify ordinary prose mentioning security keywords does not trigger."""
    text = (
        "The API key is stored securely in environment variables. "
        "The password field contains the user's password in an encrypted format."
    )
    assert detector.detect(text, context) == []


def test_invalid_content_type_raises_validation_error(
    detector: SecretDetector, context: DetectorContext
):
    """Verify passing a non-string object raises ValidationError."""
    with pytest.raises(ValidationError, match="content must be a string"):
        detector.detect(12345, context)  # type: ignore[arg-type]


# -------------------------------------------------------------------------
# OpenAI Pattern
# -------------------------------------------------------------------------


def test_openai_api_key_detected(
    detector: SecretDetector, context: DetectorContext
):
    """Verify standard and project-scoped OpenAI keys are recognized."""
    fake_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
    text = f"My key is {fake_key} for testing."
    findings = detector.detect(text, context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.detector_name == "secret-detector"
    assert finding.category == DetectionCategory.SECRET
    assert finding.severity == Severity.HIGH
    assert finding.confidence >= 0.90
    assert "OpenAI API key" in finding.description

    # Location offset verification
    start = finding.location.char_start
    end = finding.location.char_end
    assert text[start:end] == fake_key


def test_openai_proj_key_detected(
    detector: SecretDetector, context: DetectorContext
):
    """Verify modern sk-proj- prefixed OpenAI keys are recognized."""
    fake_key = "sk-proj-abcdef1234567890abcdef1234567890xyz"
    text = f"Config: {fake_key}"
    findings = detector.detect(text, context)

    assert len(findings) == 1
    start = findings[0].location.char_start
    end = findings[0].location.char_end
    assert text[start:end] == fake_key


# -------------------------------------------------------------------------
# GitHub Token Patterns
# -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prefix",
    ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
)
def test_github_tokens_detected(
    detector: SecretDetector, context: DetectorContext, prefix: str
):
    """Verify multiple GitHub personal access token prefixes are detected."""
    fake_token = f"{prefix}123456789012345678901234567890123456"
    text = f"Token is {fake_token}."
    findings = detector.detect(text, context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == DetectionCategory.SECRET
    assert finding.severity == Severity.HIGH
    assert finding.metadata["pattern"] == "github_token"
    start = finding.location.char_start
    end = finding.location.char_end
    assert text[start:end] == fake_token


# -------------------------------------------------------------------------
# Google API Key Pattern
# -------------------------------------------------------------------------


def test_google_api_key_detected(
    detector: SecretDetector, context: DetectorContext
):
    """Verify Google AIza-prefixed API key format is detected."""
    fake_key = "AIzaSyDummyKey1234567890abcdefghijklm"
    text = f"const apiKey = '{fake_key}';"
    findings = detector.detect(text, context)

    # May match google_api_key and/or credential_assignment
    google_matches = [
        f for f in findings if f.metadata.get("pattern") == "google_api_key"
    ]
    assert len(google_matches) == 1
    start = google_matches[0].location.char_start
    end = google_matches[0].location.char_end
    assert text[start:end] == fake_key


# -------------------------------------------------------------------------
# AWS Access Key IDs
# -------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["AKIA", "ASIA"])
def test_aws_access_key_id_detected(
    detector: SecretDetector, context: DetectorContext, prefix: str
):
    """Verify AWS AKIA and ASIA access key identifiers are detected."""
    fake_aws = f"{prefix}IOSFODNN7EXAMPLE"
    text = f"AWS_ACCESS_KEY_ID={fake_aws}"
    findings = detector.detect(text, context)

    aws_matches = [
        f for f in findings if f.metadata.get("pattern") == "aws_access_key_id"
    ]
    assert len(aws_matches) == 1
    finding = aws_matches[0]
    assert "Possible AWS access key ID" in finding.description
    start = finding.location.char_start
    end = finding.location.char_end
    assert text[start:end] == fake_aws


# -------------------------------------------------------------------------
# Slack Token Patterns
# -------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["xoxb-", "xoxp-", "xoxa-", "xoxr-"])
def test_slack_tokens_detected(
    detector: SecretDetector, context: DetectorContext, prefix: str
):
    """Verify Slack token prefixes are identified."""
    fake_slack = f"{prefix}123456789012-123456789012-abcdefghijklmnopqrst"
    text = f"slack_token: {fake_slack}"
    findings = detector.detect(text, context)

    slack_matches = [
        f for f in findings if f.metadata.get("pattern") == "slack_token"
    ]
    assert len(slack_matches) == 1
    start = slack_matches[0].location.char_start
    end = slack_matches[0].location.char_end
    assert text[start:end] == fake_slack


# -------------------------------------------------------------------------
# JSON Web Token (JWT)
# -------------------------------------------------------------------------


def test_jwt_token_detected(
    detector: SecretDetector, context: DetectorContext
):
    """Verify 3-part base64url JWT structure is recognized."""
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    text = f"jwt_token = '{fake_jwt}'"
    findings = detector.detect(text, context)

    jwt_matches = [f for f in findings if f.metadata.get("pattern") == "jwt"]
    assert len(jwt_matches) == 1
    finding = jwt_matches[0]
    assert "Possible JWT" in finding.description
    start = finding.location.char_start
    end = finding.location.char_end
    assert text[start:end] == fake_jwt


# -------------------------------------------------------------------------
# Bearer Token Recognition
# -------------------------------------------------------------------------


def test_bearer_token_in_header_detected(
    detector: SecretDetector, context: DetectorContext
):
    """Verify Authorization Bearer header is recognized."""
    fake_token = "mF_9.B5f-4.1JqM_fakeBearerToken123456"
    text = f"Authorization: Bearer {fake_token}"
    findings = detector.detect(text, context)

    bearer_matches = [
        f for f in findings if f.metadata.get("pattern") == "bearer_token"
    ]
    assert len(bearer_matches) == 1
    start = bearer_matches[0].location.char_start
    end = bearer_matches[0].location.char_end
    assert text[start:end] == fake_token


def test_prose_mentioning_bearer_auth_does_not_trigger(
    detector: SecretDetector, context: DetectorContext
):
    """Ensure prose mentioning bearer authentication is not flagged as a token."""
    text = "Bearer authentication is commonly used across REST APIs."
    findings = detector.detect(text, context)
    assert findings == []


# -------------------------------------------------------------------------
# Credential Assignments
# -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "val"),
    [
        ("api_key", "secretValue99999"),
        ("access_token", "authTokenValue88888"),
        ("client_secret", "clientSecret99999"),
        ("password", "superSecretPass123!"),
        ("private_key", "privateKeyPayload999"),
    ],
)
def test_explicit_assignments_detected(
    detector: SecretDetector, context: DetectorContext, key: str, val: str
):
    """Verify various explicit assignment formats with equals and colons."""
    text1 = f'{key}="{val}"'
    findings1 = detector.detect(text1, context)
    assert len(findings1) >= 1
    loc1 = findings1[0].location
    assert text1[loc1.char_start:loc1.char_end] == val

    text2 = f"{key}: '{val}'"
    findings2 = detector.detect(text2, context)
    assert len(findings2) >= 1
    loc2 = findings2[0].location
    assert text2[loc2.char_start:loc2.char_end] == val


def test_empty_assignment_does_not_trigger(
    detector: SecretDetector, context: DetectorContext
):
    """Verify assignments with empty values are ignored."""
    text = 'api_key="" and password=\'\''
    assert detector.detect(text, context) == []


# -------------------------------------------------------------------------
# False-Positive & Placeholder Mitigations
# -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placeholder",
    [
        "YOUR_API_KEY",
        "YOUR_SECRET",
        "YOUR_TOKEN",
        "<YOUR_API_KEY>",
        "REPLACE_ME",
        "CHANGEME",
        "dummy-token",
        "example-token",
        "test-token",
    ],
)
def test_placeholders_do_not_trigger(
    detector: SecretDetector, context: DetectorContext, placeholder: str
):
    """Verify standard documentation placeholders do not generate findings."""
    text = f'api_key = "{placeholder}"'
    assert detector.detect(text, context) == []


# -------------------------------------------------------------------------
# Location Accuracy Tests
# -------------------------------------------------------------------------


def test_location_at_start_middle_end(
    detector: SecretDetector, context: DetectorContext
):
    """Verify exact character coordinates at beginning, middle, and end."""
    token = "ghp_123456789012345678901234567890123456"

    # At start
    text_start = f"{token} is the token"
    res_start = detector.detect(text_start, context)
    assert len(res_start) == 1
    assert res_start[0].location.char_start == 0
    assert res_start[0].location.char_end == len(token)

    # In middle
    text_mid = f"Token: {token} here"
    res_mid = detector.detect(text_mid, context)
    start_mid = res_mid[0].location.char_start
    end_mid = res_mid[0].location.char_end
    assert text_mid[start_mid:end_mid] == token

    # At end
    text_end = f"Token is {token}"
    res_end = detector.detect(text_end, context)
    assert len(res_end) == 1
    assert res_end[0].location.char_end == len(text_end)


def test_multiline_character_offsets(
    detector: SecretDetector, context: DetectorContext
):
    """Verify newline characters are accurately accounted for in offsets."""
    token = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
    text = f"Line 1\nLine 2 with {token}\nLine 3"
    findings = detector.detect(text, context)

    assert len(findings) == 1
    start = findings[0].location.char_start
    end = findings[0].location.char_end
    assert text[start:end] == token


def test_repeated_secrets_produce_multiple_findings(
    detector: SecretDetector, context: DetectorContext
):
    """Verify repeated tokens in same string produce distinct findings."""
    token1 = "ghp_111111111111111111111111111111111111"
    token2 = "ghp_222222222222222222222222222222222222"
    text = f"First: {token1} and second: {token2}"
    findings = detector.detect(text, context)

    assert len(findings) == 2
    s0 = findings[0].location.char_start
    e0 = findings[0].location.char_end
    s1 = findings[1].location.char_start
    e1 = findings[1].location.char_end
    assert s0 is not None and e0 is not None and s1 is not None and e1 is not None
    assert text[s0:e0] == token1
    assert text[s1:e1] == token2
    assert s0 < s1


# -------------------------------------------------------------------------
# Privacy Safeguards
# -------------------------------------------------------------------------


def test_privacy_non_exposure_in_all_representations(
    detector: SecretDetector, context: DetectorContext
):
    """Verify raw secret is never present in repr, str, or metadata."""
    secret = "sk-superSecretTokenThatMustNeverBeExposed12345"
    text = f"My live key: {secret}"
    findings = detector.detect(text, context)

    assert len(findings) == 1
    finding = findings[0]

    # Verify absence of raw secret in repr and str
    assert secret not in repr(finding)
    assert secret not in str(finding)

    # Verify absence in metadata values
    for val in finding.metadata.values():
        assert secret not in str(val)

    # Verify no raw secret fields exist on the model
    assert not hasattr(finding, "raw_secret")
    assert not hasattr(finding, "detected_value")
    assert not hasattr(finding, "secret_value")
