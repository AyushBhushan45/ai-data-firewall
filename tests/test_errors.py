"""Tests for the AIFirewallError exception hierarchy and error safety."""

import pytest

from aifirewall.core.errors import (
    AIFirewallError,
    ConfigurationError,
    DetectorError,
    ProcessingError,
    ValidationError,
)


def test_error_hierarchy():
    """Verify that all domain errors inherit from AIFirewallError."""
    assert issubclass(ValidationError, AIFirewallError)
    assert issubclass(DetectorError, AIFirewallError)
    assert issubclass(ConfigurationError, AIFirewallError)
    assert issubclass(ProcessingError, AIFirewallError)
    assert issubclass(AIFirewallError, Exception)


def test_base_error_representation():
    """Verify string and repr formatting for AIFirewallError."""
    err = AIFirewallError("Core firewall failure")
    assert str(err) == "Core firewall failure"
    assert repr(err) == "AIFirewallError('Core firewall failure')"
    assert err.message == "Core firewall failure"


def test_detector_error_metadata():
    """Verify DetectorError captures detector identifier safely."""
    err = DetectorError("regex_scanner", "Pattern compilation failed")
    assert err.detector_name == "regex_scanner"
    assert "Detector 'regex_scanner' failed: Pattern compilation failed" in str(err)
    assert "DetectorError" in repr(err)


def test_error_privacy_safety():
    """Ensure sensitive payload data is not introduced by error handlers."""
    safe_msg = "Validation failed for field 'confidence'"
    err = ValidationError(safe_msg)
    assert "sk-" not in str(err)
    assert "password" not in str(err)
    assert str(err) == safe_msg


def test_raising_and_catching_errors():
    """Verify standard exception handling catching base AIFirewallError."""
    with pytest.raises(AIFirewallError):
        raise ValidationError("Test validation issue")

    with pytest.raises(AIFirewallError):
        raise DetectorError("dummy", "Engine fault")

    with pytest.raises(AIFirewallError):
        raise ConfigurationError("Missing key: rules")

    with pytest.raises(AIFirewallError):
        raise ProcessingError("Pipeline stage timed out")
