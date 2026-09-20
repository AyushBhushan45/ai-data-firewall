"""Smoke tests for package initialization and version."""

from aifirewall import __version__


def test_version_exists():
    """Verify that the package exposes a valid version string."""
    assert __version__ == "0.1.0"
