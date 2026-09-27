"""Tests for AI Data Firewall command-line interface (CLI).

Validates:
- aifirewall --help and -h
- aifirewall --version, -v, -V (single source of truth from package)
- aifirewall providers (offline provider listing)
- aifirewall scan (offline scanning, clean, redact, block, warn, --json)
- aifirewall start (argument parsing, precedence, safe error handling)
- Exit codes: 0 (success/redact/warn), 1 (runtime error), 2 (usage), 3 (blocked)
"""

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

import aifirewall
from aifirewall.cli import (
    EXIT_BLOCKED,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE_ERROR,
    main,
)


class TestCLIVersionAndHelp:
    """Tests for top-level help and version display."""

    def test_version_flag_long(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--version displays the package version from a single source of truth."""
        ret = main(["--version"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert f"aifirewall {aifirewall.__version__}" in captured.out

    def test_version_flag_short(self, capsys: pytest.CaptureFixture[str]) -> None:
        """-v and -V display package version."""
        ret = main(["-v"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert f"aifirewall {aifirewall.__version__}" in captured.out

    def test_help_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--help displays usage and available subcommands."""
        ret = main(["--help"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "usage: aifirewall" in captured.out
        assert "start" in captured.out
        assert "scan" in captured.out
        assert "providers" in captured.out

    def test_no_args_displays_help_and_exits_usage_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invoking without arguments displays help and returns EXIT_USAGE_ERROR."""
        ret = main([])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "usage: aifirewall" in captured.out

    def test_invalid_command_returns_usage_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unknown subcommand returns usage error without raw tracebacks."""
        ret = main(["nonexistent_command"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err


class TestCLIProviders:
    """Tests for 'aifirewall providers' offline listing."""

    def test_providers_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Listing providers prints all 4 registered adapters offline."""
        ret = main(["providers"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Supported Provider Adapters:" in captured.out
        assert "openai" in captured.out
        assert "anthropic" in captured.out
        assert "gemini" in captured.out
        assert "ollama" in captured.out
        assert "offline" in captured.out


class TestCLIScan:
    """Tests for offline 'aifirewall scan' command."""

    SYNTHETIC_KEY = "sk-proj-abc123456789012345678901234567890123456789012345678"

    def test_scan_clean_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Clean text yields 0 detections, ALLOW action, exit code 0."""
        ret = main(["scan", "The weather is sunny and clear today."])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Detections : 0" in captured.out
        assert "Action     : allow" in captured.out
        assert "Redacted   : no" in captured.out

    def test_scan_secret_text_default_redact(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Text with secret is redacted by default; raw secret is never printed."""
        text = f"Configure secret key: {self.SYNTHETIC_KEY} in settings."
        ret = main(["scan", text])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Detections : 1" in captured.out
        assert "Action     : redact" in captured.out
        assert "Redacted   : yes" in captured.out
        assert "Sanitized Content:" in captured.out
        assert "[REDACTED_SECRET]" in captured.out
        # Privacy guarantee: raw secret must NEVER appear in output
        assert self.SYNTHETIC_KEY not in captured.out
        assert self.SYNTHETIC_KEY not in captured.err

    def test_scan_secret_text_block_preset(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Block preset returns EXIT_BLOCKED (3); raw secret is never printed."""
        text = f"Leaking token {self.SYNTHETIC_KEY}"
        ret = main(["scan", text, "--policy-preset", "block-secrets"])
        assert ret == EXIT_BLOCKED
        captured = capsys.readouterr()
        assert "Detections : 1" in captured.out
        assert "Action     : block" in captured.out
        assert "Redacted   : no" in captured.out
        assert self.SYNTHETIC_KEY not in captured.out

    def test_scan_secret_text_warn_preset(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warn preset returns EXIT_SUCCESS (0); traffic allowed with warning."""
        text = f"Key {self.SYNTHETIC_KEY}"
        ret = main(["scan", text, "--policy-preset", "warn-secrets"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Detections : 1" in captured.out
        assert "Action     : warn" in captured.out
        assert "Redacted   : no" in captured.out
        assert self.SYNTHETIC_KEY not in captured.out

    def test_scan_json_output_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--json produces valid, privacy-safe JSON without raw secrets."""
        text = f"My secret is {self.SYNTHETIC_KEY}"
        ret = main(["scan", text, "--json"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()

        data = json.loads(captured.out)
        assert data["action"] == "redact"
        assert data["detection_count"] == 1
        assert data["redacted"] is True
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["category"] == "secret"
        assert finding["severity"] == "high"
        assert "rule_id" in finding
        assert "[REDACTED_SECRET]" in data["transformed_content"]

        # Ensure raw secret is NOT anywhere in the json payload
        assert self.SYNTHETIC_KEY not in captured.out

    def test_scan_from_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scanning text from a file with -f/--file."""
        test_file = tmp_path / "prompt.txt"
        test_file.write_text(f"Token: {self.SYNTHETIC_KEY}", encoding="utf-8")

        ret = main(["scan", "-f", str(test_file)])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Detections : 1" in captured.out
        assert "[REDACTED_SECRET]" in captured.out
        assert self.SYNTHETIC_KEY not in captured.out

    def test_scan_file_not_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Non-existent file reports a clear error without stack trace."""
        ret = main(["scan", "-f", "non_existent_file_path_12345.txt"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Error: File not found" in captured.err
        assert "Traceback" not in captured.err

    def test_scan_stdin(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Scanning text from '-' reads stdin."""
        monkeypatch.setattr(
            "sys.stdin", StringIO(f"Piped input with {self.SYNTHETIC_KEY}")
        )
        ret = main(["scan", "-"])
        assert ret == EXIT_SUCCESS
        captured = capsys.readouterr()
        assert "Detections : 1" in captured.out
        assert "[REDACTED_SECRET]" in captured.out

    def test_scan_no_text_provided(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Missing input text returns clear error."""
        ret = main(["scan"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Error: No text provided" in captured.err


class TestCLIStart:
    """Tests for 'aifirewall start' proxy startup command."""

    def test_start_missing_upstream_returns_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Missing upstream target returns configuration error."""
        ret = main(["start"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Configuration error: Missing required upstream target" in captured.err
        assert "Traceback" not in captured.err

    def test_start_invalid_port_returns_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invalid port number returns clean configuration error."""
        ret = main(["start", "--upstream", "http://127.0.0.1:11434", "--port", "70000"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "port must be between 1 and 65535" in captured.err

    def test_start_invalid_upstream_scheme(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Non-http/https upstream scheme is rejected."""
        ret = main(["start", "--upstream", "ftp://127.0.0.1:11434"])
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Unsupported upstream_url scheme" in captured.err

    def test_start_unsupported_provider(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Invalid provider name returns clean configuration error."""
        ret = main(
            ["start", "--upstream", "http://127.0.0.1:11434", "--provider", "cohere"]
        )
        assert ret == EXIT_USAGE_ERROR
        captured = capsys.readouterr()
        assert "Unsupported provider: 'cohere'" in captured.err

    def test_start_clean_keyboard_interrupt_shutdown(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Ctrl+C (KeyboardInterrupt) triggers clean shutdown with exit 0."""
        with patch("aifirewall.cli.FirewallProxy.run", side_effect=KeyboardInterrupt):
            ret = main(
                [
                    "start",
                    "--upstream",
                    "http://127.0.0.1:11434",
                    "--provider",
                    "ollama",
                ]
            )
            assert ret == EXIT_SUCCESS
            captured = capsys.readouterr()
            assert "Shutting down AI Data Firewall gracefully..." in captured.out
            assert "Traceback" not in captured.err

    def test_start_oserror_bind_conflict(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Socket bind failure returns clean error message."""
        with patch(
            "aifirewall.cli.FirewallProxy.run",
            side_effect=OSError(10048, "Address already in use"),
        ):
            ret = main(["start", "--upstream", "http://127.0.0.1:11434"])
            assert ret == EXIT_ERROR
            captured = capsys.readouterr()
            assert "Startup error: Unable to bind" in captured.err
            assert "Traceback" not in captured.err
