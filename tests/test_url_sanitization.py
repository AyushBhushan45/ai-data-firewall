"""Tests for URL sanitization and privacy-safe URL display."""

from __future__ import annotations

from aifirewall.core.utils import sanitize_url_for_display


class TestUrlSanitization:
    """Validate that sensitive credentials and tokens are scrubbed from URLs."""

    def test_empty_or_none_url(self) -> None:
        assert sanitize_url_for_display("") == ""
        assert sanitize_url_for_display(None) == ""  # type: ignore[arg-type]
        assert sanitize_url_for_display("   ") == ""

    def test_clean_urls_preserved(self) -> None:
        assert (
            sanitize_url_for_display("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
        )
        assert (
            sanitize_url_for_display("https://api.openai.com/v1/chat/completions")
            == "https://api.openai.com/v1/chat/completions"
        )
        assert (
            sanitize_url_for_display("http://localhost:11434/api/chat?model=llama3")
            == "http://localhost:11434/api/chat?model=llama3"
        )

    def test_userinfo_credentials_scrubbed(self) -> None:
        url_with_creds = "http://admin:super_secret_pwd@127.0.0.1:11434"
        sanitized = sanitize_url_for_display(url_with_creds)
        assert "super_secret_pwd" not in sanitized
        assert "admin" not in sanitized
        assert sanitized == "http://[REDACTED]@127.0.0.1:11434"

    def test_userinfo_without_password_scrubbed(self) -> None:
        url_with_user = "http://myuser@example.com:9000/v1"
        sanitized = sanitize_url_for_display(url_with_user)
        assert "myuser" not in sanitized
        assert sanitized == "http://[REDACTED]@example.com:9000/v1"

    def test_sensitive_query_parameters_scrubbed(self) -> None:
        url = (
            "https://example.com/v1?api_key=sk-1234567890abcdef&model=gpt-4o&client=sdk"
        )
        sanitized = sanitize_url_for_display(url)
        assert "sk-1234567890abcdef" not in sanitized
        assert "api_key=[REDACTED]" in sanitized
        assert "model=gpt-4o" in sanitized
        assert "client=sdk" in sanitized

    def test_various_sensitive_parameter_names(self) -> None:
        url = (
            "https://example.com/api?access_token=token123"
            "&user_secret=sec456&auth=auth789&password=p1"
            "&safe_param=hello"
        )
        sanitized = sanitize_url_for_display(url)
        assert "token123" not in sanitized
        assert "sec456" not in sanitized
        assert "auth789" not in sanitized
        assert "p1" not in sanitized
        assert "access_token=[REDACTED]" in sanitized
        assert "user_secret=[REDACTED]" in sanitized
        assert "auth=[REDACTED]" in sanitized
        assert "password=[REDACTED]" in sanitized
        assert "safe_param=hello" in sanitized

    def test_secret_pattern_in_value_scrubbed_even_with_benign_key(self) -> None:
        url = "https://example.com/api?q=sk-proj-1234567890123456789012345678"
        sanitized = sanitize_url_for_display(url)
        assert "sk-proj-1234567890" not in sanitized
        assert "q=[REDACTED]" in sanitized

    def test_both_userinfo_and_query_secrets_scrubbed(self) -> None:
        url = "http://user:pass@127.0.0.1:8080/v1?token=secret123&foo=bar"
        sanitized = sanitize_url_for_display(url)
        assert "user" not in sanitized
        assert "pass" not in sanitized
        assert "secret123" not in sanitized
        assert (
            sanitized == "http://[REDACTED]@127.0.0.1:8080/v1?token=[REDACTED]&foo=bar"
        )
