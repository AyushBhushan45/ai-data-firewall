"""Tests for AI Data Firewall configuration loading and precedence.

Validates:
- Loading valid TOML and JSON config files
- Malformed TOML and JSON error handling
- Unsupported config formats
- Deterministic configuration precedence:
    CLI arguments > Environment variables > Config file > Defaults
- Policy presets and custom rule parsing
"""

import json
from pathlib import Path

import pytest

from aifirewall.config import (
    PRESET_BLOCK_SECRETS,
    PRESET_REDACT_SECRETS,
    PRESET_WARN_SECRETS,
    build_firewall_config,
    create_preset_policy,
    load_config_file,
    parse_policy_rule_from_dict,
)
from aifirewall.core.errors import ConfigurationError
from aifirewall.core.types import PolicyAction, Severity


class TestConfigFileLoading:
    """Tests for loading TOML and JSON configuration files."""

    def test_load_valid_toml(self, tmp_path: Path) -> None:
        """Loading a valid TOML configuration file."""
        cfg_path = tmp_path / "firewall.toml"
        cfg_path.write_text(
            """
            [proxy]
            host = "127.0.0.1"
            port = 9000
            upstream_url = "http://127.0.0.1:11434"
            provider = "ollama"

            [policy]
            default_action = "allow"
            preset = "redact-secrets"
            """,
            encoding="utf-8",
        )
        data = load_config_file(cfg_path)
        assert data["proxy"]["port"] == 9000
        assert data["proxy"]["provider"] == "ollama"
        assert data["policy"]["preset"] == "redact-secrets"

    def test_load_valid_json(self, tmp_path: Path) -> None:
        """Loading a valid JSON configuration file."""
        cfg_path = tmp_path / "firewall.json"
        content = {
            "proxy": {
                "host": "127.0.0.1",
                "port": 9001,
                "upstream_url": "https://api.openai.com",
                "provider": "openai",
            },
            "policy": {
                "default_action": "warn",
            },
        }
        cfg_path.write_text(json.dumps(content), encoding="utf-8")
        data = load_config_file(cfg_path)
        assert data["proxy"]["port"] == 9001
        assert data["proxy"]["provider"] == "openai"
        assert data["policy"]["default_action"] == "warn"

    def test_load_nonexistent_file_raises_error(self) -> None:
        """Missing configuration file raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="Configuration file not found"):
            load_config_file("nonexistent_path_to_config.toml")

    def test_load_malformed_toml_raises_error(self, tmp_path: Path) -> None:
        """Malformed TOML syntax raises ConfigurationError."""
        cfg_path = tmp_path / "invalid.toml"
        cfg_path.write_text("invalid = = = toml", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="Malformed TOML"):
            load_config_file(cfg_path)

    def test_load_malformed_json_raises_error(self, tmp_path: Path) -> None:
        """Malformed JSON syntax raises ConfigurationError."""
        cfg_path = tmp_path / "invalid.json"
        cfg_path.write_text("{bad json syntax,", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="Malformed JSON"):
            load_config_file(cfg_path)

    def test_load_unsupported_format_raises_error(self, tmp_path: Path) -> None:
        """Unsupported file extensions (.yaml, .ini, etc.) raise ConfigurationError."""
        cfg_path = tmp_path / "config.yaml"
        cfg_path.write_text("proxy:\n  port: 8080\n", encoding="utf-8")
        with pytest.raises(
            ConfigurationError, match="Unsupported configuration format"
        ):
            load_config_file(cfg_path)


class TestConfigPrecedence:
    """Tests deterministic hierarchy: CLI > Env > File > Defaults."""

    def test_cli_overrides_env_and_file(self, tmp_path: Path) -> None:
        """CLI arguments take highest precedence over environment and file."""
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text(
            """
            [proxy]
            upstream_url = "http://127.0.0.1:11434"
            port = 8080
            provider = "ollama"
            """,
            encoding="utf-8",
        )

        env = {
            "AIFIREWALL_PORT": "8081",
            "AIFIREWALL_PROVIDER": "anthropic",
        }

        cli_args = {
            "config": str(cfg_file),
            "port": 9090,
            "provider": "openai",
        }

        fw_cfg = build_firewall_config(cli_args=cli_args, env=env)
        # Port from CLI (9090), provider from CLI (openai), upstream from file
        assert fw_cfg.proxy.port == 9090
        assert fw_cfg.proxy.provider == "openai"
        assert fw_cfg.proxy.upstream_url == "http://127.0.0.1:11434"

    def test_env_overrides_file_and_defaults(self, tmp_path: Path) -> None:
        """Environment variables override config file and defaults."""
        cfg_file = tmp_path / "config.json"
        cfg_file.write_text(
            json.dumps(
                {
                    "proxy": {
                        "upstream_url": "http://127.0.0.1:11434",
                        "port": 8080,
                    }
                }
            ),
            encoding="utf-8",
        )

        env = {
            "AIFIREWALL_PORT": "8888",
            "AIFIREWALL_PROVIDER": "gemini",
        }

        cli_args = {"config": str(cfg_file)}

        fw_cfg = build_firewall_config(cli_args=cli_args, env=env)
        assert fw_cfg.proxy.port == 8888
        assert fw_cfg.proxy.provider == "gemini"
        assert fw_cfg.proxy.upstream_url == "http://127.0.0.1:11434"

    def test_defaults_applied_when_unspecified(self) -> None:
        """Safe defaults (127.0.0.1:8080) are used when not overridden."""
        cli_args = {"upstream": "http://127.0.0.1:11434"}
        fw_cfg = build_firewall_config(cli_args=cli_args, env={})
        assert fw_cfg.proxy.host == "127.0.0.1"
        assert fw_cfg.proxy.port == 8080
        assert fw_cfg.proxy.provider is None
        assert fw_cfg.policy.default_action == PolicyAction.ALLOW


class TestPolicyParsing:
    """Tests policy rule parsing and preset generation."""

    def test_create_preset_policies(self) -> None:
        """Known presets create expected PolicyConfig."""
        redact_cfg = create_preset_policy(PRESET_REDACT_SECRETS)
        assert len(redact_cfg.rules) == 1
        assert redact_cfg.rules[0].action == PolicyAction.REDACT

        block_cfg = create_preset_policy(PRESET_BLOCK_SECRETS)
        assert len(block_cfg.rules) == 1
        assert block_cfg.rules[0].action == PolicyAction.BLOCK

        warn_cfg = create_preset_policy(PRESET_WARN_SECRETS)
        assert len(warn_cfg.rules) == 1
        assert warn_cfg.rules[0].action == PolicyAction.WARN

    def test_unknown_preset_raises_error(self) -> None:
        """Unknown preset raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="Unknown policy preset"):
            create_preset_policy("aggressive-destroy")

    def test_custom_rule_parsing_from_dict(self) -> None:
        """Parsing valid custom rule from dict."""
        data = {
            "rule_id": "rule-block-critical",
            "action": "block",
            "category": "secret",
            "minimum_severity": "critical",
            "minimum_confidence": 0.85,
            "description": "Block critical secrets",
        }
        rule = parse_policy_rule_from_dict(data)
        assert rule.rule_id == "rule-block-critical"
        assert rule.action == PolicyAction.BLOCK
        assert rule.minimum_severity == Severity.CRITICAL
        assert rule.minimum_confidence == 0.85
