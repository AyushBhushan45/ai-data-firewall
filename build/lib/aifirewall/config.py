"""Configuration management for AI Data Firewall.

Handles loading, merging, and validating configuration across:
1. CLI arguments (highest precedence)
2. Environment variables
3. Configuration files (.toml, .json)
4. Safe defaults (lowest precedence)

No external libraries are used for configuration parsing; standard library
`tomllib` and `json` are strictly utilized to prevent dependency creep and
arbitrary code execution.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aifirewall.core.errors import ConfigurationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    DetectionCategory,
    PolicyAction,
    Severity,
)
from aifirewall.policy.models import PolicyConfig, PolicyRule
from aifirewall.proxy.config import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_HOST,
    DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_PORT,
    DEFAULT_READ_TIMEOUT,
    DEFAULT_TOTAL_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT,
    ProxyConfig,
)

ENV_PREFIX = "AIFIREWALL_"
ENV_UPSTREAM = f"{ENV_PREFIX}UPSTREAM"
ENV_PROVIDER = f"{ENV_PREFIX}PROVIDER"
ENV_HOST = f"{ENV_PREFIX}HOST"
ENV_PORT = f"{ENV_PREFIX}PORT"
ENV_CONFIG = f"{ENV_PREFIX}CONFIG"
ENV_POLICY_PRESET = f"{ENV_PREFIX}POLICY_PRESET"

PRESET_REDACT_SECRETS = "redact-secrets"
PRESET_BLOCK_SECRETS = "block-secrets"
PRESET_WARN_SECRETS = "warn-secrets"
PRESET_ALLOW_ALL = "allow-all"

SUPPORTED_PRESETS: frozenset[str] = frozenset(
    {
        PRESET_REDACT_SECRETS,
        PRESET_BLOCK_SECRETS,
        PRESET_WARN_SECRETS,
        PRESET_ALLOW_ALL,
    }
)


def create_preset_policy(preset_name: str) -> PolicyConfig:
    """Create a PolicyConfig instance from a known preset name.

    Args:
        preset_name: Name of the policy preset.

    Returns:
        Configured PolicyConfig.

    Raises:
        ConfigurationError: If preset_name is unknown.
    """
    clean_name = preset_name.strip().lower()
    if clean_name == PRESET_REDACT_SECRETS:
        return PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="preset-redact-secrets",
                    action=PolicyAction.REDACT,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                    description="Redact detected secrets with confidence >= 0.5",
                )
            ],
            default_action=PolicyAction.ALLOW,
        )
    elif clean_name == PRESET_BLOCK_SECRETS:
        return PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="preset-block-secrets",
                    action=PolicyAction.BLOCK,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                    description="Block requests and responses with secrets",
                )
            ],
            default_action=PolicyAction.ALLOW,
        )
    elif clean_name == PRESET_WARN_SECRETS:
        return PolicyConfig(
            rules=[
                PolicyRule(
                    rule_id="preset-warn-secrets",
                    action=PolicyAction.WARN,
                    category=DetectionCategory.SECRET,
                    minimum_confidence=0.5,
                    description="Warn on detected secrets with confidence >= 0.5",
                )
            ],
            default_action=PolicyAction.ALLOW,
        )
    elif clean_name == PRESET_ALLOW_ALL:
        return PolicyConfig(
            rules=[],
            default_action=PolicyAction.ALLOW,
        )
    else:
        supported = ", ".join(repr(p) for p in sorted(SUPPORTED_PRESETS))
        raise ConfigurationError(
            f"Unknown policy preset: {preset_name!r}. Supported presets: [{supported}]"
        )


def parse_policy_rule_from_dict(data: dict[str, Any], index: int = 0) -> PolicyRule:
    """Safely parse a single PolicyRule from a dictionary.

    Args:
        data: Dictionary containing policy rule fields.
        index: Rule index for clear error messages.

    Returns:
        Validated PolicyRule instance.

    Raises:
        ConfigurationError: If rule definition is invalid.
    """
    if not isinstance(data, dict):
        raise ConfigurationError(
            f"Policy rule at index {index} must be a dictionary/mapping"
        )

    rule_id = data.get("rule_id")
    if not rule_id or not isinstance(rule_id, str):
        raise ConfigurationError(
            f"Policy rule at index {index} is missing a valid 'rule_id' string"
        )

    action_val = data.get("action")
    if not action_val or not isinstance(action_val, str):
        raise ConfigurationError(
            f"Policy rule {rule_id!r} is missing a valid 'action' string "
            "(allow, warn, redact, block)"
        )
    try:
        action = PolicyAction(action_val.strip().lower())
    except ValueError as err:
        raise ConfigurationError(
            f"Policy rule {rule_id!r} has invalid action {action_val!r}"
        ) from err

    # Optional fields
    category: DetectionCategory | None = None
    if "category" in data and data["category"] is not None:
        cat_str = str(data["category"]).strip().lower()
        try:
            category = DetectionCategory(cat_str)
        except ValueError as err:
            raise ConfigurationError(
                f"Policy rule {rule_id!r} has invalid category {data['category']!r}"
            ) from err

    minimum_severity: Severity | None = None
    if "minimum_severity" in data and data["minimum_severity"] is not None:
        sev_str = str(data["minimum_severity"]).strip().lower()
        try:
            minimum_severity = Severity(sev_str)
        except ValueError as err:
            raise ConfigurationError(
                f"Policy rule {rule_id!r} has invalid minimum_severity "
                f"{data['minimum_severity']!r}"
            ) from err

    minimum_confidence: float | None = None
    if "minimum_confidence" in data and data["minimum_confidence"] is not None:
        try:
            minimum_confidence = float(data["minimum_confidence"])
            if not (0.0 <= minimum_confidence <= 1.0):
                raise ValueError("Out of range [0.0, 1.0]")
        except (ValueError, TypeError) as err:
            raise ConfigurationError(
                f"Policy rule {rule_id!r} minimum_confidence must be "
                "a float between 0.0 and 1.0"
            ) from err

    source: ContentSource | None = None
    if "source" in data and data["source"] is not None:
        try:
            source = ContentSource(str(data["source"]).strip().lower())
        except ValueError as err:
            raise ConfigurationError(
                f"Policy rule {rule_id!r} has invalid source {data['source']!r}"
            ) from err

    direction: ContentDirection | None = None
    if "direction" in data and data["direction"] is not None:
        try:
            direction = ContentDirection(str(data["direction"]).strip().lower())
        except ValueError as err:
            raise ConfigurationError(
                f"Policy rule {rule_id!r} has invalid direction {data['direction']!r}"
            ) from err

    description = str(data.get("description", ""))
    detector_name = (
        str(data["detector_name"]).strip()
        if data.get("detector_name") is not None
        else None
    )
    enabled = bool(data.get("enabled", True))
    priority = int(data.get("priority", 100))

    return PolicyRule(
        rule_id=rule_id.strip(),
        action=action,
        description=description,
        category=category,
        minimum_severity=minimum_severity,
        minimum_confidence=minimum_confidence,
        detector_name=detector_name,
        source=source,
        direction=direction,
        enabled=enabled,
        priority=priority,
    )


def load_config_file(path: str | Path) -> dict[str, Any]:
    """Safely load configuration from a TOML or JSON file.

    Args:
        path: Path to .toml or .json file.

    Returns:
        Parsed configuration dictionary.

    Raises:
        ConfigurationError: If file not found, unreadable, or syntactically invalid.
    """
    file_path = Path(path).resolve()
    if not file_path.exists():
        raise ConfigurationError(f"Configuration file not found: {file_path}")
    if not file_path.is_file():
        raise ConfigurationError(f"Configuration path is not a file: {file_path}")

    suffix = file_path.suffix.lower()
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except Exception as err:
        raise ConfigurationError(
            f"Failed to read configuration file {file_path.name}: {err}"
        ) from err

    if suffix == ".toml":
        try:
            return tomllib.loads(raw_text)
        except Exception as err:
            raise ConfigurationError(
                f"Malformed TOML configuration in {file_path.name}: {err}"
            ) from err
    elif suffix == ".json":
        try:
            parsed = json.loads(raw_text)
            if not isinstance(parsed, dict):
                raise ConfigurationError(
                    f"JSON configuration root must be an object/dict in "
                    f"{file_path.name}"
                )
            return parsed
        except json.JSONDecodeError as err:
            raise ConfigurationError(
                f"Malformed JSON configuration in {file_path.name}: {err}"
            ) from err
    else:
        raise ConfigurationError(
            f"Unsupported configuration format {suffix!r} in {file_path.name}. "
            "Supported formats: .toml, .json"
        )


@dataclass(frozen=True)
class FirewallConfig:
    """Combined configuration holding proxy and policy settings."""

    proxy: ProxyConfig
    policy: PolicyConfig


def build_firewall_config(
    cli_args: dict[str, Any] | None = None,
    env: dict[str, str] | None = None,
    config_file_path: str | Path | None = None,
) -> FirewallConfig:
    """Build a unified, validated FirewallConfig resolving precedence.

    Precedence order:
    1. CLI arguments (highest)
    2. Environment variables
    3. Configuration file (.toml / .json)
    4. Safe defaults (lowest)

    Args:
        cli_args: Dict of arguments passed on CLI (None values are ignored).
        env: Environment dict (defaults to os.environ).
        config_file_path: Optional explicit configuration file path.

    Returns:
        Unified FirewallConfig with validated ProxyConfig and PolicyConfig.

    Raises:
        ConfigurationError: If any configuration value is invalid or required
            upstream URL is missing.
    """
    args = cli_args or {}
    environment = env if env is not None else dict(os.environ)

    # 1. Determine config file path (CLI > Env > Explicit argument)
    resolved_config_path: str | Path | None = None
    if args.get("config"):
        resolved_config_path = args["config"]
    elif environment.get(ENV_CONFIG):
        resolved_config_path = environment[ENV_CONFIG]
    elif config_file_path:
        resolved_config_path = config_file_path

    file_data: dict[str, Any] = {}
    if resolved_config_path:
        file_data = load_config_file(resolved_config_path)

    # Extract sub-tables if present, otherwise allow top-level keys
    raw_proxy = file_data.get("proxy")
    proxy_file_data: dict[str, Any] = raw_proxy if isinstance(raw_proxy, dict) else {}

    raw_policy = file_data.get("policy")
    policy_file_data: dict[str, Any] = (
        raw_policy if isinstance(raw_policy, dict) else {}
    )

    # Helper to resolve single value by precedence
    def get_val(key: str, env_key: str | None, default: Any = None) -> Any:
        # CLI
        if args.get(key) is not None:
            return args[key]
        # Env
        if env_key and environment.get(env_key) is not None:
            val = environment[env_key].strip()
            if val:
                return val
        # File (check proxy sub-table first, then top-level)
        if key in proxy_file_data and proxy_file_data[key] is not None:
            return proxy_file_data[key]
        if key in file_data and file_data[key] is not None:
            return file_data[key]
        # Default
        return default

    # 2. Resolve Proxy Configuration
    upstream_url = get_val("upstream", ENV_UPSTREAM)
    if not upstream_url:
        # Check alias upstream_url
        upstream_url = get_val("upstream_url", ENV_UPSTREAM)

    if not upstream_url:
        raise ConfigurationError(
            "Missing required upstream target. Specify via --upstream, "
            f"{ENV_UPSTREAM} environment variable, or 'upstream_url' in config file."
        )

    host = str(get_val("host", ENV_HOST, DEFAULT_HOST))

    raw_port = get_val("port", ENV_PORT, DEFAULT_PORT)
    try:
        port = int(raw_port)
    except (ValueError, TypeError) as err:
        raise ConfigurationError(f"Invalid port number: {raw_port!r}") from err

    provider = get_val("provider", ENV_PROVIDER, None)
    if provider is not None:
        provider = str(provider).strip().lower()
        if not provider:
            provider = None

    connect_timeout = float(get_val("connect_timeout", None, DEFAULT_CONNECT_TIMEOUT))
    read_timeout = float(get_val("read_timeout", None, DEFAULT_READ_TIMEOUT))
    write_timeout = float(get_val("write_timeout", None, DEFAULT_WRITE_TIMEOUT))
    total_timeout = float(get_val("total_timeout", None, DEFAULT_TOTAL_TIMEOUT))

    max_request_bytes = int(
        get_val("max_request_body_bytes", None, DEFAULT_MAX_REQUEST_BODY_BYTES)
    )
    max_response_bytes = int(
        get_val("max_response_body_bytes", None, DEFAULT_MAX_RESPONSE_BODY_BYTES)
    )

    proxy_config = ProxyConfig(
        upstream_url=str(upstream_url),
        host=host,
        port=port,
        provider=provider,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        write_timeout=write_timeout,
        total_timeout=total_timeout,
        max_request_body_bytes=max_request_bytes,
        max_response_body_bytes=max_response_bytes,
    )

    # 3. Resolve Policy Configuration
    preset = args.get("policy_preset")
    if not preset and environment.get(ENV_POLICY_PRESET):
        preset = environment[ENV_POLICY_PRESET]
    if not preset and "preset" in policy_file_data:
        preset = policy_file_data["preset"]

    policy_rules: list[PolicyRule] = []
    default_action = PolicyAction.ALLOW

    if preset:
        preset_cfg = create_preset_policy(str(preset))
        policy_rules.extend(preset_cfg.rules)
        default_action = preset_cfg.default_action

    # Check for custom rules defined in config file
    if "default_action" in policy_file_data:
        try:
            default_action = PolicyAction(
                str(policy_file_data["default_action"]).strip().lower()
            )
        except ValueError as err:
            raise ConfigurationError(
                "Invalid default_action in policy config: "
                f"{policy_file_data['default_action']!r}"
            ) from err

    custom_rules_data = policy_file_data.get("rules")
    if custom_rules_data and isinstance(custom_rules_data, list):
        for idx, rule_dict in enumerate(custom_rules_data):
            rule = parse_policy_rule_from_dict(rule_dict, index=idx)
            policy_rules.append(rule)

    policy_config = PolicyConfig(
        rules=policy_rules,
        default_action=default_action,
    )

    return FirewallConfig(proxy=proxy_config, policy=policy_config)
