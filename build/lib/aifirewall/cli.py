"""Command-line interface for AI Data Firewall.

Provides user-facing CLI subcommands:
- `aifirewall start`: Launch the local HTTP reverse proxy with safe defaults.
- `aifirewall scan`: Offline test scan through the detection & policy pipeline.
- `aifirewall providers`: List registered provider adapters without network calls.
- `aifirewall --version`: Display single source-of-truth package version.

Strict Privacy Guarantee:
Under no circumstances are raw secrets, authorization headers, or sensitive
credentials printed, logged, or serialized to standard output/error.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from aifirewall import __version__
from aifirewall.config import (
    PRESET_REDACT_SECRETS,
    SUPPORTED_PRESETS,
    FirewallConfig,
    build_firewall_config,
    create_preset_policy,
    load_config_file,
    parse_policy_rule_from_dict,
)
from aifirewall.core.errors import ConfigurationError
from aifirewall.core.types import (
    ContentDirection,
    ContentSource,
    PolicyAction,
)
from aifirewall.detectors.base import DetectorContext
from aifirewall.detectors.secret import SecretDetector
from aifirewall.policy.engine import PolicyEngine
from aifirewall.policy.models import PolicyConfig, PolicyContext, PolicyRule
from aifirewall.providers.registry import create_default_registry
from aifirewall.proxy.pipeline import SecurityPipeline
from aifirewall.proxy.server import FirewallProxy
from aifirewall.transformation.redaction import RedactionEngine

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_USAGE_ERROR = 2
EXIT_BLOCKED = 3


def _build_parser() -> argparse.ArgumentParser:
    """Construct standard library argparse CLI parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="aifirewall",
        description=(
            "AI Data Firewall: An open-source, local-first security layer "
            "for AI applications."
        ),
    )
    parser.add_argument(
        "-v",
        "-V",
        "--version",
        action="version",
        version=f"aifirewall {__version__}",
        help="Show program's version number and exit.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available CLI subcommands",
    )

    # 1. 'start' subcommand
    start_parser = subparsers.add_parser(
        "start",
        help="Start the local AI Data Firewall reverse proxy.",
        description="Launch local proxy forwarding to a fixed upstream AI target.",
    )
    start_parser.add_argument(
        "-u",
        "--upstream",
        type=str,
        default=None,
        help="Fixed upstream AI target URL (e.g. http://127.0.0.1:11434).",
    )
    start_parser.add_argument(
        "-p",
        "--provider",
        type=str,
        default=None,
        help="Provider adapter name: openai, anthropic, gemini, or ollama.",
    )
    start_parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Local network interface to bind (default: 127.0.0.1).",
    )
    start_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Local port to bind (default: 8080).",
    )
    start_parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to configuration file (.toml or .json).",
    )
    start_parser.add_argument(
        "--policy-preset",
        type=str,
        default=None,
        choices=sorted(SUPPORTED_PRESETS),
        help="Security policy preset: redact-secrets, block-secrets, warn-secrets.",
    )
    start_parser.add_argument(
        "--timeout",
        dest="total_timeout",
        type=float,
        default=None,
        help="Upstream total timeout in seconds (default: 60.0).",
    )
    start_parser.add_argument(
        "--max-request-bytes",
        dest="max_request_body_bytes",
        type=int,
        default=None,
        help="Maximum request body size in bytes (default: 5MB).",
    )
    start_parser.add_argument(
        "--max-response-bytes",
        dest="max_response_body_bytes",
        type=int,
        default=None,
        help="Maximum response body size in bytes (default: 10MB).",
    )

    # 2. 'scan' subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run an offline security scan on text or a file.",
        description="Inspect text using detection and policy without proxy.",
    )
    scan_parser.add_argument(
        "text",
        nargs="?",
        default=None,
        help="Text string to scan. Use '-' to read from standard input.",
    )
    scan_parser.add_argument(
        "-t",
        "--text",
        dest="flag_text",
        type=str,
        default=None,
        help="Explicit text string to scan.",
    )
    scan_parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=None,
        help="Path to file whose content should be scanned.",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable, privacy-safe JSON results.",
    )
    scan_parser.add_argument(
        "--policy-preset",
        type=str,
        default=PRESET_REDACT_SECRETS,
        choices=sorted(SUPPORTED_PRESETS),
        help="Policy preset for evaluation (default: redact-secrets).",
    )
    scan_parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to configuration file (.toml or .json) containing custom rules.",
    )

    # 3. 'providers' subcommand
    subparsers.add_parser(
        "providers",
        help="List supported provider adapters offline.",
        description="Print all registered AI provider normalization adapters.",
    )

    return parser


def run_start(args: argparse.Namespace) -> int:
    """Execute proxy startup.

    Converts CLI arguments into typed configuration and starts FirewallProxy.
    """
    cli_dict = {
        "upstream": args.upstream,
        "provider": args.provider,
        "host": args.host,
        "port": args.port,
        "config": args.config,
        "policy_preset": args.policy_preset,
        "total_timeout": args.total_timeout,
        "max_request_body_bytes": args.max_request_body_bytes,
        "max_response_body_bytes": args.max_response_body_bytes,
    }
    # Filter out None values to let lower precedence layers apply
    filtered_cli = {k: v for k, v in cli_dict.items() if v is not None}

    try:
        fw_config: FirewallConfig = build_firewall_config(cli_args=filtered_cli)
    except ConfigurationError as err:
        sys.stderr.write(f"Configuration error: {err}\n")
        return EXIT_USAGE_ERROR

    proxy_cfg = fw_config.proxy
    policy_cfg = fw_config.policy

    # Initialize SecurityPipeline
    pipeline = SecurityPipeline(
        config=proxy_cfg,
        policy_engine=PolicyEngine(policy_cfg),
    )

    # Initialize FirewallProxy
    proxy = FirewallProxy(config=proxy_cfg, pipeline=pipeline)

    provider_label = proxy_cfg.provider or "generic/passthrough"
    rule_count = len(policy_cfg.rules)
    policy_info = f"{rule_count} rule(s) (Default: {policy_cfg.default_action.value})"

    sys.stdout.write("==================================================\n")
    sys.stdout.write(f"AI Data Firewall v{__version__}\n")
    sys.stdout.write("==================================================\n")
    sys.stdout.write(f"Proxy Address   : http://{proxy_cfg.host}:{proxy_cfg.port}\n")
    sys.stdout.write(f"Upstream Target : {proxy_cfg.upstream_url}\n")
    sys.stdout.write(f"Provider Adapter: {provider_label}\n")
    sys.stdout.write(f"Active Policy   : {policy_info}\n")
    sys.stdout.write("Health Check    : GET /health\n")
    sys.stdout.write("Status          : Running. Press Ctrl+C to terminate cleanly.\n")
    sys.stdout.write("==================================================\n")
    sys.stdout.flush()

    try:
        proxy.run()
    except KeyboardInterrupt:
        sys.stdout.write("\nShutting down AI Data Firewall gracefully...\n")
        sys.stdout.flush()
        return EXIT_SUCCESS
    except OSError as err:
        sys.stderr.write(
            f"Startup error: Unable to bind to "
            f"{proxy_cfg.host}:{proxy_cfg.port} ({err}).\n"
        )
        return EXIT_ERROR
    except Exception as err:
        sys.stderr.write(f"Proxy execution error: {err}\n")
        return EXIT_ERROR

    return EXIT_SUCCESS


def run_scan(args: argparse.Namespace) -> int:
    """Execute offline security scan on input text.

    Guarantees privacy safety: detected raw secrets are NEVER printed.
    """
    raw_text: str | None = None

    if args.flag_text is not None:
        raw_text = args.flag_text
    elif args.file is not None:
        file_path = Path(args.file)
        if not file_path.exists():
            sys.stderr.write(f"Error: File not found: {file_path}\n")
            return EXIT_USAGE_ERROR
        try:
            raw_text = file_path.read_text(encoding="utf-8")
        except Exception as err:
            sys.stderr.write(f"Error reading file {file_path}: {err}\n")
            return EXIT_USAGE_ERROR
    elif args.text is not None:
        if args.text == "-":
            try:
                raw_text = sys.stdin.read()
            except Exception as err:
                sys.stderr.write(f"Error reading stdin: {err}\n")
                return EXIT_USAGE_ERROR
        else:
            raw_text = args.text

    if raw_text is None:
        sys.stderr.write(
            "Error: No text provided to scan. Pass text as argument or via -t/-f.\n"
        )
        return EXIT_USAGE_ERROR

    # Build policy
    policy_config: PolicyConfig
    if args.config:
        try:
            file_data = load_config_file(args.config)
            policy_data = file_data.get("policy", {})
            rules: list[PolicyRule] = []
            default_action = PolicyAction.ALLOW
            preset_name = policy_data.get("preset") or args.policy_preset
            if preset_name:
                p_cfg = create_preset_policy(preset_name)
                rules.extend(p_cfg.rules)
                default_action = p_cfg.default_action
            if "default_action" in policy_data:
                default_action = PolicyAction(
                    str(policy_data["default_action"]).strip().lower()
                )
            if "rules" in policy_data and isinstance(policy_data["rules"], list):
                for idx, r_dict in enumerate(policy_data["rules"]):
                    rules.append(parse_policy_rule_from_dict(r_dict, index=idx))
            policy_config = PolicyConfig(rules=rules, default_action=default_action)
        except ConfigurationError as err:
            sys.stderr.write(f"Configuration error: {err}\n")
            return EXIT_USAGE_ERROR
    else:
        try:
            policy_config = create_preset_policy(args.policy_preset)
        except ConfigurationError as err:
            sys.stderr.write(f"Configuration error: {err}\n")
            return EXIT_USAGE_ERROR

    # Run detection
    detector = SecretDetector()
    context = DetectorContext(
        request_id="cli_scan",
        direction=ContentDirection.REQUEST,
        source=ContentSource.USER,
    )
    findings = detector.detect(raw_text, context)

    # Evaluate policy
    policy_engine = PolicyEngine(policy_config)
    decision = policy_engine.evaluate(
        detections=findings,
        context=PolicyContext(
            direction=ContentDirection.REQUEST,
            source=ContentSource.USER,
        ),
    )

    action = decision.action
    is_redacted = False
    transformed_text: str | None = None

    if action == PolicyAction.REDACT and findings:
        redactor = RedactionEngine()
        redaction_res = redactor.redact(
            content=raw_text, detections=findings, decision=decision
        )
        transformed_text = redaction_res.content
        is_redacted = True

    # Build safe findings list (zero raw secret values)
    def _format_val(val: object) -> str:
        return str(getattr(val, "value", val))

    safe_findings = [
        {
            "category": _format_val(f.category),
            "severity": _format_val(f.severity),
            "confidence": round(f.confidence, 4),
            "detector_name": f.detector_name,
            "rule_id": decision.matched_rules[0] if decision.matched_rules else None,
        }
        for f in findings
    ]

    if args.json:
        result_payload = {
            "action": action.value,
            "detection_count": len(findings),
            "redacted": is_redacted,
            "findings": safe_findings,
        }
        if transformed_text is not None:
            result_payload["transformed_content"] = transformed_text
        sys.stdout.write(json.dumps(result_payload, indent=2) + "\n")
    else:
        sys.stdout.write("==================================================\n")
        sys.stdout.write("AI Data Firewall -- Scan Report\n")
        sys.stdout.write("==================================================\n")
        sys.stdout.write(f"Detections : {len(findings)}\n")
        sys.stdout.write(f"Action     : {action.value}\n")
        sys.stdout.write(f"Redacted   : {'yes' if is_redacted else 'no'}\n")
        if findings:
            sys.stdout.write("Findings   :\n")
            for idx, sf in enumerate(safe_findings, start=1):
                sys.stdout.write(
                    f"  {idx}. Category: {sf['category']} | "
                    f"Severity: {sf['severity']} | "
                    f"Confidence: {sf['confidence']} | "
                    f"Detector: {sf['detector_name']}\n"
                )
        if is_redacted and transformed_text is not None:
            sys.stdout.write("--------------------------------------------------\n")
            sys.stdout.write("Sanitized Content:\n")
            sys.stdout.write(f"{transformed_text}\n")
        sys.stdout.write("==================================================\n")

    if action == PolicyAction.BLOCK:
        return EXIT_BLOCKED
    return EXIT_SUCCESS


def run_providers() -> int:
    """Print registered AI provider adapters offline."""
    registry = create_default_registry()
    names = registry.list_providers()

    descriptions = {
        "openai": "OpenAI Chat Completions & Embeddings (/v1/chat/completions)",
        "anthropic": "Anthropic Messages API (/v1/messages)",
        "gemini": "Google Gemini API (/v1beta/models/...:generateContent)",
        "ollama": "Ollama Local Chat & Generate API (/api/chat)",
    }

    sys.stdout.write("AI Data Firewall -- Supported Provider Adapters:\n")
    sys.stdout.write("--------------------------------------------------\n")
    for name in names:
        desc = descriptions.get(name, "Generic AI provider adapter")
        sys.stdout.write(f"  * {name:<12}: {desc}\n")
    sys.stdout.write("--------------------------------------------------\n")
    sys.stdout.write(
        "All normalization and transformation are performed offline locally.\n"
    )
    return EXIT_SUCCESS


def main(argv: Sequence[str] | None = None) -> int:
    """CLI main entry point.

    Args:
        argv: Command-line argument vector (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 = success, 1 = runtime error, 2 = usage error, 3 = blocked).
    """
    parser = _build_parser()

    # If no arguments provided at all, show help
    args_list = list(argv) if argv is not None else sys.argv[1:]
    if not args_list:
        parser.print_help()
        return EXIT_USAGE_ERROR

    try:
        parsed_args = parser.parse_args(args_list)
    except SystemExit as err:
        return err.code if isinstance(err.code, int) else EXIT_USAGE_ERROR

    if parsed_args.command == "start":
        return run_start(parsed_args)
    elif parsed_args.command == "scan":
        return run_scan(parsed_args)
    elif parsed_args.command == "providers":
        return run_providers()
    else:
        parser.print_help()
        return EXIT_USAGE_ERROR


if __name__ == "__main__":
    sys.exit(main())
