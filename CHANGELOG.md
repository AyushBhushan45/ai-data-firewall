# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0]

### Added
- **Command-Line Interface (CLI)**:
  - `aifirewall start`: Launches the local reverse proxy daemon with safe defaults (127.0.0.1:8080) and fixed upstream target.
  - `aifirewall scan`: Offline testing tool for text and files supporting safe text and `--json` machine-readable output.
  - `aifirewall providers`: Lists registered provider adapters offline.
  - `aifirewall --version`: Prints package version derived from single source of truth.
  - Console script entry point `aifirewall` registered via `pyproject.toml`.
- **Configuration Management**:
  - Deterministic precedence: CLI arguments > Environment variables > Configuration file (.toml/.json) > Defaults.
  - Standard library TOML (`tomllib`) and JSON parsing with zero new dependencies.
  - Safe policy presets (`redact-secrets`, `block-secrets`, `warn-secrets`, `allow-all`) and custom rule configuration.
- **Provider Adapters & Normalization**:
  - OpenAI adapter (`OpenAIAdapter`) for chat completions and embeddings.
  - Anthropic adapter (`AnthropicAdapter`) for Messages API format.
  - Google Gemini adapter (`GeminiAdapter`) for `generateContent` format.
  - Ollama adapter (`OllamaAdapter`) for local chat API format.
  - Round-trip denormalization preserving non-text parameters intact.
- **Core Detection & Policies**:
  - `SecretDetector` with entropy and pattern recognition for API keys, tokens, and private credentials.
  - `PolicyEngine` with deterministic conflict resolution (ALLOW < WARN < REDACT < BLOCK).
  - `RedactionEngine` providing right-to-left span masking without offset distortion.
- **Local Reverse Proxy**:
  - FastAPI + Uvicorn reverse proxy with anti-open-proxy protections and fixed upstream targets.
  - Strict localhost binding by default (`127.0.0.1:8080`).
  - Request and response body size limits, upstream timeouts, and privacy-safe error handling.
- **Security & Privacy Hardening**:
  - Zero raw secrets or credentials printed, logged, or serialized.
  - `Authorization` headers forwarded upstream but never logged or exposed in audit events.
  - Completely offline automated test suite (416 tests passing deterministically).

### Limitations & Intentionally Deferred
- SSE streaming token inspection (`text/event-stream`) is deferred (fails safe with clean error).
- WebSockets are not supported.
- Multimodal binary/image semantic inspection is limited to non-text passthrough.
- Zero mandatory databases, external telemetry, or cloud dependencies.
