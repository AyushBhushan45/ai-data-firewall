# AI Data Firewall — v0.1.0 Release Notes

**AI Data Firewall v0.1.0** is the first usable pre-alpha release of the open-source, local-first security layer for AI applications.

---

## Highlights

- **CLI-First Developer Experience**: Start the local proxy or run offline scans directly with the `aifirewall` command.
- **Provider-Aware Normalization**: Native support for OpenAI, Anthropic, Gemini, and Ollama APIs while keeping the security engine strictly provider-agnostic.
- **Bi-Directional Inspection**: Inbound prompt protection and outbound completion masking/blocking.
- **Privacy-Safe by Design**: Under no circumstances are raw secrets, authorization headers, or sensitive prompts printed, logged, or sent to external telemetry.
- **Local-First & Zero-Database**: Runs entirely in-memory with zero persistent databases, cloud metrics, or tracking SDKs.
- **100% Offline Testability**: All 416 automated tests run deterministically without requiring live provider credentials or internet access.

---

## Supported Provider Adapters

| Provider | Identifier | Format Handled | Non-Streaming | Request Redaction | Response Redaction |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenAI** | `openai` | `/v1/chat/completions` | Supported | Supported | Supported |
| **Anthropic** | `anthropic` | `/v1/messages` | Supported | Supported | Supported |
| **Google Gemini** | `gemini` | `/v1beta/models/...:generateContent` | Supported | Supported | Supported |
| **Ollama** | `ollama` | `/api/chat` | Supported | Supported | Supported |

---

## Installation

```bash
# Clean pip installation
pip install .

# Or for development with testing dependencies
pip install -e ".[dev]"
```

Verify the installation:
```bash
aifirewall --version
aifirewall --help
aifirewall providers
```

---

## Quick Start Example

### 1. Test Scanning Offline
```bash
# Offline scan with default secret redaction
aifirewall scan "Deploying service with key sk-proj-EXAMPLE_NOT_A_REAL_KEY_1234567890"

# Machine-readable JSON output
aifirewall scan "My token is ghp_EXAMPLE_NOT_A_REAL_TOKEN_123456" --json

# Enforce blocking policy
aifirewall scan "Key: sk-proj-EXAMPLE_NOT_A_REAL_KEY_1234567890" --policy-preset block-secrets
```

### 2. Start the Local Firewall Proxy
```bash
# Start proxy pointing to a local Ollama instance
aifirewall start --upstream http://127.0.0.1:11434 --provider ollama

# Or start proxy pointing to an upstream provider endpoint
aifirewall start --upstream https://example.invalid --provider openai --policy-preset redact-secrets
```

### 3. Route Your Application Through the Firewall
Point your SDK or client base URL to the local proxy:
```python
from openai import OpenAI

# Direct traffic through the local firewall
client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="sk-proj-EXAMPLE_NOT_A_REAL_KEY",  # Forwarded safely without logging
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

---

## Configuration

Configuration precedence order:
1. CLI arguments (`--upstream`, `--provider`, `--port`, `--policy-preset`)
2. Environment variables (`AIFIREWALL_UPSTREAM`, `AIFIREWALL_PROVIDER`, etc.)
3. Configuration file (`--config firewall.toml` or `firewall.json`)
4. Safe defaults (Host: `127.0.0.1`, Port: `8080`, Action: `ALLOW`)

Example configuration files are provided in [`examples/firewall.toml`](../examples/firewall.toml), [`examples/firewall.json`](../examples/firewall.json), and [`.env.example`](../.env.example).

---

## Known Limitations & Intentional Boundaries

This release is an early v0.1 open-source developer release. Please note the following boundaries:
- **Streaming Inspection**: Server-Sent Events (SSE) streaming (`stream: true`) is deferred and fails safe with a clean 400 error.
- **WebSockets**: Not supported.
- **Multimodal Scanning**: Image/audio binary payloads are passed through intact without deep semantic content scanning.
- **Network Boundaries**: Designed for localhost / single-container sidecar deployments, not as a multi-tenant public gateway.
- **Telemetry**: Zero remote reporting; audit logging is local and privacy-safe.

For planned future milestones, see [docs/roadmap.md](roadmap.md).
For maintainer pre-release verification, see [docs/release-checklist.md](release-checklist.md).

---

## Validation Status

- **Automated Tests**: 426 passed (100% passing rate)
- **Linter**: Ruff passing (0 errors)
- **Formatter**: Ruff formatting verified
- **Type Checker**: Pyright passing (0 errors)
- **Package Build**: Wheel and sdist verified, clean install tested in isolated environment

