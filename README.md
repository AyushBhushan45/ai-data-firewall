# AI Data Firewall

An open-source, local-first security layer for AI applications.

---

## Project Status

> [!NOTE]
> **Status: v0.1.0 Pre-Alpha Release (CLI + End-to-End Hardening Implemented)**
>
> AI Data Firewall provides a local HTTP reverse proxy and offline CLI inspection tool. It intercepts AI requests and responses, normalizes provider-specific payloads into a unified domain model, detects sensitive credentials, and enforces declarative policies (allow, warn, redact, block).
>
> **Honest Pre-Alpha Boundaries**:
> - Supported providers: OpenAI, Anthropic, Gemini, Ollama (non-streaming).
> - Streaming tokens (`text/event-stream` / SSE), WebSockets, deep multimodal semantic scanning, persistent databases, and hosted cloud deployments are **intentionally deferred**.
> - Do not use as a public internet-facing gateway. Designed for local developer environments or single-container sidecar deployments.

---

## Why This Project Exists

Modern AI-driven applications routinely process sensitive information:
- User prompts and conversation histories.
- Context documents retrieved from internal knowledge bases (RAG).
- API keys, credentials, and access tokens accidentally pasted into prompts.
- Unsanitized model completions that may regurgitate credentials or sensitive data.

Transmitting raw, uninspected content directly between applications and remote AI providers creates substantial security and compliance risks.

AI Data Firewall acts as a local intermediary between your application and upstream AI providers. It inspects incoming prompts and outgoing completions, evaluates deterministic policies, and prevents credential exfiltration or unsafe outputs.

---

## Architecture Pipeline

```text
       +-----------------------+
       |    AI APPLICATION     |
       +-----------------------+
                   |
                   | 1. Outgoing AI Request (HTTP/SDK)
                   v
+-------------------------------------------------------------+
|                      AI DATA FIREWALL                       |
|                                                             |
|  [ Request Intake & Routing ]                               |
|            |                                                |
|            v                                                |
|  [ Provider Normalization ] -> [ Content Extraction ]       |
|                                         |                   |
|                                         v                   |
|                                [ Detection Engine ]         |
|                                (SecretDetector)             |
|                                         |                   |
|                                         v                   |
|                                [ Policy Engine ]            |
|                                         |                   |
|                   +---------------------+-----------------+ |
|                   |                                       | |
|                   v                                       v |
|               [ BLOCK ]                              [ CONTINUE ]
|                   |                                       | |
|                   v                                       v |
|          (Safe 403 Error)                           [ Redact ]      |
|                                                     (Right-to-Left) |
|                                                           | |
|                                                           v |
|                                                    [ Forwarding ]
+-----------------------------------------------------------|-+
                                                            |
                                                            | 2. Allowed / Sanitized Request
                                                            v
                                               +-------------------------+
                                               |   AI MODEL / PROVIDER   |
                                               +-------------------------+
                                                            |
                                                            | 3. Model Completion
                                                            v
+-----------------------------------------------------------|-+
|  [ Response Intake ] <------------------------------------+ |
|            |                                                |
|            v                                                |
|  [ Response Normalization ] -> [ Content Extraction ]       |
|                                         |                   |
|                                         v                   |
|                                [ Detection Engine ]         |
|                                (Secrets / Leakage)          |
|                                         |                   |
|                                         v                   |
|                                [ Policy Engine ]            |
|                                         |                   |
|                   +---------------------+-----------------+ |
|                   |                                       | |
|                   v                                       v |
|               [ BLOCK ]                               [ ALLOW ]
|                   |                                       | |
|                   v                                       v |
|          (Safe 502 Error)                          [ Redact ]       |
|                                                    (Output Masking) |
|                                                           | |
|                                                           v |
|                                                  [ Client Delivery ]
+-----------------------------------------------------------|-+
                                                            |
                                                            | 4. Sanitized Completion
                                                            v
                                               +-----------------------+
                                               |    AI APPLICATION     |
                                               +-----------------------+
```

---

## Core Design Principles

- **Local-First**: Runs directly on `127.0.0.1` or as a container sidecar. Zero mandatory external cloud services.
- **Privacy-Guaranteed**: Raw prompts, completions, and secrets are NEVER logged, serialized, or emitted to telemetry.
- **Zero-Database**: Operates entirely in-memory with zero persistent database dependencies (no SQLite, PostgreSQL, or Redis).
- **Zero-Telemetry**: No tracking SDKs, hosted metrics, or OpenTelemetry collectors.
- **Provider-Agnostic Core**: The security engine (detectors, policy engine, redaction) operates strictly on normalized representations, completely independent of provider schemas.

---

## Supported Provider Adapters

| Provider | Identifier | API Format | Non-Streaming | Request Redaction | Response Redaction | Streaming |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **OpenAI** | `openai` | `/v1/chat/completions` | Supported | Supported | Supported | Deferred (Fails Safe) |
| **Anthropic** | `anthropic` | `/v1/messages` | Supported | Supported | Supported | Deferred (Fails Safe) |
| **Google Gemini** | `gemini` | `/v1beta/models/...:generateContent` | Supported | Supported | Supported | Deferred (Fails Safe) |
| **Ollama** | `ollama` | `/api/chat` | Supported | Supported | Supported | Deferred (Fails Safe) |

---

## Installation

### Standard Installation
```bash
pip install .
```

### Editable Development Installation
```bash
pip install -e ".[dev]"
```

Verify installation:
```bash
aifirewall --version
aifirewall --help
aifirewall providers
```

---

## Quick Start & CLI Usage

### 1. Offline Text & File Scanning
Test the detection and policy pipeline offline without running the proxy:

```bash
# Scan a string (redacts detected secrets by default)
aifirewall scan "Deploying cluster with key sk-proj-123456789012345678901234567890123456789012345678"

# Machine-readable, privacy-safe JSON output
aifirewall scan "My token is ghp_123456789012345678901234567890123456" --json

# Enforce blocking policy (exits with code 3 on match)
aifirewall scan "Secret text" --policy-preset block-secrets

# Scan text from a file
aifirewall scan -f prompt.txt
```

### 2. Start the Local Firewall Proxy
Launch the local reverse proxy forwarding to an upstream AI provider:

```bash
# Point to a local Ollama instance (default: http://127.0.0.1:8080)
aifirewall start --upstream http://127.0.0.1:11434 --provider ollama

# Point to OpenAI with secret redaction
aifirewall start --upstream https://api.openai.com --provider openai --policy-preset redact-secrets

# Custom host, port, and timeouts
aifirewall start --upstream http://127.0.0.1:11434 --host 127.0.0.1 --port 9000 --timeout 30.0
```

### 3. Route Your Application Through the Firewall
Configure your AI client or SDK to use the local proxy address:

```python
from openai import OpenAI

# Direct client traffic to the local firewall proxy
client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="your-actual-api-key",  # Forwarded safely upstream; never logged
)

# Outgoing prompt is inspected; response completion is sanitized
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(response.choices[0].message.content)
```

---

## Configuration Architecture

Configuration uses deterministic precedence:
1. **CLI arguments** (`--upstream`, `--provider`, `--port`, `--policy-preset`)
2. **Environment variables** (`AIFIREWALL_UPSTREAM`, `AIFIREWALL_PROVIDER`, `AIFIREWALL_PORT`, `AIFIREWALL_CONFIG`)
3. **Configuration file** (`--config firewall.toml` or `firewall.json`)
4. **Safe defaults** (Host: `127.0.0.1`, Port: `8080`, Action: `ALLOW`)

Example configuration files are provided in [`examples/firewall.toml`](examples/firewall.toml) and [`examples/firewall.json`](examples/firewall.json).

### Built-in Policy Presets
- `redact-secrets`: Masks detected high-confidence secrets with category-aware placeholders (e.g. `[REDACTED_SECRET]`).
- `block-secrets`: Drops requests or responses containing detected secrets and returns safe structured error payloads.
- `warn-secrets`: Permits traffic while recording privacy-preserving audit events.
- `allow-all`: Evaluates default allow policy.

---

## Security & Privacy Guarantees

- **No Open-Proxy Risk**: The proxy binds to `127.0.0.1` by default and enforces a fixed upstream URL configured at startup. Client requests cannot override or redirect the destination.
- **Credential Protection**: `Authorization` and credential headers are forwarded upstream when needed but are strictly excluded from proxy logs, CLI output, error payloads, and audit events.
- **Fail-Safe Streaming**: Requests requesting streaming (`stream: true`) are safely rejected with HTTP 400 until streaming token inspection is implemented.
- **Input Boundaries**: Enforces strict request body (5MB default) and response body (10MB default) limits to prevent memory exhaustion.

---

## Known Limitations

- **Streaming / SSE**: Server-Sent Events (`stream: true`) are not yet inspected. Requests with streaming enabled fail safely with HTTP 400.
- **WebSockets**: Not supported.
- **Multimodal Scanning**: Image/audio binaries are passed through intact; deep semantic scanning is deferred.
- **Local Deployment Scope**: Designed for localhost or sidecar deployment, not as a shared multi-tenant public proxy.

---

## Documentation

- [Release Notes (v0.1.0)](docs/release-0.1.md): Summary of v0.1.0 capabilities and validation status.
- [System Architecture](docs/architecture.md): Complete technical design, module responsibilities, and normalization pipelines.
- [Security Threat Model](docs/security-model.md): Assets, trust boundaries, attack vectors, and privacy guarantees.
- [Development Guide](docs/development.md): Development setup, testing workflows, and extension guides.
- [Changelog](CHANGELOG.md): Historical record of changes across build milestones.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ai-data-firewall/ai-data-firewall.git
cd ai-data-firewall

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install in editable mode with development dependencies
pip install -e ".[dev]"

# Run test suite (416 offline tests)
pytest

# Run linter & formatter checks
ruff check .
ruff format --check .

# Run static type checker
npx --yes pyright
```

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, architectural boundaries, and testing requirements.

## Security

Please review [SECURITY.md](SECURITY.md) for vulnerability reporting procedures and our responsible disclosure process.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
