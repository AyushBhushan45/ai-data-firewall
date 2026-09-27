# AI Data Firewall

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Release Status](https://img.shields.io/badge/status-v0.1.0%20pre--alpha-orange.svg)](docs/release-0.1.md)
[![Tests Status](https://img.shields.io/badge/tests-offline%20verified-brightgreen.svg)](tests/)

AI Data Firewall is an open-source, local-first security gateway for AI applications. It inspects AI requests and responses for security-sensitive content and applies configurable policies such as allow, warn, redact, or block.

---

## What It Does

AI Data Firewall acts as a local transparent intermediary between your application and AI inference providers (such as OpenAI, Anthropic, Google Gemini, or local Ollama instances):
- **Inspects Outgoing Prompts**: Detects API keys, private tokens, and credentials accidentally embedded in user prompts or RAG context before they reach upstream providers.
- **Inspects Ingoing Completions**: Analyzes model responses to prevent sensitive credentials or secrets from being returned to clients.
- **Enforces Deterministic Policies**: Evaluates declarative rules (`ALLOW`, `WARN`, `REDACT`, `BLOCK`) with clean conflict resolution.
- **Performs In-Place Redaction**: Masks sensitive content using right-to-left span masking without corrupting surrounding text or JSON structures.
- **Provides Offline CLI Inspection**: Scans strings or files directly from the command line without running a background server.

---

## Why It Exists

Modern AI applications increasingly handle sensitive organizational data:
- User prompts and conversation histories.
- Context documents retrieved from internal knowledge bases (RAG).
- API keys, credentials, and access tokens accidentally pasted into prompts.
- Model completions that may inadvertently reproduce training secrets or leaked keys.

Directly transmitting raw, uninspected content between client applications and external AI providers creates data leakage and compliance vulnerabilities.

AI Data Firewall provides a lightweight, local-first inspection boundary that gives developers visibility and control over what leaves and enters their environment—without requiring external cloud security brokers or persistent databases.

---

## Who Is This For?

- **AI Application Developers**: Teams building agents, RAG pipelines, or LLM-powered features who need a local safety net against accidental credential exfiltration.
- **Local-First Engineers**: Developers seeking a local in-process or sidecar data privacy layer between their application and remote AI providers.
- **Security Researchers & Builders**: Engineers experimenting with AI security, guardrail architectures, and policy enforcement.
- **Open-Source Contributors**: Developers interested in adding new secret patterns, PII detectors, and provider normalization adapters.

---

## Architecture

The firewall decouples transport, provider schema normalization, detection, and policy enforcement into independent layers:

```text
    AI Application
          │
          │ 1. Outgoing Request
          ▼
┌────────────────────────────────────────────────────────┐
│                   AI DATA FIREWALL                     │
│                                                        │
│  [ HTTP Firewall Proxy ]                               │
│           │                                            │
│           ▼                                            │
│  [ Provider Adapter ]                                  │
│           │                                            │
│           ▼                                            │
│  [ Normalized AI Model ]                               │
│           │                                            │
│           ▼                                            │
│  [ Detection Engine (SecretDetector) ]                 │
│           │                                            │
│           ▼                                            │
│  [ Policy Engine ]                                     │
│           │                                            │
│     ┌─────┴───────────────┐                            │
│     ▼                     ▼                            │
│  [ BLOCK ]      [ REDACT / ALLOW ]                     │
│  (Safe 403)               │                            │
│                           ▼                            │
│                 [ Denormalize Request ]                │
│                           │                            │
└───────────────────────────┼────────────────────────────┘
                            │
                            │ 2. Sanitized Request
                            ▼
                  [ Upstream AI Provider ]
                            │
                            │ 3. Model Completion
                            ▼
┌────────────────────────────────────────────────────────┐
│                   AI DATA FIREWALL                     │
│                                                        │
│  [ Response Intake ]                                   │
│           │                                            │
│           ▼                                            │
│  [ Normalization ]                                     │
│           │                                            │
│           ▼                                            │
│  [ Detection Engine ]                                  │
│           │                                            │
│           ▼                                            │
│  [ Policy Engine ]                                     │
│           │                                            │
│     ┌─────┴───────────────┐                            │
│     ▼                     ▼                            │
│  [ BLOCK ]      [ REDACT / ALLOW ]                     │
│  (Safe 502)               │                            │
│                           ▼                            │
│                 [ Client Delivery ]                    │
└───────────────────────────┼────────────────────────────┘
                            │
                            │ 4. Sanitized Completion
                            ▼
                      AI Application
```

For comprehensive technical specifications, see [docs/architecture.md](docs/architecture.md).

---

## Capability Matrix

| Capability | Status | Notes |
| :--- | :--- | :--- |
| **Secret Detection** | Supported | Pattern matching and Shannon entropy for API keys, tokens, and private credentials |
| **Policy Engine** | Supported | Declarative rules with deterministic precedence (`ALLOW` < `WARN` < `REDACT` < `BLOCK`) |
| **Redaction** | Supported | Right-to-left span masking preserving surrounding text and string indices |
| **Local HTTP Proxy** | Supported | Reverse proxy with strict localhost binding (`127.0.0.1:8080`) and fixed upstream |
| **Request Inspection** | Supported | Inspects inbound prompts, system instructions, and user messages |
| **Response Inspection** | Supported | Inspects outbound model completions and choice messages |
| **OpenAI-Compatible Adapter** | Supported | Schema normalization for `/v1/chat/completions` and `/v1/embeddings` |
| **Anthropic Adapter** | Supported | Schema normalization for Messages API (`/v1/messages`) |
| **Google Gemini Adapter** | Supported | Schema normalization for `generateContent` format |
| **Ollama Adapter** | Supported | Schema normalization for local Ollama `/api/chat` format |
| **CLI & Offline Tools** | Supported | `start`, `scan`, `providers`, and `--version` subcommands |
| **SSE / Streaming Inspection** | Not yet supported | Deferred; streaming requests (`stream: true`) fail safely with HTTP 400 |
| **WebSocket Inspection** | Not yet supported | Deferred |
| **Advanced Multimodal Scanning** | Not yet supported | Binary image/audio payloads are passed through intact without deep semantic analysis |

---

## Supported Provider Payload Families

The firewall supports normalization adapters for the following provider schema families:

- **OpenAI-compatible**: Targets `/v1/chat/completions` and `/v1/embeddings` payloads.
- **Anthropic**: Targets `/v1/messages` payload structures.
- **Google Gemini**: Targets `generateContent` request and candidate structures.
- **Ollama**: Targets local `/api/chat` payload structures.

> [!NOTE]
> Provider APIs evolve over time. AI Data Firewall adapters target the documented JSON schema structures for each provider family. Support does not imply endorsement by or official partnership with these providers.

---

## Quick Start

### 1. Installation

Install from source:

```bash
# Standard installation
pip install .

# Or for development with test dependencies
pip install -e ".[dev]"
```

Verify the installation:

```bash
aifirewall --version
aifirewall providers
```

### 2. Offline Text Scanning

Run an offline security scan on a string containing a synthetic credential:

```bash
aifirewall scan "Deploying service with key sk-proj-EXAMPLE_NOT_A_REAL_KEY_1234567890"
```

Output:
```text
==================================================
AI Data Firewall -- Scan Report
==================================================
Detections : 1
Action     : redact
Redacted   : yes
Findings   :
  1. Category: secret | Severity: high | Confidence: 0.95 | Detector: secret-detector
--------------------------------------------------
Sanitized Content:
Deploying service with key [REDACTED_SECRET]
==================================================
```

Emit machine-readable, privacy-safe JSON:

```bash
aifirewall scan "My token is ghp_EXAMPLE_NOT_A_REAL_TOKEN_123456789012" --json
```

Output:
```json
{
  "action": "redact",
  "detection_count": 1,
  "redacted": true,
  "findings": [
    {
      "category": "secret",
      "severity": "high",
      "confidence": 0.95,
      "detector_name": "secret-detector",
      "rule_id": "preset-redact-secrets"
    }
  ],
  "transformed_content": "My token is [REDACTED_SECRET]"
}
```

Enforce blocking policy (exits with code 3 on match):

```bash
aifirewall scan "Key: sk-proj-EXAMPLE_NOT_A_REAL_KEY_1234567890" --policy-preset block-secrets
```

---

## Local Proxy Example

Start the local reverse proxy pointing to your local Ollama instance or an upstream inference endpoint:

```bash
aifirewall start --upstream http://127.0.0.1:11434 --provider ollama
```

Startup banner:
```text
==================================================
AI Data Firewall v0.1.0
==================================================
Proxy Address   : http://127.0.0.1:8080
Upstream Target : http://127.0.0.1:11434
Provider Adapter: ollama
Active Policy   : 1 rule(s) (Default: ALLOW)
Client Target   : Point SDK base_url to http://127.0.0.1:8080
Health Check    : GET http://127.0.0.1:8080/health
Status          : Running. Press Ctrl+C to terminate cleanly.
==================================================
```

### Routing Application Traffic Through the Firewall

Direct your application's SDK to `http://127.0.0.1:8080`. The proxy intercepts the request, inspects and sanitizes the content, and forwards it to the configured upstream target:

```python
from openai import OpenAI

# Direct traffic to the local firewall proxy
client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="sk-proj-EXAMPLE_NOT_A_REAL_KEY",  # Forwarded safely upstream; never logged
)

# Prompts are inspected; completions are sanitized
response = client.chat.completions.create(
    model="llama3",
    messages=[{"role": "user", "content": "Hello, world!"}],
)
print(response.choices[0].message.content)
```

---

## Security Model

AI Data Firewall strictly separates pipeline responsibilities:
$$\text{Detection} \longrightarrow \text{Policy} \longrightarrow \text{Transformation}$$

- **Detection**: Detectors find findings without deciding what action to take.
- **Policy**: The policy engine evaluates findings against rules to determine the action (`ALLOW`, `WARN`, `REDACT`, `BLOCK`).
- **Transformation**: Transformation engines (such as `RedactionEngine`) execute the policy decision without altering business logic.

### Privacy Guarantees
- **Zero Raw Secret Output**: Detected secret values and authorization headers are never logged, echoed in console outputs, or serialized to JSON.
- **Anti-Open-Proxy**: The proxy binds strictly to `127.0.0.1` by default and enforces a fixed upstream destination configured at startup. Inbound requests cannot specify or override the destination host.
- **Upstream URL Sanitization**: Any credentials embedded in upstream URLs (such as HTTP Basic Auth or sensitive query tokens) are automatically redacted in all logs and console displays.

For details on trust boundaries and threat modeling, see [docs/security-model.md](docs/security-model.md).

---

## Limitations

As an early-stage project (`v0.1.0 pre-alpha`), the following limitations currently apply:

- **Streaming / SSE**: Server-Sent Events (`stream: true`) are not yet inspected. Requests with streaming enabled fail safely with HTTP 400.
- **WebSockets**: WebSocket inspection is not supported.
- **Multimodal Scanning**: Image, audio, and binary attachments pass through intact; deep semantic scanning is deferred.
- **Payload Schema Variants**: Some non-standard or experimental provider payload variants may be unsupported and fail safe.
- **Local-First Scope**: Designed for localhost or container sidecar execution, not as a shared multi-tenant public proxy.
- **Not a Universal Secret Scanner**: Focuses on high-risk credential patterns in AI traffic; should be used as part of a defense-in-depth strategy.

---

## Project Status

**Status: v0.1.0 / early-stage (Pre-Alpha)**

AI Data Firewall is under active development. The core security pipeline, provider adapters, CLI, and local reverse proxy are fully functional and backed by offline automated tests. However, this is an early-stage release and has not undergone formal third-party operational security audits.

---

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ai-data-firewall/ai-data-firewall.git
cd ai-data-firewall

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install in editable mode with development dependencies
pip install -e ".[dev]"

# Run offline automated test suite
pytest

# Run linter and formatter checks
ruff check .
ruff format --check .

# Run static type checking
npx --yes pyright
```

---

## Contributing

We welcome contributions! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, architectural boundaries, and instructions on adding new detectors or provider adapters.

---

## Security Reporting

Please review [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures. **Do not open public GitHub issues for security vulnerabilities.**

---

## License

This project is licensed under the [Apache License 2.0](LICENSE).
