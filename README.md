# AI Data Firewall

An open-source, local-first security layer for AI applications.

---

## Project Status

> [!NOTE]
> **Current Status: Early Development (Pre-Alpha — Step 4 Domain Layer Established)**
>
> The project now contains the foundational domain models, detector interface, validation logic, and error boundaries. However, concrete security detectors (secrets, PII, prompt injection), the proxy runtime, and provider integrations are **not yet implemented**.
>
> The firewall cannot yet inspect network traffic or protect AI applications in production.

---

## Why This Project Exists

Modern AI-driven applications routinely process sensitive information:
- User prompts and conversation histories
- Context documents retrieved from internal databases or external knowledge bases (RAG)
- Source code, system configurations, and internal infrastructure details
- Secrets, credentials, and access tokens accidentally embedded in developer prompts
- Unsanitized inputs from third-party sources vulnerable to prompt manipulation

Transmitting raw, uninspected content directly between end applications and remote AI providers creates substantial security, compliance, and privacy risks.

AI Data Firewall is designed to serve as an intermediary security layer positioned between the AI application and the upstream AI model/provider. Its role is to inspect incoming prompts and outgoing model responses, evaluate them against deterministic policies, and prevent unauthorized data exfiltration, token leakage, or unsafe completions.

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
|                                (Secrets, PII, Injection)    |
|                                         |                   |
|                                         v                   |
|                                [ Risk & Policy Engine ]     |
|                                         |                   |
|                   +---------------------+-----------------+ |
|                   |                                       | |
|                   v                                       v |
|               [ BLOCK ]                              [ CONTINUE ]
|                   |                                       | |
|                   v                                       v |
|          (Safe Error Return)                        [ Transform ]
|                                                     (Redaction)     |
|                                                           | |
|                                                           v |
|                                                    [ Forwarding ]
+-----------------------------------------------------------|-+
                                                            |
                                                            | 2. Allowed / Transformed Request
                                                            v
                                               +-------------------------+
                                               |   AI MODEL / PROVIDER   |
                                               +-------------------------+
                                                            |
                                                            | 3. Raw Model Response
                                                            v
+-----------------------------------------------------------|-+
|  [ Response Intake ] <------------------------------------+ |
|            |                                                |
|            v                                                |
|  [ Response Normalization ] -> [ Content Extraction ]       |
|                                         |                   |
|                                         v                   |
|                                [ Detection Engine ]         |
|                                (Leaks, Unsafe Outputs)      |
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
|          (Safe Policy Error)                       [ Transform ]
|                                                    (Output Redaction)|
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

- **Local-First**: Operates directly inside the user's infrastructure or local developer environment. Zero mandatory cloud services.
- **Privacy-First**: Sensitive prompts and model outputs are never sent to external telemetry or third parties. Raw prompts and secrets are never stored in default audit logs.
- **Transparent**: Every inspection decision and policy match is explainable, traceable, and inspectable.
- **Modular**: Detection modules, policy evaluators, and format handlers are built with decoupled interfaces for straightforward extension.
- **Provider-Agnostic**: Operates on normalized internal representations, independent of any single model provider or proprietary LLM API.
- **Open Source**: Community-governed, self-hostable, and inspectable by any contributor.

---

## Planned Capabilities

The following capabilities represent the planned roadmap and are **NOT YET IMPLEMENTED** in the current release:

- **Secrets Detection**: Identification and redaction of API keys, private keys, passwords, and service tokens in prompts and responses.
- **PII Detection**: Recognition and handling of Personally Identifiable Information (emails, phone numbers, identifiers) before data leaves local infrastructure.
- **Prompt Injection Detection**: Heuristic and pattern-based analysis to flag suspicious instructions aimed at overriding model behavior.
- **Configurable Policies**: Declarative rules defining whether to allow, warn, redact, or block specific traffic patterns.
- **Request & Response Inspection**: Pre-flight analysis of outgoing payloads and post-flight analysis of model-generated text.
- **Local Audit Logs**: Structured, privacy-preserving audit logs for security observability without payload duplication.
- **Provider Abstraction**: Consistent security semantics across various upstream model providers (e.g., OpenAI, Anthropic, local LLMs).
- **Local Development / Mock Mode**: Tooling to simulate policies and test security scenarios without active external API calls.

---

## Roadmap

Development is structured into incremental phases:

- **Phase 0: Project Foundation** *(Complete)* — Packaging, repository scaffolding, code standards, smoke tests, CI.
- **Phase 1: Technical Architecture & Design** *(Complete)* — System architecture, threat models, domain protocols, ADRs.
- **Phase 2: Core Detection Engine** — Scanning protocols, high-confidence secret and credential detection, test fixtures.
- **Phase 3: Policy Engine** — Declarative rule evaluation (allow, warn, redact, block) and conflict resolution.
- **Phase 4: Transformation Layer** — Safe string masking and redaction without payload corruption.
- **Phase 5: Provider Normalization & Mock Provider** — OpenAI/Anthropic format normalizers and offline test harness.
- **Phase 6: Local Proxy Daemon** — Minimal HTTP forwarding and reverse-proxy engine.
- **Phase 7: Developer Tooling & CLI** — Command-line interface and configuration validation.

---

## Documentation

- [System Architecture](docs/architecture.md): Complete technical design, module responsibilities, and request/response pipelines.
- [Architecture Decision Records (ADRs)](docs/architecture-decisions.md): Documented architectural trade-offs and decisions.
- [Security Threat Model](docs/security-model.md): Assets, trust boundaries, attack vectors, and privacy guarantees.
- [Development Guide](docs/development.md): Coding conventions, testing philosophy, and extension guides.

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

# Run tests
pytest

# Run linter & formatter checks
ruff check .
ruff format --check .
```

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows, testing requirements, and code style guidelines.

## Security

Please review [SECURITY.md](SECURITY.md) for vulnerability reporting procedures and our responsible disclosure process.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
