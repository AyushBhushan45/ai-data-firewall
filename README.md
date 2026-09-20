# AI Data Firewall

An open-source, local-first security layer for AI applications.

---

## Project Status

> [!NOTE]
> **Current Status: Early Development (Pre-Alpha)**
>
> AI Data Firewall is in its foundational stage. Core architectural abstractions, documentation, packaging, and testing infrastructure are established, but the actual security inspection, detection, and firewalling engines are **not yet implemented**.
>
> This project is **not** currently suitable for production use or as an active security perimeter.

---

## Why This Project Exists

Modern AI-driven applications routinely process sensitive information:
- User prompts and conversation histories
- Context documents retrieved from internal databases or external knowledge bases
- Source code, system configurations, and internal infrastructure details
- Secrets, credentials, and access tokens accidentally embedded in developer prompts
- Unsanitized inputs from third-party sources vulnerable to prompt manipulation

Transmitting raw, uninspected content directly between end applications and remote AI providers creates substantial security, compliance, and privacy risks.

AI Data Firewall is designed to serve as an intermediary security layer positioned between the AI application and the upstream AI model/provider. Its role is to inspect incoming prompts and outgoing model responses, evaluate them against deterministic policies, and prevent unauthorized data exfiltration, token leakage, or unsafe completions.

---

## Vision

The long-term vision of AI Data Firewall is to deliver a transparent, vendor-neutral, local-first security boundary that developers can run within their own infrastructure to monitor, audit, and sanitize AI interactions without introducing cloud dependencies or sacrificing developer velocity.

---

## Planned Capabilities

The following capabilities represent the planned roadmap and are **NOT YET IMPLEMENTED** in the current release:

- **Secrets Detection**: Identification and redaction of API keys, private keys, passwords, and service tokens in prompts and responses.
- **PII Detection**: Recognition and handling of Personally Identifiable Information (emails, phone numbers, identifiers) before data leaves local infrastructure.
- **Prompt Injection Detection**: Heuristic and pattern-based analysis to flag suspicious instructions aimed at overriding model behavior.
- **Configurable Policies**: Declarative rules defining whether to allow, warn, redact, or block specific traffic patterns.
- **Request Inspection**: Pre-flight analysis of outgoing payloads before transmission to model providers.
- **Response Inspection**: Post-flight analysis of model-generated text before delivery to the client application.
- **Local Audit Logs**: Structured, privacy-preserving audit logs for security observability.
- **Provider Abstraction**: Consistent security semantics across various upstream model providers (e.g., OpenAI, Anthropic, local LLMs).
- **Local Development / Mock Mode**: Tooling to simulate policies and test security scenarios without active external API calls.
- **Developer SDKs & Integrations**: Simple client libraries and reverse-proxy setups for painless integration.

---

## Design Principles

- **Local-First**: Operates directly inside the user's infrastructure or local developer environment.
- **Privacy-First**: Sensitive prompts and model outputs are not sent to any external telemetry, analysis, or third-party service.
- **Transparent**: Every inspection decision and policy match is explainable, traceable, and inspectable.
- **Modular**: Detection modules, policy evaluators, and format handlers are built with decoupled interfaces for straightforward extension.
- **Provider-Agnostic**: Independent of any single model provider or proprietary LLM API.
- **Open Source**: Community-governed, self-hostable, and inspectable by any contributor.

---

## Current Limitations

- **Foundation Only**: The current repository contains project structure, packaging configurations, initial documentation, test harnesses, and CI scaffolding.
- **No Active Protection**: No real-time filtering, detection, or proxying logic is currently active.

---

## Roadmap

Development is structured into incremental phases:

- **Phase 0: Project Foundation** *(Current)* — Packaging, documentation, code standards, smoke tests, CI.
- **Phase 1: Detection Engine** — Core scanning interfaces, regex/pattern token detection, unit tests.
- **Phase 2: Policy Engine** — Declarative rule evaluation (allow, warn, redact, block).
- **Phase 3: Local Proxy** — Minimal HTTP/forwarding interception layer.
- **Phase 4: Provider Integration** — Adapter layers for standard LLM protocol formats.
- **Phase 5: Developer Tooling** — CLI, local testing harness, and configuration generators.
- **Phase 6: Production Hardening** — Benchmarking, performance optimization, and security audits.

---

## Repository Structure

```text
ai-data-firewall/
│
├── .github/
│   ├── workflows/
│   │   └── ci.yml               # Automated linting and test execution
│   │
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.yml       # Bug report issue template
│       └── feature_request.yml  # Feature proposal template
│
├── docs/
│   ├── architecture.md          # Planned architecture and data flow
│   ├── development.md           # Local setup and engineering guidelines
│   └── security-model.md        # Conceptual trust boundaries and threat vectors
│
├── src/
│   └── aifirewall/              # Core Python package namespace
│       └── __init__.py          # Package version and metadata
│
├── tests/
│   └── test_package.py          # Package import and version smoke test
│
├── .gitignore                   # Standard Python/IDE ignore patterns
├── CHANGELOG.md                 # Version release history
├── CODE_OF_CONDUCT.md           # Community guidelines (Contributor Covenant)
├── CONTRIBUTING.md               # Guide for developers and contributors
├── LICENSE                      # Apache License 2.0
├── README.md                    # Project overview and status
├── SECURITY.md                  # Vulnerability disclosure policy
└── pyproject.toml               # Package build, dependencies, pytest & ruff configs
```

---

## Development

### Prerequisites

- Python 3.11+
- Git

### Quick Setup

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

# Run linter
ruff check .

# Check formatting
ruff format --check .
```

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows, testing requirements, and code style guidelines.

## Security

Please review [SECURITY.md](SECURITY.md) for vulnerability reporting procedures and our responsible disclosure process.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
