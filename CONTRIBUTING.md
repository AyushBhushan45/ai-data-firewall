# Contributing to AI Data Firewall

Thank you for your interest in contributing to **AI Data Firewall**!
We welcome contributions that improve code quality, extend provider adapter support, add detectors, or enhance documentation while adhering to our local-first, privacy-guaranteed principles.

---

## Code of Conduct

All contributors are expected to uphold the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

---

## Support & Issue Reporting

- **Bug Reports**: Please open a GitHub issue using the [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml). Provide a minimal reproduction using synthetic credentials.
- **Feature Requests**: Please open a GitHub issue using the [Feature Request Template](.github/ISSUE_TEMPLATE/feature_request.yml). Specify which architectural layer is affected.
- **Security Vulnerabilities**: **Do NOT open public GitHub issues for security vulnerabilities.** Follow the private disclosure instructions in [SECURITY.md](SECURITY.md).

---

## Architectural Boundaries

Before making changes, understand where each layer lives:

| Layer | Directory | Responsibility |
| :--- | :--- | :--- |
| **Detectors** | `src/aifirewall/detectors/` | Scans text strings for sensitive items (secrets, tokens). Implements `Detector` protocol. |
| **Policy Engine** | `src/aifirewall/policy/` | Evaluates declarative rules (`ALLOW`, `WARN`, `REDACT`, `BLOCK`) against findings. |
| **Transformation** | `src/aifirewall/transformation/` | Executes modifications on text (e.g. right-to-left span redaction). |
| **Provider Adapters** | `src/aifirewall/providers/` | Normalizes provider payloads to `NormalizedAIRequest` / `NormalizedAIResponse` and denormalizes back. |
| **Reverse Proxy** | `src/aifirewall/proxy/` | Ingests HTTP requests, coordinates the security pipeline, and forwards to fixed upstream. |
| **CLI & Config** | `src/aifirewall/cli.py`, `src/aifirewall/config.py` | Command-line arguments, environment variable precedence, and TOML/JSON parsing. |
| **Tests** | `tests/` | Offline unit, integration, and security regression tests. |

**Key Rule**: The core detection and policy engines operate exclusively on normalized data structures (`NormalizedMessage`, `ContentLocation`, `DetectionResult`). Never couple detectors or policies directly to provider-specific JSON schemas.

---

## Development Environment Setup

### 1. Prerequisites

- Python 3.11 or higher
- Git

### 2. Setup Virtual Environment

```bash
# Clone the repository
git clone https://github.com/ai-data-firewall/ai-data-firewall.git
cd ai-data-firewall

# Create virtual environment
python -m venv .venv

# Activate environment:
# On Linux / macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (Command Prompt):
.venv\Scripts\activate.bat

# Upgrade pip and install package in editable mode with dev dependencies
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

---

## Standard Development Workflow

Before submitting a pull request, run the following verification steps:

```bash
# 1. Run all unit and integration tests (offline, ~6-8s)
pytest

# 2. Check linting with Ruff
ruff check .

# 3. Check code formatting with Ruff
ruff format --check .

# 4. Run static type checking with Pyright
npx --yes pyright

# 5. Run CLI smoke tests
aifirewall --version
aifirewall --help
aifirewall providers
aifirewall scan "Deploying key sk-proj-EXAMPLE_NOT_A_REAL_KEY_1234567890"
```

---

## How-To Guides

### Adding a New Detector

1. Create your detector class in `src/aifirewall/detectors/`:
   ```python
   from aifirewall.core.types import DetectionCategory, Severity
   from aifirewall.detectors.base import Detector, DetectorContext
   from aifirewall.detectors.models import DetectionResult


   class ExampleDetector:
       """Detects specific token patterns."""

       @property
       def category(self) -> DetectionCategory:
           return DetectionCategory.SECRET

       def detect(
           self, text: str, context: DetectorContext | None = None
       ) -> list[DetectionResult]:
           results: list[DetectionResult] = []
           # Implement pattern or heuristic search
           # Append DetectionResult with start, end, severity, confidence, rule_id
           return results
   ```
2. Export your detector in `src/aifirewall/detectors/__init__.py`.
3. Add comprehensive offline unit tests in `tests/test_<name>_detector.py`.
4. Ensure all tests run offline without network access or real credentials.

### Adding a New Provider Adapter

1. Subclass `ProviderAdapter` in `src/aifirewall/providers/adapters/<name>.py`:
   - Implement `provider_name` property.
   - Implement `can_handle_request(method, path, headers, body) -> bool`.
   - Implement `normalize_request(method, path, headers, body) -> NormalizedAIRequest`.
   - Implement `normalize_response(status_code, headers, body, request) -> NormalizedAIResponse`.
   - Implement `apply_redactions_request(body, request, redactions) -> bytes`.
   - Implement `apply_redactions_response(body, response, redactions) -> bytes`.
2. Register the adapter in `src/aifirewall/providers/registry.py` inside `create_default_registry()`.
3. Add unit tests in `tests/test_provider_<name>.py` testing round-trip normalization, non-streaming detection, and redaction.

### Adding a Policy Rule

Policy rules are defined declaratively in TOML or JSON:
```toml
[[policy.rules]]
rule_id = "block-critical-secrets"
action = "block"
category = "secret"
minimum_severity = "critical"
minimum_confidence = 0.8
description = "Block any request or response containing high-confidence critical secrets"
```

---

## Pull Request Guidelines

1. **Focused Changes**: Keep pull requests focused on a single issue or feature.
2. **Deterministic Tests**: Include automated tests covering both success and edge cases.
3. **No Secrets**: Never include real API keys, bearer tokens, or personal identifiers in code, tests, or documentation. Use `sk-proj-EXAMPLE_NOT_A_REAL_KEY` or similar synthetic tokens.
4. **No Raw Logging**: Ensure no logging statements log raw request bodies, completions, headers, or detected secret values.
5. **PR Checklist**: Complete the checklist in `.github/pull_request_template.md`.
