# Contributing to AI Data Firewall

Thank you for your interest in contributing to AI Data Firewall! We welcome contributions that align with our mission of building a transparent, local-first, provider-agnostic security layer for AI applications.

---

## Before Contributing

1. **Review Documentation**: Read the [README.md](README.md), [Architecture Guide](docs/architecture.md), and [Security Model](docs/security-model.md) to understand project goals and design principles.
2. **Check Existing Issues**: Search existing GitHub issues and pull requests to ensure the work is not already in progress or discussed.
3. **Keep It Focused**: Small, cohesive contributions are much easier to review and integrate than monolithic pull requests.

---

## Development Setup

### 1. Prerequisites

- Python 3.11 or higher
- Git

### 2. Clone and Setup Environment

```bash
# Clone the repository
git clone https://github.com/ai-data-firewall/ai-data-firewall.git
cd ai-data-firewall

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
# On Linux/macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Windows (Command Prompt):
.venv\Scripts\activate.bat

# Install the package in editable mode with development dependencies
pip install -e ".[dev]"
```

### 3. Verify Local Setup

Run the test suite and linter:

```bash
# Run pytest
pytest

# Check code style and linting
ruff check .

# Check code formatting
ruff format --check .

# Run static type checking
npx --yes pyright
```

---

## Contribution Expectations

When submitting code or documentation, please keep the following in mind:

- **Incremental Progress**: We build features stage-by-stage. Avoid jumping ahead to unapproved components or premature abstractions.
- **Typed Python**: Write clear, typed Python code adhering to modern standards.
- **Test Coverage**: Accompany all new logic or bug fixes with clean, deterministic tests. Do not add fake or mocking-only tests for unimplemented features.
- **Zero Secrets**: Never commit API keys, tokens, real credentials, or sensitive test data to the repository. Use synthesized or sanitized dummy values when required in tests.
- **Minimal Dependencies**: Do not introduce new dependencies unless they are strictly necessary and discussed beforehand.
- **Documentation**: Update relevant documentation files in `docs/` or docstrings whenever interfaces or configurations change.

---

## Pull Request Guidelines

1. **Descriptive Title**: Use clear, conventional commit messages (e.g., `feat: add regex token detector`, `fix: handle empty payload gracefully`).
2. **Clear Description**: Summarize what changed, why the change was made, and any trade-offs considered.
3. **Security Considerations**: If your change touches data handling, parsing, or security-sensitive boundaries, explicitly describe the security implications in the PR description.
4. **CI Passing**: Ensure that `pytest` and `ruff` pass cleanly before requesting a review.

---

## Reporting Issues

- **Bug Reports**: Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml) and include reproduction steps, expected behavior, actual behavior, and environment details.
- **Feature Requests**: Use the [Feature Request template](.github/ISSUE_TEMPLATE/feature_request.yml) to outline the proposed enhancement and use case.
- **Security Vulnerabilities**: For security concerns, do NOT open a public issue. Follow the instructions in [SECURITY.md](SECURITY.md).
