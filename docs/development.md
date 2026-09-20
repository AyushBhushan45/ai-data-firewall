# Development Guide

This guide describes the engineering workflow, local environment setup, testing standards, and development conventions for contributing to AI Data Firewall.

---

## Prerequisites

- **Python**: Version 3.11 or higher
- **Git**: Version 2.20 or higher
- **Packaging**: Standard Python `pip` and `venv`

---

## Local Environment Setup

### 1. Repository Setup

```bash
git clone https://github.com/ai-data-firewall/ai-data-firewall.git
cd ai-data-firewall
```

### 2. Virtual Environment

Always use a virtual environment to isolate project dependencies:

```bash
# Create virtual environment
python -m venv .venv

# Activate on Linux / macOS:
source .venv/bin/activate

# Activate on Windows PowerShell:
.venv\Scripts\Activate.ps1

# Activate on Windows CMD:
.venv\Scripts\activate.bat
```

### 3. Install Package in Editable Mode

Install `aifirewall` in editable mode with optional development dependencies:

```bash
pip install -e ".[dev]"
```

---

## Quality Assurance & Tooling

### Testing with pytest

All tests reside under the `tests/` directory and are run using `pytest`:

```bash
pytest
```

To run with verbose output:

```bash
pytest -v
```

### Linting and Formatting with Ruff

We use [Ruff](https://github.com/astral-sh/ruff) for fast, unified linting and code formatting:

```bash
# Run linter
ruff check .

# Automatically apply safe fixes
ruff check --fix .

# Check code formatting
ruff format --check .

# Format code
ruff format .
```

---

## Development Conventions

### 1. Code Style and Typing
- Follow [PEP 8](https://peps.python.org/pep-0008/) naming and formatting conventions.
- Provide type annotations on all new functions, methods, and class attributes.
- Use small, single-purpose functions with explicit argument names.

### 2. Dependency Management
- Keep dependencies minimal. Prefer the Python standard library whenever feasible.
- Do not introduce heavy AI frameworks, cloud client libraries, or databases unless explicitly required by an approved architectural milestone.

### 3. Security Hygiene
- **Never hardcode credentials**: Do not commit API keys, tokens, or passwords to code, documentation, or test fixtures.
- **Sanitized Fixtures**: Test cases must use synthetic, dummy strings (e.g., `sk-dummy-1234567890abcdef`) rather than real keys.
- **Safe Logging**: Never log unredacted prompts, secrets, or raw sensitive payloads.

### 4. Continuous Integration
All pull requests must pass automated CI checks in GitHub Actions, which executes:
- Python 3.11 environment setup
- `ruff check .`
- `pytest`
