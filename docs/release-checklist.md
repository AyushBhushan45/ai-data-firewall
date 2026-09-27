# AI Data Firewall — Maintainer Release Checklist

This document outlines the standard release hygiene verification procedure required before publishing any version of **AI Data Firewall**.

---

## Pre-Release Verification Steps

1. **Automated Test Suite**
   - Run complete test suite offline:
     ```bash
     pytest
     ```
   - All tests must pass cleanly (100% pass rate). Zero skipped or failed tests without documented justification.

2. **Linter and Code Style**
   - Run Ruff linter:
     ```bash
     ruff check .
     ```
   - Run Ruff format check:
     ```bash
     ruff format --check .
     ```
   - Must report 0 errors and 0 warnings.

3. **Static Type Checking**
   - Run Pyright:
     ```bash
     npx --yes pyright
     ```
   - Must report 0 errors and 0 warnings.

4. **Package Build Verification**
   - Build source distribution and wheel:
     ```bash
     python -m pip install --upgrade build
     python -m build
     ```
   - Inspect `dist/` directory to ensure both `.tar.gz` and `.whl` exist.

5. **Clean Environment Installation**
   - Create an isolated test virtual environment and install the built wheel:
     ```bash
     python -m venv test_env
     # Activate environment
     test_env/bin/pip install dist/ai_data_firewall-0.1.0-py3-none-any.whl
     ```

6. **CLI Smoke Testing**
   - Verify CLI subcommands in the clean environment:
     ```bash
     aifirewall --version
     aifirewall --help
     aifirewall providers
     aifirewall scan "Deploying service with key sk-proj-EXAMPLE_NOT_A_REAL_KEY"
     aifirewall scan "token test" --json
     ```
   - Confirm that no raw secret strings are emitted in output.

7. **Documentation & Version Alignment**
   - Verify `pyproject.toml` version matches `src/aifirewall/__init__.py`.
   - Ensure `CHANGELOG.md` reflects all notable changes for the release.
   - Ensure `README.md` and `docs/release-0.1.md` reflect current capabilities and limitations.

8. **Repository Secret Hygiene Audit**
   - Perform a scan across all tracked files for accidental secrets, tokens, or credentials:
     - No real API keys (only synthetic examples like `sk-proj-EXAMPLE_NOT_A_REAL_KEY`).
     - No personal or machine-specific paths committed.

9. **Working Tree and Generated Files Cleanup**
   - Remove temporary build artifacts (`build/`, `dist/`, `*.egg-info/`, `.pytest_cache/`, scratch files).
   - Verify Git status is clean:
     ```bash
     git status
     ```

10. **Tagging**
    - Tag release locally:
      ```bash
      git tag -a v0.1.0 -m "Release v0.1.0"
      ```
