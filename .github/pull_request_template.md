## Description
Briefly describe what this PR does, why it is needed, and any design context.

## Architectural Layer
- [ ] Detector (`src/aifirewall/detectors/`)
- [ ] Policy Engine (`src/aifirewall/policy/`)
- [ ] Transformation / Redaction (`src/aifirewall/transformation/`)
- [ ] Provider Adapter (`src/aifirewall/providers/`)
- [ ] Reverse Proxy / Upstream Transport (`src/aifirewall/proxy/`)
- [ ] CLI & Configuration (`src/aifirewall/cli.py`, `src/aifirewall/config.py`)
- [ ] Documentation / Tests / Infrastructure

## Security & Privacy Considerations
Explain the security and privacy implications of this change:
- Does this change handle raw prompts, completions, tokens, or credentials?
- How is zero-leakage maintained (no logging of raw bodies, tokens, or secrets)?
- Are failure modes fail-safe?

## Contributor Quality Checklist
Please ensure all of the following requirements are met before requesting review:
- [ ] **Tests added / updated**: New logic is covered by clean, deterministic automated tests.
- [ ] **Existing tests pass**: Running `pytest` passes 100% locally.
- [ ] **Linter passes**: Running `ruff check .` reports 0 errors.
- [ ] **Format check passes**: Running `ruff format --check .` reports 0 formatting errors.
- [ ] **Type check passes**: Running `npx --yes pyright` reports 0 errors and 0 warnings.
- [ ] **No secrets added**: No real API keys, bearer tokens, passwords, or credentials in code, tests, or docs (only synthetic placeholders like `sk-proj-EXAMPLE_NOT_A_REAL_KEY`).
- [ ] **No raw logging**: No logging of raw requests, responses, headers, or secret values.
- [ ] **Architecture boundaries preserved**: The security engine remains provider-agnostic; provider quirks remain isolated in adapter layer.
- [ ] **Documentation updated**: Docstrings, `README.md`, or relevant files in `docs/` have been updated if behavior changed.
- [ ] **No unrelated changes**: The PR contains only cohesive changes relevant to this PR's goal.
