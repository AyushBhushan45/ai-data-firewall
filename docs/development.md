# Development Guide & Engineering Standards

This document establishes the engineering standards, architectural conventions, security rules, and testing strategies for contributing to **AI Data Firewall**.

---

## 1. Security-Sensitive Development Rules

Because AI Data Firewall is a security tool designed to handle sensitive traffic, contributors must strictly adhere to these 10 principles:

1. **Never hardcode credentials**: Never commit API keys, passwords, tokens, or private keys to source code, documentation, or configuration files.
2. **Never place realistic keys in tests**: Test fixtures must use synthesized, obviously fake placeholders (e.g., `sk-dummy-1234567890abcdefghijklmnopqrstuvwxyz`).
3. **Never log sensitive content by default**: Audit loggers, error handlers, and serializers must never write raw prompt strings, model completions, or detected secrets to stdout or disk.
4. **Never make security decisions silently**: Every block, redaction, or warning must generate a traceable `SecurityEvent` audit record.
5. **Keep detection and policy strictly decoupled**: Detectors observe and classify (`DetectionResult`); they never make enforcement decisions. The `PolicyEngine` enforces actions (`PolicyDecision`).
6. **Never assume a detector is infallible**: Design all scanners with explicit confidence ratings (`0.0` to `1.0`) and account for both false positives and false negatives.
7. **Never treat arbitrary user content as trusted**: Validate and normalize all incoming requests before processing.
8. **Never trust retrieved documents blindly**: Content originating from RAG vector stores, web searches, or document parsers must be labeled as `RETRIEVED_DOCUMENT` and scanned for indirect prompt injection.
9. **Treat agent tool outputs as untrusted**: Output from external API calls and system tools must be treated as `TOOL_OUTPUT` and evaluated prior to model ingestion.
10. **Fail securely**: If an inspection component or policy engine crashes unexpectedly, the default posture is **fail-closed** (block or reject).

---

## 2. Architectural Boundaries & Extension Points

The architecture is designed to be extensible without modifying core pipeline orchestration.

### How to Add a New Detector
1. Create a new module under `src/aifirewall/detectors/` (e.g., `jwt_detector.py`).
2. Implement the `Detector` protocol defined in [`src/aifirewall/protocols.py`](../src/aifirewall/protocols.py):
   - Expose `@property def name(self) -> str`
   - Expose `@property def category(self) -> str`
   - Implement `def detect(self, content: str, location: ContentLocation) -> list[DetectionResult]`
3. Ensure findings produce valid `DetectionResult` objects with `char_start` and `char_end` spans relative to the input text.
4. **Do NOT store the raw detected value** in the result.
5. Add unit tests under `tests/detectors/` covering clean inputs, positive matches, and boundary cases.
6. Register the detector in the central detector registry.

### How to Add a New Provider Adapter
1. Create a module under `src/aifirewall/providers/` (e.g., `anthropic_adapter.py`).
2. Implement the `ProviderAdapter` protocol:
   - `normalize_request(raw_request: dict) -> NormalizedAIRequest`
   - `normalize_response(raw_response: dict, request_id: str) -> NormalizedAIResponse`
   - `denormalize_request(request: NormalizedAIRequest) -> dict`
3. Ensure that missing or proprietary fields are mapped gracefully into the `metadata` dictionary without throwing unexpected exceptions.
4. Add unit tests verifying bidirectional schema translation.

### How to Add a New Policy Rule
1. Policy rules are declarative entries loaded by the `PolicyEngine`.
2. A rule specifies:
   - `name`: Human-readable identifier.
   - `category`: Target detection category (e.g., `api_key`, `pii`).
   - `severity`: Minimum severity threshold (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - `min_confidence`: Minimum confidence threshold (`0.0` to `1.0`).
   - `action`: Prescribed resolution (`ALLOW`, `WARN`, `REDACT`, `BLOCK`).
3. Add configuration tests ensuring the rule resolves deterministically according to the precedence hierarchy:
   $$\mathbf{BLOCK} > \mathbf{REDACT} > \mathbf{WARN} > \mathbf{ALLOW}$$

---

## 3. Testing Strategy

Quality assurance in AI Data Firewall spans four distinct tiers:

### Tier 1: Unit Tests
- Fast, isolated, deterministic tests executing in milliseconds.
- Test detector regex patterns, Shannon entropy math, policy precedence resolution, and string transformation functions.
- Run via `pytest tests/`.

### Tier 2: Integration Tests with Mock Provider
- Tests end-to-end request/response flows without making network calls or invoking paid APIs.
- Employs `MockProvider` to simulate realistic provider behaviors:
  - Clean responses.
  - Responses containing regurgitated secrets.
  - Upstream 500 errors.
  - Malformed JSON outputs.

### Tier 3: Security Regression Tests
- Whenever a detection bypass, parser ambiguity, or injection evasion is identified, a dedicated security regression test must be added to `tests/security/`.
- Test cases include:
  - Obfuscated credentials (spaces, base64 wrappers, delimiter insertion).
  - Unicode homoglyph normalization attacks.
  - Prompt injection override permutations.

### Tier 4: Property-Based & Performance Tests
- Fuzz testing string transformation engines using diverse character sets to guarantee that redaction never corrupts unrelated text spans.
- Latency benchmarks ensuring the inspection pass adds negligible overhead to model invocations.

---

## 4. Local Development Commands

```bash
# Activate virtual environment
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Run complete test suite
pytest -v

# Run linter
ruff check .

# Apply automatic formatting fixes
ruff check --fix .

# Verify formatting compliance
ruff format --check .

# Format code
ruff format .
```
