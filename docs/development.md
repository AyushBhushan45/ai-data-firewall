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

### How to Add a New Detector (Contributor Guidance)

When contributing a new security or privacy detector in future steps:

1. **Implement the `Detector` protocol** defined in [`src/aifirewall/detectors/base.py`](../src/aifirewall/detectors/base.py):
   - Expose `@property def name(self) -> str` (e.g. `"secret_pattern_detector"`)
   - Expose `@property def version(self) -> str` (e.g. `"0.1.0"`)
   - Expose `@property def description(self) -> str` (safe human-readable purpose)
   - Expose `@property def supported_categories(self) -> tuple[DetectionCategory | str, ...]`
   - Implement `def detect(self, content: str, context: DetectorContext) -> list[DetectionResult]`
2. **Return `DetectionResult` objects**:
   - Provide a unique `detection_id` (e.g., UUID or structured ID).
   - Set calibrated `confidence` (float between `0.0` and `1.0`).
   - Assign appropriate `severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - Attach a validated `ContentLocation` with character offsets (`char_start`, `char_end`).
   - Provide a **safe description** (e.g., `"Possible credential pattern detected"`).
3. **Avoid policy decisions**:
   - Adhere strictly to **`DETECTION ≠ POLICY ≠ TRANSFORMATION`**.
   - A detector only answers *"What did I find?"*. Never attempt to dictate enforcement actions (such as `BLOCK` or `REDACT`) within the detector.
4. **Avoid storing or logging raw sensitive content**:
   - Never place plaintext passwords, credentials, or full user prompts into `DetectionResult`, `metadata`, or log statements.
5. **Include unit tests**:
   - Test against clean, benign text (confirm it returns `[]`).
   - Test against positive trigger text using synthetic, fake placeholders (confirm valid `DetectionResult`).
   - Test boundary conditions (empty strings, unicode strings, long text spans).
6. **Document false-positive considerations**:
   - Document known edge cases, ambiguous patterns, and recommended confidence thresholds.

### How to Add a New Secret Pattern to `SecretDetector`

To contribute a new credential pattern recognizer to [`SecretDetector`](../src/aifirewall/detectors/secret.py):

1. **Define the Pattern in `_compile_patterns()`**:
   - Create a `SecretPattern` with a unique identifier (e.g., `name="my_service_token"`).
   - Provide a precompiled regex with word boundaries `\b` and appropriate minimum length constraints.
   - Set an appropriate `Severity` (`HIGH` for high-impact tokens, `MEDIUM` for identifiers).
   - Set a deterministic, calibrated `confidence` (e.g. `0.95` for specific prefixes, `0.80` for generic matches).
   - Assign a safe description (e.g. `"Possible MyService token detected."`).
   - If custom span calculation or token validation is needed, provide an optional validator function.
2. **Enforce Placeholder & False-Positive Guardrails**:
   - Verify that standard placeholders (`YOUR_API_KEY`, `<TOKEN>`, `dummy-token`, etc.) are ignored.
   - Avoid overly greedy regexes that match arbitrary alphanumeric strings.
3. **Never Store or Expose the Secret Value**:
   - Ensure the validator and pattern metadata only store pattern names and non-sensitive attributes.
4. **Add Comprehensive Unit Tests**:
   - Add test cases in [`tests/test_secret_detector.py`](../tests/test_secret_detector.py).
   - Use strictly synthetic, fake placeholders.
   - Verify correct character start/end coordinates against `content[start:end]`.

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
