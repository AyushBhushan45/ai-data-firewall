# AI Data Firewall: Complete System Architecture & Technical Design

> [!IMPORTANT]
> **Redaction Engine Milestone (Step 7 Implemented)**
>
> Step 7 implements the deterministic content transformation layer:
> - **`RedactionEngine`** ([`src/aifirewall/transformation/redaction.py`](../src/aifirewall/transformation/redaction.py)): Executes deterministic, policy-controlled string mutations.
> - **Domain Models**: `RedactionResult` ([`src/aifirewall/transformation/models.py`](../src/aifirewall/transformation/models.py)).
> - **Core Guarantees**: Strict architectural boundary ($\mathbf{DETECTION \ne POLICY \ne TRANSFORMATION}$), right-to-left replacement preserving string offsets, deterministic overlap and nesting clustering ($\mathbf{Severity > Confidence > Span\ Length > ID}$), safe semantic placeholders (`[REDACTED_SECRET]`), strict span coordinate validation, caller-owned argument immutability, zero secret persistence, and privacy-safe representations (`__repr__` and `__str__` exclude raw/transformed text).
>
> **Explicit Boundary:** HTTP proxy daemons, PII detectors, prompt-injection detectors, database persistence, telemetry, and provider adapters remain **PLANNED FOR FUTURE STEPS**.

---

## 1. System Overview & Architecture Diagram

AI Data Firewall operates as a local-first, privacy-preserving security and inspection layer positioned between an AI application (client) and an upstream AI provider or model runtime (e.g., OpenAI, Anthropic, Gemini, local Ollama instances).

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

## 2. Core Modules & Responsibilities

The codebase is organized into clean, single-responsibility modules:

```text
src/aifirewall/
├── core/             # Primitives: types.py (enums), errors.py (exception hierarchy)
├── models/           # Domain models: content.py, request.py, response.py, detection.py, event.py
├── detectors/        # Observational protocols & contexts: base.py (future scanners live here)
├── protocols.py      # Structural subtyping protocols (ProviderAdapter, PolicyEngine, etc.)
├── policies/         # [Future] Rule evaluation and policy decision engine
├── transform/        # [Future] Text transformation and redaction engine
├── normalization/    # [Future] Provider-specific payload mapping
├── providers/        # [Future] Upstream client connections and mock adapters
├── proxy/            # [Future] HTTP reverse-proxy server daemon
├── logging/          # [Future] Structured audit log sinks (JSONL, stderr)
├── config/           # [Future] Declarative YAML configuration schemas and validation
└── cli/              # [Future] Command-line entry points
```

### Module Ownership Matrix

| Module | Primary Responsibility | Status |
| :--- | :--- | :--- |
| `core/` | Primitives: Enums (`ContentDirection`, `ContentSource`, `Severity`, `PolicyAction`, `EventType`) and safe exception hierarchy (`AIFirewallError`, `ValidationError`, `DetectorError`). | **Implemented in Step 4** |
| `models/` | Frozen canonical dataclasses: `ContentLocation`, `DetectionResult`, `NormalizedMessage`, `NormalizedAIRequest`, `NormalizedAIResponse`, `PolicyDecision`, `SecurityEvent`. | **Implemented in Step 4** |
| `detectors/base.py`| Structural subtyping contract: `Detector` protocol and minimal `DetectorContext`. | **Implemented in Step 4** |
| `detectors/secret.py`| Pattern-based detection of common API keys, personal access tokens, and credential assignments (`SecretDetector`). | **Implemented in Step 5** |
| `detectors/` (others)| Scanners for PII, prompt injections, and future detectors. | *Planned for Future Steps* |
| `policy/` | Declarative policy models (`PolicyRule`, `PolicyConfig`, `PolicyContext`) and deterministic evaluation engine (`PolicyEngine`). | **Implemented in Step 6** |
| `transformation/` (`transform/`) | Deterministic, policy-controlled content redaction engine (`RedactionEngine`, `RedactionResult`). | **Implemented in Step 7** |
| `providers/` | External provider format mappings and transport adapters. | *Planned for Future Steps* |
| `proxy/` | Local HTTP reverse-proxy runtime daemon. | *Planned for Future Steps* |

---

## 3. Request Processing Pipeline

Every incoming AI request is processed through an explicit, 15-step sequence:

```text
[Step 1: Ingest Request]
         |
[Step 2: Validate Request Structure]
         |
[Step 3: Generate Correlation Context (request_id)]
         |
[Step 4: Identify Provider & Route]
         |
[Step 5: Normalize into NormalizedAIRequest]
         |
[Step 6: Extract Inspectable Content Blocks with ContentLocation]
         |
[Step 7: Execute Enabled Detectors Sequentially / Independently]
         |
[Step 8: Aggregate DetectionResult[] List]
         |
[Step 9: Evaluate Policies via PolicyEngine]
         |
         +-----------------------------+
         |                             |
[If Action == BLOCK]         [If Action == REDACT / WARN / ALLOW]
         |                             |
[Step 10: Record Audit Event] [Step 11: Apply Transformations (if REDACT)]
         |                             |
[Step 12: Return Safe Error]  [Step 13: Record Privacy-Safe Audit Event]
                                       |
                              [Step 14: Denormalize & Forward to Provider]
                                       |
                              [Step 15: Receive Upstream Provider Response]
```

### Detailed Pipeline Stages

1. **Request Intake**: Ingests raw HTTP request payload and headers from the calling application.
2. **Schema Validation**: Confirms the request is well-formed JSON conforming to expected API schemas.
3. **Correlation Context**: Assigns a deterministic `request_id` (UUIDv4) and initializes a `RequestContext`.
4. **Route Identification**: Identifies the destination provider adapter (e.g., `/v1/chat/completions` -> OpenAI adapter).
5. **Provider Normalization**: Converts provider-specific payload into a unified `NormalizedAIRequest`.
6. **Content Extraction**: Walks normalized message trees to extract inspectable strings annotated with `ContentLocation` metadata (role, index, character spans).
7. **Detector Execution**: Dispatches extracted text blocks to registered detectors. Each detector runs in isolation.
8. **Findings Aggregation**: Collects all `DetectionResult` objects. Detections do not store the raw secret string.
9. **Policy Evaluation**: The `PolicyEngine` matches findings against active policies and produces a `PolicyDecision`.
10. **Enforcement (Block)**: If `BLOCK`, execution halts immediately. Upstream network calls are prohibited.
11. **Enforcement (Redact)**: If `REDACT`, the `ContentTransformer` modifies sensitive spans using safe masks.
12. **Enforcement (Warn/Allow)**: If `WARN` or `ALLOW`, findings are logged without modifying the payload.
13. **Audit Recording**: A `SecurityEvent` record is emitted to configured audit sinks.
14. **Forwarding**: The normalized (or transformed) payload is denormalized back into the provider's format and dispatched.
15. **Handoff**: The raw provider response is received and handed directly to the Response Pipeline.

---

## 4. Response Processing Pipeline

Completions generated by upstream AI models undergo post-flight inspection before returning to the client application:

```text
[Step 1: Receive Raw Provider Response]
         |
[Step 2: Validate Response HTTP Status & Structure]
         |
[Step 3: Normalize into NormalizedAIResponse]
         |
[Step 4: Extract Output Content Spans]
         |
[Step 5: Run Response-Specific Detectors (Secret Regurgitation, PII, Policy Checks)]
         |
[Step 6: Aggregate DetectionResult[] List]
         |
[Step 7: Evaluate Response Policy]
         |
         +-----------------------------+
         |                             |
[If Action == BLOCK]         [If Action == REDACT / WARN / ALLOW]
         |                             |
[Step 8: Record Audit Event]  [Step 9: Apply Redaction to Completion (if REDACT)]
         |                             |
[Step 10: Return Safe Policy  [Step 11: Denormalize & Deliver Sanitized Response]
          Error to Client]
```

### Response Policy Rules
- **Accidental Secret Regurgitation**: If a model inadvertently emits an API key, database credential, or private key in its completion, response policies default to `BLOCK` or `REDACT`.
- **PII Masking**: Outgoing PII (e.g., customer account details extracted from RAG context) can be redacted in place.
- **Client Transparency**: When a response is blocked, the client receives a structured JSON security error with the `request_id`, explaining that the model response violated security policies.

---

## 5. Domain Models & Protocols (Implemented in Step 4)

Rather than forcing detectors and policy engines to parse varied vendor formats, the system operates on immutable, validated internal dataclasses defined in [`src/aifirewall/models/`](../src/aifirewall/models/):

### Normalized Representations
- **`NormalizedAIRequest`**: Canonical representation containing validated `request_id`, target `model`, a list of `NormalizedMessage` objects, parameters, and metadata.
- **`NormalizedMessage`**: Represents a conversational turn (`role`, normalized `content`, `source`, `metadata`). Validates non-empty role.
- **`NormalizedAIResponse`**: Normalized model completion containing `request_id`, `model`, `content`, `finish_reason`, parameters, and metadata.

### Content Location Tracking
To pinpoint where findings occur without re-parsing raw payloads, findings include a `ContentLocation`:
- `source`: `ContentSource` enum (`SYSTEM`, `USER`, `ASSISTANT`, `TOOL_INPUT`, `TOOL_OUTPUT`, `RETRIEVED_CONTENT`, `UNKNOWN`).
- `message_index`: Optional zero-based index of the message in the conversational history array.
- `block_index`: Optional zero-based index of a content block within structured or multimodal messages.
- `char_start` & `char_end`: Zero-indexed character slice boundaries within the text block. Validates non-negative values and `char_start <= char_end`.
- `field_path`: Dot-notation path to the inspected attribute (e.g. `messages[2].content`).

### Finding & Decision Representations
- **`DetectionResult`**: Captures an observational finding produced by a detector:
  - `detection_id`: Unique identifier for the finding.
  - `detector_name`: Identifier of the detector module.
  - `category`: Classification category (`SECRET`, `PII`, `PROMPT_INJECTION`, `OTHER`).
  - `severity`: Observational severity level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - `confidence`: Validated float strictly within `[0.0, 1.0]`.
  - `location`: Frozen `ContentLocation` coordinates.
  - `description`: Non-empty safe diagnostic explanation.
  - `metadata`: Optional safe metadata dictionary.
  - **Zero Raw Secret Storage**: The model stores NO plaintext secrets or raw tokens.
  - **No Policy Decisions**: In adherence to `DETECTION ≠ POLICY`, detectors do NOT set policy actions on findings.
- **`PolicyDecision`**: Encapsulates `action` (`ALLOW`, `WARN`, `REDACT`, `BLOCK`), `reason`, `matched_rules`, and referenced `detections`.
- **`SecurityEvent`**: Standardized audit log entry containing `event_id`, `timestamp`, `request_id`, `direction`, `action_taken`, `safe_explanation`, `event_type`, and sanitized detection summaries.

---

## 6. Detector Architecture & Context (Implemented in Step 4)

Detectors are self-contained observational scanning modules implementing the `Detector` protocol defined in [`src/aifirewall/detectors/base.py`](../src/aifirewall/detectors/base.py):

```python
@runtime_checkable
class Detector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def supported_categories(self) -> tuple[DetectionCategory | str, ...]: ...

    def detect(
        self,
        content: str,
        context: DetectorContext,
    ) -> list[DetectionResult]: ...
```

### Detector Context (`DetectorContext`)
Detectors receive minimal contextual information via `DetectorContext`:
- `request_id`: Correlation identifier for the transaction.
- `direction`: Traffic flow direction (`REQUEST` or `RESPONSE`).
- `source`: Content boundary provenance (`USER`, `SYSTEM`, `ASSISTANT`, etc.).
- `model`: Optional target model name (e.g., `gpt-4o`).
- `provider`: Optional upstream provider identifier (e.g., `openai`).
- `location`: Optional parent content location coordinates.
- `metadata`: Safe arbitrary metadata.
- **Privacy Boundary**: Context strictly prohibits raw API keys, credentials, or user identity tokens.

### Concrete Implementation: `SecretDetector` (Implemented in Step 5)
[`SecretDetector`](../src/aifirewall/detectors/secret.py) is the first operational security detector. It identifies common credential and access token patterns across 8 recognizer families:
1. **OpenAI API keys**: Matches `sk-[a-zA-Z0-9]{20,}` and `sk-proj-[a-zA-Z0-9_-]{20,}` (`Severity.HIGH`, `confidence=0.95`).
2. **GitHub personal access tokens**: Matches `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` tokens (`Severity.HIGH`, `confidence=0.95`).
3. **Google API keys**: Matches `AIza[0-9A-Za-z-_]{33,40}` (`Severity.HIGH`, `confidence=0.95`).
4. **AWS access key IDs**: Matches `AKIA` and `ASIA` prefixes (`Severity.HIGH`, `confidence=0.90`).
5. **Slack-style tokens**: Matches `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-` (`Severity.HIGH`, `confidence=0.95`).
6. **JSON Web Tokens (JWT)**: Matches 3-part Base64URL headers/payloads without decoding payload content (`Severity.HIGH`, `confidence=0.85`).
7. **Bearer authentication tokens**: Matches `Authorization: Bearer <token>` and standalone Bearer tokens without triggering on ordinary prose (`Severity.HIGH`, `confidence=0.85`).
8. **Explicit credential assignments**: Matches assignments such as `api_key=...`, `client_secret=...`, `password=...`, `private_key=...` (`Severity.HIGH`, `confidence=0.80`).

**False-Positive Mitigation**:
- Filters obvious placeholders (e.g. `YOUR_API_KEY`, `<TOKEN>`, `REPLACE_ME`, `CHANGEME`, `dummy-token`).
- Rejects empty values and conversational prose mentioning security terminology without assignment syntax.
- Deduplicates identical spans between generic assignments and specific token patterns.

---

## 7. Policy Engine & Precedence Model

The `PolicyEngine` evaluates the aggregated list of `DetectionResult` objects against declarative `PolicyRule` objects to produce an explainable `PolicyDecision`.

### Core Architectural Separation

$$\mathbf{DETECTION \ne POLICY \ne TRANSFORMATION}$$

- **Detector**: *"What did I find?"* (Observes text, emits `DetectionResult[]`).
- **Policy**: *"What should the firewall do about that finding?"* (Evaluates findings, emits `PolicyDecision`).
- **Transformation**: *"How should the content be modified?"* (Applies masking/redaction if action is `REDACT`).

The policy engine operates purely on normalized `DetectionResult` instances; it never inspects raw prompts, runs regexes, or mutates text.

### Policy Rule Model (`PolicyRule`)

A `PolicyRule` specifies deterministic match criteria (evaluated with strict AND logic):
- `rule_id`: Unique non-empty string identifier.
- `action`: Prescribed action (`ALLOW`, `WARN`, `REDACT`, `BLOCK`).
- `description`: Safe diagnostic summary of rule purpose.
- `category`: Optional `DetectionCategory` filter (e.g. `SECRET`, `PII`).
- `minimum_severity`: Optional minimum `Severity` threshold (`INFO < LOW < MEDIUM < HIGH < CRITICAL`).
- `minimum_confidence`: Optional minimum confidence threshold in `[0.0, 1.0]` (inclusive).
- `detector_name`: Optional detector identifier filter.
- `source`: Optional `ContentSource` filter (matched against `finding.location.source`).
- `direction`: Optional `ContentDirection` filter (matched via context or finding metadata).
- `enabled`: Boolean flag (disabled rules never match).
- `priority`: Numeric priority rank (default: 100; higher number = higher precedence).

### Deterministic Conflict Resolution

When multiple rules match across one or more findings, the engine resolves conflicts using an explicit 4-tier sort order:
1. **Rule Priority**: Higher numeric priority wins (`rule.priority` descending).
2. **Action Precedence**: Equal-priority conflicts are resolved by action severity:
   $$\mathbf{BLOCK} > \mathbf{REDACT} > \mathbf{WARN} > \mathbf{ALLOW}$$
3. **Rule Identifier**: Tie-broken by alphabetical order of `rule.rule_id`.
4. **Detection Identifier**: Tie-broken by alphabetical order of `detection.detection_id`.

This guarantees that evaluation is 100% deterministic and independent of the order in which findings are supplied.

### Default Policy Safety

If no rules match or the findings list is empty, the policy engine safely defaults to `PolicyAction.ALLOW` with an explicit diagnostic reason (`"No policy rules matched."` or `"No detections to evaluate."`).

### Privacy-Preserving Explanations

The resulting `PolicyDecision` reason provides clear audit explanations without leaking sensitive data:
- Safe: `"Blocked because high-severity secret matched rule 'block_high_secrets'."`
- Strictly forbidden: Emitting detected API keys, passwords, or raw prompt strings.

---

## 8. Content Transformation & Redaction Engine (Implemented in Step 7)

The transformation layer is the **ONLY** component in the architecture permitted to mutate content. It operates strictly after the `PolicyEngine` has evaluated detection findings and issued a `PolicyAction.REDACT` decision.

### Architectural Separation
$$\mathbf{DETECTION \ne POLICY \ne TRANSFORMATION}$$

- **Detector**: *"What did I find?"* (`DetectionResult[]`)
- **Policy**: *"What should happen?"* (`PolicyDecision`)
- **Transformation**: *"How should the content change?"* (`RedactionResult`)

The `RedactionEngine` does NOT perform secret detection, run regular expressions, evaluate policy rules, inspect network packets, or call external providers.

### Redaction API & Protocol Conformance

The `RedactionEngine` ([`src/aifirewall/transformation/redaction.py`](../src/aifirewall/transformation/redaction.py)) exposes a clean, provider-agnostic signature:

```python
def redact(
    self,
    content: str,
    detections: Sequence[DetectionResult],
    decision: PolicyDecision,
) -> RedactionResult: ...
```

It also implements the `ContentTransformer` structural subtyping protocol:
```python
def transform(
    self,
    content: str,
    detections: Sequence[DetectionResult] | list[DetectionResult],
) -> str: ...
```

### Policy-Controlled Governance
Transformation is strictly governed by the supplied `PolicyDecision`:
- **`ALLOW`**: Returns content unmodified (`changed=False`, `redaction_count=0`).
- **`WARN`**: Returns content unmodified (`changed=False`, `redaction_count=0`).
- **`BLOCK`**: Returns content unmodified in Step 7 (`changed=False`, `redaction_count=0`). Blocking enforcement is handled by the future proxy/pipeline layer.
- **`REDACT`**: Executes surgical redaction on the candidate detections.

### Semantic Category-Aware Placeholders
Sensitive spans are replaced with category-specific placeholders:
- `DetectionCategory.SECRET` $\rightarrow$ `[REDACTED_SECRET]`
- `DetectionCategory.PII` $\rightarrow$ `[REDACTED_PII]`
- `DetectionCategory.PROMPT_INJECTION` $\rightarrow$ `[REDACTED_PROMPT_INJECTION]`
- `DetectionCategory.OTHER` $\rightarrow$ `[REDACTED]`
- Custom placeholder mappings can be configured upon engine instantiation.

### Offset Safety via Right-to-Left Application
Replacing substrings sequentially from left to right mutates subsequent character indices. To eliminate offset drift and guarantee mathematical stability:
1. All candidate spans are validated against content boundaries.
2. Spans are sorted by `char_start` ascending.
3. Overlapping and nested spans are clustered.
4. Replacements are applied strictly from **RIGHT TO LEFT** (`char_start` descending).
Because each replacement only mutates text to the right of earlier candidate offsets, prefix coordinates remain completely valid throughout the entire transformation pass without index re-computation.

### Deterministic Overlap & Nesting Resolution
In a multi-detector pipeline, finding spans may partially overlap or nest. Rather than applying multiple overlapping replacements that corrupt string structure, the engine clusters overlapping spans ($B.\text{char\_start} < A.\text{char\_end}$) into unified maximal replacement spans $[\min(\text{start}), \max(\text{end})]$.

Within each cluster, the winning detection determines the placeholder via a deterministic 4-tier hierarchy:
1. **Severity**: `CRITICAL > HIGH > MEDIUM > LOW > INFO`
2. **Confidence**: Descending float score
3. **Span Length**: Descending span size ($\text{char\_end} - \text{char\_start}$)
4. **Detection ID**: Ascending lexicographical string order

This ensures identical output regardless of input detection ordering or Python list permutations.

### Span Validation & Empty Spans
- Coordinates are validated strictly: $\text{char\_start} \ge 0$, $\text{char\_end} \ge 0$, $\text{char\_start} \le \text{char\_end}$, and $\text{char\_end} \le \text{len(content)}$.
- Violations raise `ValidationError` with privacy-safe diagnostic messages that never leak content or secret fragments.
- Zero-width empty spans ($\text{char\_start} == \text{char\_end}$) contain no text characters and are safely ignored without mutating content.

### Privacy-Preserving Result Model (`RedactionResult`)
The `RedactionResult` model ([`src/aifirewall/transformation/models.py`](../src/aifirewall/transformation/models.py)) provides audit-safe metadata:
- `content`: The resulting string (transformed or original).
- `changed`: Boolean indicating whether transformation occurred.
- `redaction_count`: Number of unique replacement operations applied.
- `redacted_detection_ids`: Sorted tuple of detection IDs that contributed to applied redactions.
- `categories`: Sorted tuple of distinct categories that were redacted.
- **Privacy Rule**: `__repr__` and `__str__` strictly omit `content` to prevent accidental sensitive data disclosure in debuggers or application loggers.

---

## 9. Provider Abstraction & Adapters

Provider adapters implement the `ProviderAdapter` protocol:
- **`normalize_request(raw_dict) -> NormalizedAIRequest`**
- **`normalize_response(raw_dict, request_id) -> NormalizedAIResponse`**
- **`denormalize_request(NormalizedAIRequest) -> raw_dict`**

### Isolation Guarantee
- The core security pipeline has zero knowledge of OpenAI, Anthropic, or Gemini JSON schemas.
- Adding a new provider requires implementing only an adapter class in `src/aifirewall/providers/` and registering its route. Core detection, policy, and transformation logic remains 100% unchanged.

---

## 10. Fail-Open vs. Fail-Closed Analysis

A production security layer must define precise failure modes:

| Failure Scenario | Policy | Rationale |
| :--- | :--- | :--- |
| **Detector Crash / Exception** | **Fail-Closed (Default)** | If a security detector fails unexpectedly, assuming the content is safe creates an unacceptable security bypass. Configurable to Fail-Open for non-critical development modes. |
| **Policy Engine Failure** | **Fail-Closed** | Inability to evaluate policies must result in blocking the request with an internal configuration error. |
| **Normalization Failure (Malformed Input)**| **Fail-Closed** | Malformed requests cannot be reliably inspected and could represent parser-evasion attacks; reject with HTTP 400. |
| **Transformation Error** | **Fail-Closed** | If redaction cannot be verified, forwarding the original text risks leaking plaintext secrets. |
| **Audit Logging System Failure** | **Fail-Open (with Local Stderr Fallback)** | A disk-full or logger crash should not halt legitimate application traffic unless strict compliance mode is explicitly enabled. |
| **Upstream Provider Error (5xx/4xx)** | **Transparent Passthrough** | Upstream model errors are passed back to the client application without firewall interference. |

---

## 11. Privacy-Preserving Audit Logging

Audit logs provide security observability without creating secondary data exfiltration risks:

### What Is Logged by Default
- `event_id`: Unique UUIDv4 identifier for the security event.
- `timestamp`: UTC ISO-8601 timestamp.
- `request_id`: Correlation identifier linking request and response phases.
- `direction`: `"request"` or `"response"`.
- `action_taken`: `"allow"`, `"warn"`, `"redact"`, `"block"`.
- `rule_id` / `detector_name`: Identifier of the policy rule or detector that matched.
- `category` & `severity`: High-level classification (e.g., `category: "api_key"`, `severity: "critical"`).
- `safe_explanation`: Non-sensitive explanation suitable for dashboards and security teams.

### What Is NEVER Logged by Default
- **Raw user prompts and conversational messages.**
- **Actual detected secret values, tokens, or passwords.**
- **Plaintext PII (names, phone numbers, addresses).**
- **Full upstream model responses.**

---

## 12. Streaming & Multimodal Considerations

### Streaming (Chunked Completions)
Model providers frequently stream responses via Server-Sent Events (SSE).
- **Architectural Challenges**: A secret or PII entity may be split across multiple chunk boundaries (e.g., chunk 1: `sk-proj-`, chunk 2: `123456789`). Inspecting individual chunks in isolation causes detection blind spots.
- **Architectural Solution**: The streaming pipeline utilizes a sliding-window buffer. Chunks are held in a small FIFO buffer sufficient to inspect overlapping token windows before emitting events downstream. If a response policy triggers `BLOCK`, the stream is terminated and replaced with an SSE error event.

### Multimodal Content (Images, Audio, Documents)
Modern requests may include base64-encoded images, PDFs, or audio.
- **Content Model Compatibility**: The `NormalizedMessage` structure isolates textual content from binary attachments.
- **Text-First Boundary**: Initial detection engines inspect textual elements, system prompts, metadata, and extracted OCR/transcription text.
- **Binary Extension Points**: Future binary scanners (e.g., steganography, image PII, adversarial visual perturbation) will plug into the existing `Detector` protocol via dedicated content types.

---

## 13. Configuration & CLI Architecture

### Configuration Design
Configuration is specified via a declarative YAML or TOML file:
- **Format**: YAML is chosen for readability and wide familiarity across DevOps and security teams.
- **Validation**: Configurations are strictly validated against a schema at startup. Unknown keys or invalid regex rules abort startup immediately rather than running with insecure defaults.

### Command-Line Interface (CLI)
The project exposes a dedicated CLI (`aifirewall`):
- `aifirewall start`: Launches the local reverse proxy daemon.
- `aifirewall scan "text"`: Offline CLI scanner to test detectors against arbitrary strings.
- `aifirewall test`: Runs built-in diagnostic and self-test routines against local rules.
- `aifirewall config validate`: Checks syntax and rule integrity of configuration files.
- `aifirewall version`: Displays version and build metadata.

---

## 14. Local Mock Provider Design

To enable zero-cost, offline development and automated CI testing without external API credentials, the architecture includes a `MockProvider`:
- Simulates standard OpenAI/Anthropic request-response schemas.
- Programmable response modes:
  - `clean`: Returns a safe, deterministic assistant completion.
  - `echo_secret`: Emits simulated dummy credentials to test response secret detection.
  - `echo_pii`: Emits simulated dummy PII to test response redaction.
  - `error_500`: Simulates upstream service failures to verify graceful error handling.
  - `malformed`: Emits invalid JSON to test response parser resilience.
