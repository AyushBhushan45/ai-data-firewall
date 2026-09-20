# AI Data Firewall: Complete System Architecture & Technical Design

> [!IMPORTANT]
> **Design-First Architectural Milestone (Step 3)**
>
> This document specifies the comprehensive technical architecture, domain models, protocols, lifecycle pipelines, and engineering boundaries for AI Data Firewall.
>
> **In accordance with Step 3 constraints, core security detectors, proxy runtimes, and provider integrations are NOT yet implemented.** This specification serves as the blueprint for incremental implementation in subsequent phases.

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

The codebase is structured to preserve modularity, deterministic execution, and testability:

```text
src/aifirewall/
├── core/             # Pipeline orchestrator, lifecycle management, and request context
├── models.py         # Foundational domain dataclasses and enums (Normalized models, Results)
├── protocols.py      # Structural subtyping protocols (Detector, ProviderAdapter, PolicyEngine)
├── detectors/        # Observational scanner modules (secrets, PII, prompt injection)
├── policies/         # Deterministic rule evaluation, precedence logic, decision types
├── transform/        # Safe content transformation (masking, redaction, replacement)
├── normalization/    # Provider-specific payload mapping to/from internal normalized models
├── providers/        # Provider adapters (OpenAI, Anthropic, Gemini, Ollama, MockProvider)
├── proxy/            # Local HTTP/reverse-proxy server and routing middleware
├── logging/          # Privacy-preserving audit event recording and serializers
├── config/           # Declarative configuration loader, schema validation, and defaults
└── cli/              # Command-line interface entry points (start, scan, test, config)
```

### Module Ownership Matrix

| Module | Primary Responsibility | Explicit Non-Responsibilities |
| :--- | :--- | :--- |
| `core/` | Request/response lifecycle orchestration, context tracking, error handling. | Does not execute pattern matching or evaluate policy rules. |
| `models.py` | Canonical typed dataclasses and enums for requests, responses, detections, and events. | Contains zero business logic, I/O, or parsing code. |
| `protocols.py` | Standard interface contracts ensuring modular subtyping across subsystems. | Contains zero concrete implementations. |
| `detectors/` | Observational inspection of normalized text spans; produces `DetectionResult[]`. | Never decides enforcement actions (`ALLOW`, `BLOCK`). |
| `policies/` | Evaluates `DetectionResult[]` against declarative rules to decide `PolicyAction`. | Does not scan raw strings or perform regex matching. |
| `transform/` | Applies surgical text transformations (e.g., masking) based on policy decisions. | Does not decide which rules apply or detect vulnerabilities. |
| `normalization/`| Maps external JSON structures into `NormalizedAIRequest`/`Response`. | Never alters prompt semantics or executes security checks. |
| `providers/` | Manages upstream connection protocols, HTTP headers, and client interactions. | Does not inspect payloads for security violations. |
| `proxy/` | Ingests incoming network traffic, terminates HTTP, and forwards sanitized streams. | Independent of security detection algorithms. |
| `logging/` | Records structured, privacy-safe `SecurityEvent` audit entries. | Never persists raw prompts, credentials, or full completions. |
| `config/` | Loads, validates, and freezes YAML/TOML configuration at startup. | Does not dynamically mutate configuration during requests. |
| `cli/` | Exposes administrative commands and standalone scanner utilities. | Does not contain embedded detection or proxy logic. |

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

## 5. Domain Models & Protocols

### Normalized Representations
Rather than forcing detectors and policy engines to parse varied vendor formats, the system operates on immutable internal dataclasses defined in [`src/aifirewall/models.py`](../src/aifirewall/models.py):

- **`NormalizedAIRequest`**: Contains `request_id`, `model`, a list of `NormalizedMessage` objects, model parameters (e.g., temperature), and request metadata.
- **`NormalizedMessage`**: Contains `role` (`system`, `user`, `assistant`, `tool`), `content` (normalized text), and `ContentSource` classification.
- **`NormalizedAIResponse`**: Contains `request_id`, `model`, completion `content`, `finish_reason`, and provider metadata.

### Content Location Tracking
To pinpoint where findings occur without re-parsing raw payloads, findings include a `ContentLocation`:
- `source`: `ContentSource` enum (`USER_INPUT`, `SYSTEM_INSTRUCTION`, `RETRIEVED_DOCUMENT`, `TOOL_OUTPUT`, `MODEL_OUTPUT`).
- `message_index`: Index of the message in the conversational history array.
- `char_start` & `char_end`: Zero-indexed character slice boundaries within the text block.
- `field_path`: Dot-notation path to the inspected attribute (e.g., `messages[2].content`).

### Finding & Decision Representations
- **`DetectionResult`**: Captures `detector_name`, `category`, `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `confidence` (float between 0.0 and 1.0), `location`, `description`, and `recommended_action`. **Never stores the raw sensitive value.**
- **`PolicyDecision`**: Encapsulates `action` (`ALLOW`, `WARN`, `REDACT`, `BLOCK`), `reason`, `matched_rules`, and referenced `detections`.
- **`SecurityEvent`**: Standardized audit log entry containing `event_id`, `timestamp`, `request_id`, `direction`, `action_taken`, `safe_explanation`, and sanitized detection summaries.

---

## 6. Detector Architecture

Detectors are self-contained modules implementing the `Detector` protocol defined in [`src/aifirewall/protocols.py`](../src/aifirewall/protocols.py):

```python
class Detector(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def category(self) -> str: ...
    def detect(
        self, content: str, location: ContentLocation
    ) -> list[DetectionResult]: ...
```

### Core Detector Principles
1. **Strict Separation of Observation and Enforcement**: Detectors *only identify conditions*; they never make enforcement decisions. Enforcement belongs solely to the `PolicyEngine`.
2. **Deterministic Execution**: Given the same input string and context, a detector must always yield the identical findings.
3. **Failure Isolation**: An unhandled exception inside any individual detector must be trapped by the pipeline orchestrator, logged as an internal diagnostic event, and handled according to the fail-safe policy without crashing the firewall process.
4. **Execution Strategy**:
   - For Phase 1, detectors run **sequentially and deterministically** in a configured order (e.g., High-Confidence Secrets -> PII -> Heuristic Prompt Injection).
   - Fast deterministic regex scans run before heavier linguistic or structural heuristics.
   - All enabled detectors run across all extracted content blocks to ensure complete audit coverage.

---

## 7. Policy Engine & Precedence Model

The `PolicyEngine` evaluates the aggregated list of `DetectionResult` objects against user-configured rules.

### Deterministic Action Precedence
When multiple detectors produce findings with differing recommended actions, the policy engine resolves conflicts using a strict, deterministic hierarchy:

$$\mathbf{BLOCK} > \mathbf{REDACT} > \mathbf{WARN} > \mathbf{ALLOW}$$

- If any active finding triggers a `BLOCK` rule, the **entire request is blocked immediately**.
- If no finding triggers `BLOCK`, but one or more findings trigger `REDACT`, the **request is allowed after transforming the sensitive spans**.
- If findings trigger only `WARN`, the request proceeds unaltered, and warning events are logged.
- If no rules match or all findings evaluate to `ALLOW`, the request proceeds silently.

### User Rule Overrides
User-defined policy rules take explicit precedence over detector default recommendations. For example:
- A developer may configure: `category: "openai_api_key" -> action: BLOCK` (overriding a default `WARN`).
- A developer in a local test environment may configure: `category: "email" -> action: WARN` (overriding a default `REDACT`).

---

## 8. Content Transformation & Overlapping Spans

When a `REDACT` action is decided, the `ContentTransformer` modifies the text before forwarding:

### Transformation Types
- **Masking / Redaction**: Replaces sensitive spans with descriptive token placeholders, e.g., `[REDACTED:API_KEY]`, `[REDACTED:EMAIL]`.
- **Character Masking**: Replaces interior characters with fixed masks, e.g., `sk-••••••••••••`.
- **Synthetic Replacement**: Substitutes realistic dummy values for testing pipelines.

### Handling Overlapping Spans
If two detectors flag overlapping character spans (for example, a secret pattern containing characters that also resemble an email address):
1. **Sort Spans**: Findings are sorted by `char_start` ascending, and by length descending.
2. **Union / Merge**: Overlapping or nested spans are merged into a single maximal replacement span.
3. **Reverse Replacement**: Transformations are applied from the end of the string to the beginning (`char_start` descending) to ensure that earlier character offsets remain valid throughout the transformation pass.
4. **Text Integrity**: Unmatched characters outside the replacement spans are strictly preserved to prevent payload corruption.

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
