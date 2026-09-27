# AI Data Firewall Roadmap

This roadmap documents the planned evolution of AI Data Firewall.
As an open-source project in early development (v0.1.0 pre-alpha), priorities are organized into high-level phases rather than calendar deadlines.

---

## Current Release: v0.1.0 (Pre-Alpha)

The baseline security foundation:
- **Core Security Domain**: Unified domain models (`NormalizedAIRequest`, `NormalizedAIResponse`, `ContentLocation`, `DetectionResult`).
- **Detection**: `SecretDetector` with entropy calculation and pattern matching for major credential families.
- **Policy Engine**: Declarative rule evaluation with deterministic action resolution (`ALLOW` < `WARN` < `REDACT` < `BLOCK`).
- **Transformation**: Right-to-left in-place string redaction preserving character offsets.
- **Local HTTP Proxy**: FastAPI + Uvicorn reverse proxy with strict localhost defaults, anti-open-proxy enforcement, and body size limits.
- **Provider Adapters**: Normalization adapters for OpenAI, Anthropic, Google Gemini, and Ollama APIs.
- **CLI & Configuration**: `aifirewall` command-line interface with TOML/JSON configuration and offline scanning.
- **Test Infrastructure**: Comprehensive offline automated test suite.

---

## Planned (Next Milestone)

Immediate focus areas following the initial public release:

### 1. Server-Sent Events (SSE) Streaming Inspection
- **Objective**: Inspect streaming completions (`text/event-stream`) in real time.
- **Challenges**: Buffering partial token chunks across secret boundary splits without incurring high latency.
- **Proposed Approach**: Sliding token window with partial pattern matching; stream abort on block; token masking on redaction.

### 2. Expanded Secret Detection Signatures
- **Objective**: Broaden the catalog of supported credential formats.
- **Areas**: Cloud provider service account keys, database connection URIs, private keys (PEM/SSH), and third-party SaaS tokens.

### 3. Personally Identifiable Information (PII) Detector
- **Objective**: Detect and mask sensitive personal data (e.g., email addresses, phone numbers, government ID formats).
- **Design Constraint**: Local-first and offline; zero reliance on cloud NER or external API endpoints.

### 4. Basic Prompt Injection Detector
- **Objective**: Detect common heuristic prompt injection and jailbreak patterns in incoming prompts.
- **Design Constraint**: Fast heuristic evaluation suitable for proxy ingress without substantial latency penalties.

### 5. Performance Benchmarks
- **Objective**: Establish reproducible latency and throughput benchmarks for local proxy overhead.

---

## Future

Planned capabilities for subsequent minor releases:

### 1. Additional Provider Adapters
- Support for additional popular inference schemas (e.g., Cohere, Mistral, AWS Bedrock format).

### 2. Custom Detector Plugin Architecture
- Documented entry-point mechanisms allowing organizations to add internal proprietary detectors without forking the codebase.

### 3. Advanced Contextual Policies
- Policies based on user identity headers, model names, prompt token counts, or specific tool call arguments.

---

## Exploratory

Long-term research areas undergoing architectural evaluation:

### 1. Multimodal Semantic Scanning
- Deep semantic content inspection for image, audio, and document attachments passed in multimodal requests.

### 2. Privacy-Preserving Audit Sinks
- Optional adapters for structured logging destinations (e.g. syslog, SIEM) that strictly enforce zero-retention of raw prompt bodies and credentials.

---

## How to Contribute to the Roadmap

Interested in working on any of these areas? Please check [CONTRIBUTING.md](../CONTRIBUTING.md) and join discussions in the issue tracker.
