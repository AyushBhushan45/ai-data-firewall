# Architecture Decision Records (ADRs)

This document records the foundational architectural decisions made for **AI Data Firewall**. Each record details the context, the decision made, the reasoning behind it, and the consequences for the project.

---

## ADR-001: Separation of Detection and Policy Enforcement

### Context
In security systems, scanning engines often tightly couple the identification of a threat with the enforcement action (e.g., a regex detector immediately throwing an exception or blocking a request).

### Decision
Strictly separate observational scanning (`Detector`) from enforcement decision-making (`PolicyEngine`). Detectors produce `DetectionResult` findings; the `PolicyEngine` evaluates these findings against user-configured rules to decide actions (`ALLOW`, `WARN`, `REDACT`, `BLOCK`).

### Reasoning
- **Modularity**: Allows swapping, tuning, or extending detectors without altering organizational policy logic.
- **Context-Aware Enforcement**: Different deployment environments (development vs. production) can apply different policies to the exact same detection finding.
- **Audit Completeness**: Enables auditing all present security findings in a payload rather than halting on the first match.

### Consequences
- Requires a two-stage pipeline execution: detection aggregation followed by policy evaluation.
- Slightly higher memory overhead to hold `DetectionResult` objects before taking action.

---

## ADR-002: Local-First, Zero-Mandatory-Cloud Architecture

### Context
Many modern AI security tools rely on cloud-hosted SaaS APIs for prompt inspection, embedding analysis, and telemetry collection.

### Decision
AI Data Firewall is designed from inception as a **local-first** security tool. Core detection, policy evaluation, audit logging, and proxying must execute entirely within the user's infrastructure without mandatory external cloud connections.

### Reasoning
- **Data Sovereignty**: AI applications frequently process trade secrets, confidential customer data, and source code. Requiring traffic to pass through a third-party security cloud creates the very privacy vulnerability users seek to mitigate.
- **Cost & Latency**: Local execution eliminates egress bandwidth costs, SaaS subscription fees, and network round-trip latency.
- **Offline Resilience**: The firewall can operate in air-gapped environments, local development machines, or private virtual clouds.

### Consequences
- Advanced detectors requiring heavy machine learning models must be lightweight enough to run on standard host hardware or rely on deterministic pattern heuristics.
- No centralized dashboard or hosted multi-tenant management is provided in the core project.

---

## ADR-003: Provider-Agnostic Core via Internal Normalization

### Context
AI providers (OpenAI, Anthropic, Google Gemini, Ollama, Mistral) utilize divergent JSON schemas for chat completions, tool calls, and system instructions.

### Decision
The core security and policy engines operate exclusively on a normalized internal representation (`NormalizedAIRequest` and `NormalizedAIResponse`). Provider-specific serialization and schema details are isolated inside the `providers/` adapter layer.

### Reasoning
- **Zero Schema Leakage**: Prevents provider-specific idiosyncrasies from proliferating into detection algorithms.
- **Extensibility**: Adding support for a new model provider requires writing only an adapter that maps external formats to and from the normalized model.
- **Consistent Security Semantics**: Ensures that policies and detectors behave identically regardless of which model provider is invoked.

### Consequences
- Incurs a small translation overhead when normalizing incoming requests and denormalizing outgoing requests.
- When providers introduce proprietary, non-standard features, the normalized model must provide a generic metadata container to preserve pass-through fields.

---

## ADR-004: Privacy-Preserving Audit Logging (No Raw Payloads by Default)

### Context
Security tools must generate audit logs for visibility, compliance, and forensics. However, logging prompt bodies and model completions in plaintext can turn the security log into a dangerous repository of leaked credentials and PII.

### Decision
By default, audit logs (`SecurityEvent`) record only metadata: timestamps, correlation IDs, matched rule names, detection categories, severity ratings, and non-sensitive explanations. **Raw prompt text, raw model completions, and detected secret values are strictly excluded from default logs.**

### Reasoning
- **Principle of Least Privilege**: Security operators need to know *that* an API key was blocked, not what the secret key was.
- **Regulatory Compliance**: Prevents logs from becoming subject to GDPR/CCPA data deletion requests due to PII ingestion.
- **Zero Regret**: Ensures that even if audit logs are compromised, attacker value is minimized.

### Consequences
- Debugging edge cases or false positives requires explicitly enabling opt-in diagnostic modes with warning banners.

---

## ADR-005: Strict Deterministic Policy Precedence Model

### Context
When inspecting a multi-part AI prompt, multiple detectors may fire simultaneously. For instance, a high-severity secret detector might recommend `BLOCK`, while a low-confidence PII detector recommends `REDACT` or `WARN`. Ambiguity in resolving conflicting actions leads to security bypasses.

### Decision
Adopt a strict, immutable resolution hierarchy:
$$\mathbf{BLOCK} > \mathbf{REDACT} > \mathbf{WARN} > \mathbf{ALLOW}$$
If any active finding triggers a `BLOCK` rule, the entire transaction is blocked immediately. `REDACT` is executed only if no `BLOCK` actions exist.

### Reasoning
- **Deterministic Predictability**: Eliminates race conditions and non-deterministic behavior during multi-finding evaluations.
- **Fail-Safe Security**: Prioritizes risk containment (blocking potential exfiltration) over partial transmission.

### Consequences
- A single high-severity finding will halt an entire request even if other sensitive entities could have been redacted.

---

## ADR-006: CLI & Local Proxy First (No Mandatory Frontend or Database)

### Context
Open-source projects often burden early users with database setup (PostgreSQL, Redis), message brokers, and web frontend builds before core functionality can be tested.

### Decision
AI Data Firewall requires no database and no frontend. It operates as a single binary/process controlled via CLI commands (`aifirewall start`, `aifirewall scan`) and configuration files, logging to local structured log files (JSONL / stderr).

### Reasoning
- **Developer Velocity**: A developer can install via `pip install aifirewall` and launch in seconds without provisioning Docker containers or databases.
- **Minimal Footprint**: Low memory consumption and zero background database connections make it ideal for embedded local development or container sidecars.
- **Future Separation**: A web UI or centralized database can be introduced later as an optional peripheral without coupling the core security engine.

### Consequences
- Historical log analysis requires standard log-shipping tools (Fluentd, Vector, Datadog) or shell utilities (`grep`, `jq`) rather than a built-in web portal.

---

## ADR-007: Fail-Closed on Security Enforcement, Fail-Open on Non-Critical Telemetry

### Context
Components within a security proxy can experience unexpected exceptions (e.g., regex engine errors, memory spikes, or disk-write failures).

### Decision
Enforce a tiered failure posture:
1. **Security Inspection & Policy Evaluation**: Fail-closed by default. If a detector, normalizer, or policy engine crashes, the request is halted and an internal error is returned.
2. **Audit Logging & Telemetry Sinks**: Fail-open with local stderr fallback. If an external or disk audit sink fails, the request is permitted to proceed while an internal alert is emitted to stderr.

### Reasoning
- **Prevent Silent Bypasses**: Failing open on security detectors would allow attackers to craft malformed payloads that crash a detector and bypass the firewall.
- **Availability Balance**: Crashing production AI traffic because a secondary log storage disk is full disrupts business operations unnecessarily.

### Consequences
- Requires distinct exception boundaries in the pipeline orchestrator for enforcement vs. logging.
