# AI Data Firewall Architecture

> [!IMPORTANT]
> **Planned Architecture**
>
> The architectural design described in this document outlines the conceptual target for future stages of AI Data Firewall. **None of the functional components described below (inspection engines, policy engines, proxies) are implemented in the current foundation release.**

---

## Conceptual Overview

AI Data Firewall is designed to act as an intermediary security inspection and policy enforcement layer positioned between an AI application (the client) and an upstream AI provider or model runtime.

```text
AI APPLICATION
      |
      v
AI DATA FIREWALL
      |
      +--> Request Inspection
      |
      +--> Detection Engine
      |
      +--> Policy Engine
      |
      +--> Forwarding Layer
      |
      v
AI PROVIDER / MODEL
      |
      v
Response Inspection
      |
      v
AI APPLICATION
```

---

## Planned Core Subsystems

### 1. Request Inspection Layer
- **Role**: Intercepts outgoing requests originating from the client application before they leave the secure perimeter.
- **Responsibilities**:
  - Validates request structure and schemas.
  - Normalizes text payloads across message roles (e.g., system instructions, user prompts, assistant messages, tool outputs).
  - Prepares extracted text blocks for evaluation by the detection engine.

### 2. Detection Engine
- **Role**: Evaluates extracted content against specialized detectors to identify potential security, privacy, or policy concerns.
- **Planned Detectors**:
  - *Secrets Detector*: Identifies API keys, private keys, authentication tokens, passwords, and connection strings.
  - *PII Detector*: Identifies Personally Identifiable Information such as emails, phone numbers, and identity numbers.
  - *Prompt Injection Detector*: Evaluates heuristic and structural indicators of adversarial prompt manipulations.
- **Design Requirement**: Every detector will be implemented as an independent, deterministic, and modular component adhering to a shared interface.

### 3. Policy Engine
- **Role**: Interprets detection findings and applies user-defined rules to determine the appropriate enforcement action.
- **Planned Actions**:
  - `ALLOW`: The payload is permitted without alteration.
  - `WARN`: The payload is permitted, but an audit warning is generated.
  - `REDACT`: Sensitive tokens or entities are masked/redacted in place before forwarding.
  - `BLOCK`: The request is halted, and a structured security error is returned to the caller.

### 4. Forwarding Layer
- **Role**: Handles communication with upstream AI model providers.
- **Responsibilities**:
  - Transparent HTTP proxying to target endpoints (e.g., local LLM instances, remote API providers).
  - Preserving connection headers, streaming protocols, and authentication headers intended for the upstream provider.

### 5. Response Inspection Layer
- **Role**: Intercepts and scans completions returned by the model before they reach the requesting application.
- **Responsibilities**:
  - Scans model outputs for accidental regurgitation of sensitive information or policy-violating patterns.
  - Applies matching post-flight policies (e.g., output redaction or blocking).

---

## Architectural Principles

1. **Explicit Boundaries**: Each component has single-purpose responsibilities and clearly typed input/output boundaries.
2. **Local-First & Offline Capable**: Security analysis should run in-process or on local networks without mandatory external lookups.
3. **Extensibility**: Third-party detectors and custom policy rules can be registered without altering core firewall internals.
4. **Auditability**: Security actions generate transparent, reproducible audit logs without logging sensitive prompt payloads in plaintext.
