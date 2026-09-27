# Security Policy

## Supported Versions

Only the latest pre-alpha release is actively evaluated for security fixes:

| Version | Supported | Notes |
| :--- | :--- | :--- |
| **0.1.x** | :white_check_mark: | Current active release branch |
| **< 0.1.0** | :x: | Experimental development increments |

---

## Project Scope & Maturity

AI Data Firewall is currently in **early development (v0.1.0 pre-alpha)**. While core secret detection, policy evaluation, right-to-left redaction, provider adapters, and local proxying are implemented and tested, the software is experimental and under active development. It must not be relied upon as a sole enterprise security perimeter.

---

## Reporting a Vulnerability

We take the security of AI Data Firewall seriously. If you discover a security vulnerability or potential security flaw:

- **Do NOT open a public issue.** Please avoid disclosing potential vulnerabilities publicly until the maintainers have had an opportunity to review and address them.
- **GitHub Security Advisories:** Please submit your findings via GitHub's private vulnerability reporting feature (under the "Security" tab -> "Advisories" -> "Report a vulnerability").
- **Maintainer Notification:** Private vulnerability reports will be handled exclusively by project maintainers through GitHub's advisory workflow.

When reporting an issue, please include:
- A description of the issue and its potential security impact.
- Clear reproduction steps or a minimal proof of concept.
- Relevant environment or configuration details.
- **Never include live credentials, secrets, or sensitive production data in reports.**

---

## Responsible Disclosure

We ask that researchers practice responsible disclosure:
1. Allow reasonable time for the maintainers to investigate, verify, and remediate the reported vulnerability before sharing details publicly.
2. Make a good-faith effort to avoid privacy violations, data destruction, and service degradation.
3. Use only synthetic dummy credentials in proof-of-concept tests.

---

## Security Disclaimer

- **Pre-Alpha Status:** The software is experimental. Users and adopters remain responsible for evaluating security and compliance requirements.
- **Detection Imperfection:** Pattern-based and heuristic detection mechanisms inherently carry false-positive and false-negative risks.
- **Defense in Depth:** AI Data Firewall is intended to serve as one layer in a defense-in-depth architecture.
