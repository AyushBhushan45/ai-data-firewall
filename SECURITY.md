# Security Policy

## Project Scope & Maturity

AI Data Firewall is currently in **early development (pre-alpha)**. Architectural components, interfaces, and core engines are being developed incrementally. At this phase, security boundaries, detection algorithms, and policy enforcement mechanisms are under active initial design and are not yet fully implemented.

## Reporting a Vulnerability

We take the security of AI Data Firewall and the systems it aims to protect seriously. If you discover a security vulnerability or potential security flaw:

- **Do NOT open a public issue.** Please avoid disclosing potential vulnerabilities publicly until the maintainers have had an opportunity to review and address them.
- **GitHub Security Advisories:** Once enabled, please submit your findings via GitHub's private vulnerability reporting feature (under the "Security" tab -> "Advisories" -> "Report a vulnerability").
- **Designated Channel:** Dedicated encrypted contact points (such as project PGP keys and an official security inbox) will be established and published prior to the first public production release.

When reporting an issue, please include:
- A description of the issue and potential impact.
- Clear reproduction steps or a minimal proof of concept.
- Any relevant context regarding the environment or configuration.

## Responsible Disclosure

We ask that reporters practice responsible disclosure:
1. Allow reasonable time for the maintainers to investigate, verify, and remediate the reported vulnerability before sharing details publicly.
2. Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of service during vulnerability research.
3. Do not include actual live credentials, secrets, or sensitive personal data in your reports or test fixtures.

## Security Disclaimer

Please note the following critical boundaries:

- **Pre-Alpha Status:** The software in this repository is experimental and under active development. It must not be relied upon as a production security boundary or sole security mechanism.
- **Detection Imperfection:** Any heuristic, pattern-based, or model-assisted detection mechanism carries inherent risks of false positives and false negatives. No automated system can provide absolute guarantees.
- **Defense in Depth:** AI Data Firewall is intended to serve as one layer in a defense-in-depth architecture. Users and adopters remain responsible for evaluating the security, privacy, and regulatory requirements of their applications and deployments.
