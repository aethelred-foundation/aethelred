# Security Policy

## Scope

This repository (`aethelred-cosmos-node`) is in scope for security review for the code and configuration it contains.

Cosmos SDK chain implementation (candidate canonical chain repo; authority notice in README pending org ratification).

## Supported Branches

Unless otherwise documented, `main` is the reference branch for security fixes and disclosures.

## Reporting a Vulnerability

Until a dedicated security contact is published, report suspected vulnerabilities privately to the Aethelred Foundation security team through the organization's designated private channel.

Include:
- affected repository and commit/tag
- impact summary
- reproduction steps / proof-of-concept
- suggested mitigations (if known)

## Disclosure Expectations

- Do not disclose vulnerabilities publicly before a coordinated fix window is agreed.
- The Foundation should acknowledge receipt, triage severity, and provide remediation status updates.

## Hardening Requirements (Repository Baseline)

- Threat model maintained under `docs/security/threat-model.md`
- SBOM generated in CI for default branch and releases
- Docs hygiene checks (no local workstation paths)
- CI evidence retained for test/security jobs
