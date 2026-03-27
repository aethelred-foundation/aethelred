# Auditor Pack Template

**Document Version:** 1.0
**Last Updated:** 2026-03-25 (SQ23 Deliverable)

---

## Purpose

This template defines the standard structure for subsystem auditor packs. Each squad listed in `docs/operations/SUBSYSTEM_OWNERSHIP.md` must produce an auditor pack following this format before external audit engagement.

---

## Required Sections

### 1. Subsystem Overview

- **Name:** (subsystem name)
- **Squad:** (owning squad ID and name)
- **Scope:** Brief description of what the subsystem does
- **Key Source Paths:** List all relevant source directories and files
- **Language/Stack:** (Go, Rust, Solidity, etc.)
- **External Dependencies:** Libraries, SDKs, oracles, or services this subsystem depends on

### 2. Architecture Overview

Provide a high-level architecture diagram (ASCII or Mermaid) showing:
- Major components and their interactions
- Data flow directions
- External system boundaries
- On-chain vs. off-chain components

### 3. Trust Boundaries

Enumerate every trust boundary the subsystem crosses or enforces:

| Boundary | From | To | Trust Assumption | Verification Mechanism |
|----------|------|----|------------------|----------------------|
| (name) | (component) | (component) | (what is assumed) | (how it is verified) |

### 4. Access Control Matrix

List all roles, permissions, and privilege levels:

| Role | Permissions | Assignment Mechanism | Revocation Mechanism |
|------|-------------|---------------------|---------------------|
| (role name) | (what can this role do) | (how is it granted) | (how is it removed) |

### 5. Key State Transitions

Document the critical state machines and transitions:

| State | Trigger | Next State | Validation | Reversible? |
|-------|---------|------------|------------|-------------|
| (from) | (event) | (to) | (checks performed) | Yes/No |

### 6. Known Risks and Mitigations

| Risk ID | Description | Severity | Mitigation | Status |
|---------|-------------|----------|------------|--------|
| R-001 | (description) | Critical/High/Medium/Low | (mitigation strategy) | Mitigated/Accepted/Open |

### 7. Test Evidence

| Evidence Type | Location | Coverage/Result |
|---------------|----------|-----------------|
| Unit tests | (path or CI link) | (coverage %) |
| Integration tests | (path or CI link) | (pass/fail) |
| Fuzz tests | (path or CI link) | (runs, corpus size) |
| Load tests | (path or CI link) | (TPS, latency) |
| Static analysis | (tool + CI link) | (findings count) |

Include links to CI dashboards, coverage reports (`make test-coverage`), and fuzz campaign results.

### 8. Previous Audit Findings and Remediation

| Finding ID | Auditor | Severity | Description | Status | Remediation PR |
|------------|---------|----------|-------------|--------|----------------|
| (id) | (firm) | (severity) | (summary) | Fixed/In Progress/Accepted | (link) |

---

## Submission Checklist

Before submitting the auditor pack for external review:

- [ ] All sections above are complete
- [ ] Architecture diagram is current and matches the code
- [ ] Trust boundaries reflect the latest code, not design docs
- [ ] Access control matrix has been verified against deployed contracts/configs
- [ ] Test evidence links are live and accessible
- [ ] Previous audit findings have up-to-date remediation status
- [ ] Pack has been reviewed by squad lead and security team
- [ ] Sensitive information (keys, internal hostnames, credentials) has been removed
