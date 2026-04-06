# Aethelred Bug Bounty SLA

## Purpose

This document defines the operating service levels for the Aethelred protocol bug
bounty and coordinated vulnerability disclosure workflow.

## Submission States

| State | Meaning |
|---|---|
| Received | Submission entered intake queue |
| Acknowledged | Reporter received first response |
| Triage | Security team validating impact and reproduction |
| Accepted | Valid issue with assigned severity and owner |
| Fix In Progress | Engineering owner assigned and patch underway |
| Mitigated | Immediate risk reduction in place |
| Resolved | Fix merged and validated |
| Rewarded | Reward decision finalized and payment approved |
| Disclosed | Public disclosure approved and published |

## Response SLAs

| Severity | Acknowledge | Triage decision | Update cadence |
|---|---:|---:|---:|
| Critical | 24 hours | 72 hours | every 24 hours |
| High | 24 hours | 5 business days | every 3 business days |
| Medium | 48 hours | 7 business days | weekly |
| Low | 5 business days | 10 business days | at milestones |

## Remediation Targets

| Severity | Target containment | Target resolution |
|---|---:|---:|
| Critical | immediate | 7 days or approved emergency window |
| High | 5 business days | 21 days |
| Medium | 10 business days | 45 days |
| Low | next planned hardening cycle | 90 days |

These are operating targets, not absolute contractual guarantees. Issues with
cross-chain, custody, or external dependency implications may require a longer
coordinated remediation window.

## Disclosure Windows

- Critical issues: disclosure after containment, remediation, and explicit
  executive/security approval
- High issues: disclosure normally after production deployment and regression
  validation
- Medium and Low issues: disclosure may be batched into a security release note

## Communication Rules

- all security communication stays private until disclosure is approved
- all accepted issues receive a named internal owner
- all accepted issues must have an evidence trail in issue tracking and release
  artifacts
- all resolved issues require regression coverage or a written rationale when a
  test is not feasible

## Exclusions From Reward Eligibility

- unsupported branch-only issues
- already known internal issues
- public information leaks with no security consequence
- findings that require compromised root credentials without a protocol flaw
- volumetric denial-of-service without a protocol weakness

## Escalation Triggers

The following conditions trigger executive-security escalation:

- credible funds-at-risk scenario
- chain safety or liveness risk
- validator or governance privilege escalation
- exploit path affecting custody or bridge invariants
- issue likely to require emergency halt, rollback, or coordinated operator action
