# Aethelred Bug Bounty Severity Matrix

## Severity Framework

Severity is assigned based on:

- exploitability in the supported release
- attacker prerequisites
- impact on funds, consensus, custody, governance, or trust
- recoverability and blast radius

The examples below are illustrative, not exhaustive.

## Current Active Payout Bands

These bands apply to the **current private protocol bounty**.

| Severity | Typical impact | Current reward band |
|---|---|---:|
| Critical | funds risk, consensus safety failure, systemic validator compromise | `$25,000 - $100,000` |
| High | severe security bypass, governance or slashing integrity failure, material protocol exploit | `$7,500 - $25,000` |
| Medium | meaningful but bounded protocol abuse or denial of service | `$1,500 - $7,500` |
| Low | limited security weakness with clear constraints | `$250 - $1,500` |

## Planned Public-Mainnet Bands

These are the **target** public-mainnet bands and are not yet active.

| Severity | Planned ceiling |
|---|---:|
| Critical | up to `$250,000` |
| High | up to `$75,000` |
| Medium | up to `$20,000` |
| Low | up to `$2,500` |

## Critical

Typical examples:

- unauthorized mint, theft, or irreversible custody loss
- consensus safety break causing chain forks, double-spend, or permanent halt
- validator or governance control bypass enabling systemic takeover
- TEE or attestation bypass allowing fraudulent compute acceptance at protocol level
- bridge exploit causing unauthorized release, mint, or accounting corruption

Target response:

- acknowledgement: `24h`
- triage decision: `72h`
- containment: immediate

## High

Typical examples:

- slash evasion or appeals abuse with real economic impact
- governance privilege escalation below full systemic takeover
- randomness or assignment manipulation with real extractable value
- protocol authentication or authorization bypass with severe state integrity impact
- validator image flaw enabling remote compromise in supported deployments

Target response:

- acknowledgement: `24h`
- triage decision: `5 business days`

## Medium

Typical examples:

- practical denial of service with bounded blast radius
- replay, ordering, or validation flaws without direct theft path
- exploitable confidentiality issue involving protocol metadata or operator secrets
- protocol abuse requiring elevated but realistic preconditions

Target response:

- acknowledgement: `48h`
- triage decision: `7 business days`

## Low

Typical examples:

- constrained weakness with limited practical impact
- exploit requiring unrealistic preconditions or unusually privileged access
- incomplete hardening where a credible exploit path is weak but still real

Target response:

- acknowledgement: `5 business days`
- triage decision: `10 business days`

## Reward Modifiers

Factors that can increase a reward:

- clean reproduction with working proof of concept
- impact reaches multiple protocol domains
- issue affects both `main` and the supported release branch
- report materially reduces triage or patching time

Factors that can reduce or eliminate a reward:

- duplicate report
- exploit depends on already compromised secrets without protocol weakness
- issue is theoretical only
- issue affects an unsupported branch or non-scoped asset
- submission quality is too weak to validate
