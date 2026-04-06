# Aethelred Bug Bounty Triage Playbook

## Purpose

This playbook defines how Aethelred should operate the protocol bug bounty as a
repeatable security function rather than an ad hoc inbox.

## Internal Owners

| Function | Owner |
|---|---|
| Intake and first response | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Severity assignment | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Engineering fix owner | Relevant protocol owner |
| Release decision | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Reward approval | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |
| Disclosure signoff | `Ramesh Tamilselvan <rameshtamilselvan@gmail.com>` |

## Intake Checklist

For every report:

1. assign a tracking ID
2. confirm scope eligibility
3. confirm support status of affected branch, release, or image
4. verify reproducibility
5. classify severity
6. assign engineering owner
7. determine whether immediate mitigation is needed

## Evidence Required

Accepted findings should capture:

- affected branch, tag, or image
- impacted code paths
- exploit steps
- blast radius
- containment decision
- fix PR or commit
- regression proof
- reward decision
- disclosure date

## Severity Decision Rules

Use the matrix in [BUG_BOUNTY_SEVERITY_MATRIX.md](BUG_BOUNTY_SEVERITY_MATRIX.md)
and bias toward the higher tier when:

- the issue crosses trust boundaries
- the exploit is reliable
- the exploit affects consensus, custody, or validator control

Bias toward the lower tier when:

- exploitability depends on unrealistic assumptions
- impact is operationally recoverable and tightly bounded

## Patch Workflow

1. reproduce on a controlled branch
2. create minimal containment if immediate risk exists
3. patch the root cause
4. add regression coverage
5. validate on supported branches
6. prepare release notes and disclosure decision

## Reward Workflow

1. confirm the issue is valid and non-duplicate
2. assign final severity
3. apply reward modifiers
4. approve payout in USD value with `USDC` as the default payment rail
5. record payment method and date

## Disclosure Workflow

No issue should be publicly disclosed before:

- mitigation or fix is deployed
- operator or validator coordination is complete where needed
- legal/compliance review is complete for sensitive cases

## Program Metrics

Track at minimum:

- acknowledgement time
- triage time
- time to containment
- time to fix
- reward turnaround time
- duplicate rate
- severity distribution

## Launch Checklist

Before calling the program operational:

- `SECURITY.md` published
- response mailbox monitored
- severity matrix approved
- reward bands approved
- fix owners identified
- disclosure signoff path documented
- interim named owners assigned
