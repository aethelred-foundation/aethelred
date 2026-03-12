# Aethelred Improvement Proposals (AIPs)

[![AIP Lint](https://img.shields.io/github/actions/workflow/status/aethelred/AIPs/aip-lint.yml?style=flat-square&label=AIP+Lint)](https://github.com/AethelredFoundation/AIPs/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)

AIPs are the primary mechanism for proposing protocol changes, new features, and standards in the Aethelred ecosystem - analogous to [Ethereum EIPs](https://eips.ethereum.org/), [Cosmos ADRs](https://docs.cosmos.network/main/build/architecture), and [Aptos AIPs](https://github.com/aptos-foundation/AIPs).

---

## AIP Index

| AIP | Title | Status | Category |
|---|---|---|---|
| [AIP-0001](AIPs/AIP-0001.md) | AIP Purpose and Guidelines | `Final` | Meta |
| [AIP-0002](AIPs/AIP-0002.md) | Proof-of-Useful-Work Consensus Specification | `Draft` | Core |
| [AIP-0003](AIPs/AIP-0003.md) | Digital Seal Standard | `Draft` | Standard |

---

## AIP Statuses

```
Idea → Draft → Review → Final
                ↓
             Withdrawn
```

| Status | Meaning |
|---|---|
| `Idea` | Pre-draft, informal discussion |
| `Draft` | Formal proposal, open for feedback |
| `Review` | Core team review + governance vote |
| `Final` | Accepted and implemented |
| `Withdrawn` | Abandoned by author |
| `Replaced` | Superseded by a newer AIP |

---

## How to Submit an AIP

1. **Discuss first**: Open a GitHub Discussion or post in Discord `#aip-discussion`
2. **Fork** this repo and copy `AIPs/AIP-TEMPLATE.md` to `AIPs/AIP-XXXX.md`
3. Fill in all required frontmatter fields
4. Open a PR - the AIP number will be assigned by a maintainer
5. Engage with feedback and iterate

---

## AIP Format

All AIPs must include the following YAML frontmatter:

```yaml
---
aip: <number>
title: <Short Title>
author: <Name> (@github_handle)
status: Draft
type: Core | Standard | Informational | Meta
created: YYYY-MM-DD
---
```

## Community

- [Discord `#aip-discussion`](https://discord.gg/aethelred)
- [GitHub Discussions](https://github.com/AethelredFoundation/AIPs/discussions)
