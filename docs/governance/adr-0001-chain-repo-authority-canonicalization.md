# ADR-0001: Canonical Public Repository Authority

Status: Proposed for Foundation ratification

Date: 2026-03-13

`AethelredFoundation/aethelred` is the proposed canonical public repository for
chain releases, security patch provenance, and the Foundation GitHub source of
truth.

This decision aligns the governance documents with the current public
organization structure and removes ambiguity introduced by earlier placeholder
repo names.

Interim enforcement is active via:

- `repo-authority.json`
- `repo-role.json`
- `.github/workflows/repo-authority-guard.yml`
- Foundation authority and GitHub standards registries

Until ratification is complete:

- Treat `AethelredFoundation/aethelred` as canonical interim authority.
- Publish chain releases only from `AethelredFoundation/aethelred`.
- Treat standalone repos as scoped distribution surfaces, not competing chain
  authorities.

Required ratifiers:

- Foundation governance delegate
- Protocol engineering lead
- Security lead or auditor liaison

Ratification record:

- Foundation governance delegate: `PENDING`
- Protocol engineering lead: `PENDING`
- Security lead / auditor liaison: `PENDING`
- Ratified on: `PENDING`
