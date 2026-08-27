# ADR-0002 — The 20x Moat: Confidential Verifiable-AI Settlement Network

**Status:** Proposed · **Date:** 2026-07-01 · Supersedes the *scope* of ADR-0001
(the EVM layer becomes **one** layer of a larger stack, and it becomes a
*confidential* EVM).

## The bar

Not a general-purpose L1 for retail speculation. **The settlement and assurance
network for AI used in regulated industries** — finance, healthcare, insurance,
identity, public sector. The moat cannot be a feature; it must be a
*vertically integrated protocol* where six hard capabilities compound. Any one of
them is a startup; a competitor needs *all six, integrated and audited*, which is
a multi-year, deep-expertise effort — not a fork.

## North-star claim

> The only network where an enterprise can run AI **on encrypted, regulated
> data**, obtain a **post-quantum cryptographic proof** that the **correct,
> attested model** produced the output — **without exposing the data or the
> weights** — settle it in **confidential smart contracts**, and hand a regulator
> or court a **portable, formally-grounded evidence pack**.

## The six pillars (the moat is their product, not their sum)

Maturity is graded honestly: **[HAVE]** in the repo today · **[BUILD]** hard but
known engineering · **[FRONTIER]** research-grade, state-of-the-art moving.

### 1. Confidential compute — inference on data the operator never sees
- **[HAVE]** Hardware-agnostic TEE attestation, 6 platforms (SEV-SNP, TDX, SGX,
  Nitro, Azure, GCP). Inference runs inside an attested enclave.
- **[BUILD]** Confidential-GPU inference (NVIDIA H100/H200 confidential-compute
  mode) so *large* models run attested on GPUs, not just CPUs. This is the
  practical frontier for enterprise AI and few chains touch it.
- **[FRONTIER]** FHE (CKKS) and MPC as a second confidentiality tier for the
  highest-sensitivity *small* models — honest caveat: FHE inference is orders of
  magnitude slower and not viable for LLMs today; positioned as an optional,
  clearly-scoped tier, not the default.
- **Why it's a moat:** regulated data (PHI, PII, MNPI) can be processed with a
  cryptographic guarantee the operator/validators never saw it. That is the
  single biggest blocker to enterprise AI adoption, solved at the protocol.

### 2. Verifiable AI across the whole model-size spectrum
- **[HAVE]** zkML via BN254 Groth16 for small models (real pairing verification,
  on-curve + subgroup checks).
- **[HAVE]** Freivalds probabilistic verification for LLM-scale matrix work
  (fast, tunable soundness).
- **[BUILD]** Optimistic execution + fraud proofs for large models (challenge
  window, re-execution), converging with TEE attestation.
- **[FRONTIER]** Sumcheck/GKR-style succinct proofs for transformer inference
  (zkLLM direction). Honest: full succinct-zk for LLM inference is not
  production-ready anywhere in 2026; our edge is the **layered verifier**
  (zk for small, Freivalds+TEE+optimistic for large) with a clean upgrade path
  to zk as it matures — not a claim that zk-LLM is solved.
- **Why it's a moat:** competitors pick one point (Ora/Ritual = optimistic,
  EZKL = small-model zk). A *spectrum* verifier with a single settlement object
  is the defensible position.

### 3. Post-quantum, end to end
- **[HAVE]** ML-DSA-65 / ML-KEM-768 hybrid for validator signing and Digital
  Seals (Cloudflare circl).
- **[BUILD]** ML-KEM for the enclave data-ingestion channel (data encrypted to
  the attested enclave with a PQC KEM) and PQC commitments inside the seal;
  optional SLH-DSA for stateless long-term signatures.
- **Why it's a moat:** regulated evidence has 7–30 year retention. A seal that
  survives a future quantum adversary is a *compliance requirement* enterprises
  will pay for and no retail L1 bothers with.

### 4. Confidential settlement — private smart contracts that consume verifiable AI
- **[BUILD]** A **confidential EVM** (TEE-backed encrypted contract state, the
  Oasis-Sapphire pattern) rather than a vanilla EVM, so enterprise dApp state
  (balances, identities, health records) is encrypted on-chain.
- **[BUILD]** Verifiable-AI precompiles (`IVerify`/`ISeal`/`IPoUW`) callable from
  those confidential contracts — a contract gates an action on a Digital Seal
  *and* keeps its own state private.
- **Why it's a moat:** confidential-state chains exist (Oasis, Secret) and
  verifiable-AI chains exist (Ora), but **no one has confidential settlement that
  natively consumes verifiable AI**. This is the intersection that upgrades
  ADR-0001 from "3x adoption" to "part of the moat."

### 5. Compliance & sovereignty as a first-class protocol layer
- **[HAVE, partial]** Jurisdiction reports, policy receipts, regulatory-evidence
  index, liability routing, auditor attestation, key-custody manifests (already
  in `docs/demo/public-proof-path`).
- **[BUILD]** ZK **selective disclosure** (prove "this inference complied with
  policy X / used an approved model / stayed in jurisdiction Y" without revealing
  the data), cryptographic **auditor roles**, **data-residency** enforcement, and
  **court-admissible evidence packs** signed by the quorum.
- **[BUILD]** **Deployment sovereignty:** the same protocol runs as (a) a public
  verification network and (b) **private/consortium sovereign instances** a
  regulated client runs in its own jurisdiction with its own validator set. Data
  never leaves the client's boundary; only seals/commitments are portable.
- **Why it's a moat:** this is exactly what regulators and CISOs demand, and it's
  the opposite of what speculative L1s build. It is also a sales moat (sovereign
  deployments) on top of the tech moat.

### 6. Formal assurance
- **[BUILD]** Formal specification + machine-checked proofs (TLA+ for the
  consensus/seal state machine; Coq/Lean for the seal protocol and precompile
  safety) and formally-verified crypto primitives where available.
- **Why it's a moat:** "formally verified verifiable-AI settlement" is a
  procurement-winning, audit-winning phrase for regulated buyers, and it raises
  the copy cost dramatically.

## Why the *product* of these is 20x, not the sum

Each competitor holds one or two pillars:

| Player | Confidential | Verifiable AI | Post-quantum | Confidential settlement | Compliance protocol | Formal |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| Oasis / Secret / Phala | ✓ | – | – | ✓ | – | – |
| Ora / Ritual / Gensyn | – | ✓ (optimistic) | – | – | – | – |
| EZKL / Modulus | – | ✓ (small zk) | – | – | – | – |
| FHE chains (Zama/Fhenix) | ✓ (FHE) | – | – | ✓ | – | – |
| **Aethelred** | **✓** | **✓ (spectrum)** | **✓** | **✓** | **✓** | **✓** |

To copy us, a competitor must integrate confidential GPU compute **and** a
spectrum verifier **and** post-quantum crypto **and** a confidential VM **and** a
compliance/sovereignty protocol **and** formal proofs — and get them audited
together. That is the moat: not any pillar, but the **integrated, audited whole**
aimed squarely at regulated buyers who can't use anyone else.

## Sequenced roadmap (max moat per unit of effort)

1. **Harden what we HAVE into the flagship product:** confidential (TEE)
   verifiable-AI inference → post-quantum Digital Seal → regulator evidence pack,
   end-to-end, on the 5-node testnet, with the confidential EVM + precompiles so
   dApps consume it. *(This alone is already ahead of the field.)*
2. **Confidential-GPU inference** for large models (H100 CC mode) + the
   optimistic-fraud-proof verifier — moves "large model" from TEE-only to
   TEE+verified.
3. **ZK selective disclosure + sovereign/consortium deployment mode** — the
   compliance moat and the enterprise sales motion.
4. **Formal verification** of consensus/seal/precompiles → Tier-1 audit.
5. **FHE/MPC tier** and **zk-LLM** as they mature (roadmap, honestly labeled).

## What this means for the immediate dApp/wallet work

The dApps and wallet sit on top of **pillar 4** (confidential settlement). So the
Phase-0 local substrate becomes: a **confidential-EVM devnet** (or a TEE-backed
EVM), the wallet as the injected provider, and the dApps wired to the
verifiable-AI precompiles — not a vanilla anvil node. Same first step (substrate
→ wallet → Cruzible), aimed at the moat architecture from day one.

## Honesty ledger (so we never oversell to a regulated buyer)

- Production-real today: TEE attestation (6 platforms), zkML small-model, real
  PQC, Freivalds, Digital Seals, the compliance evidence path.
- Serious engineering, not research: confidential-GPU, confidential EVM,
  optimistic verifier, ZK selective disclosure, sovereign deployments, formal
  specs.
- Genuinely frontier (label as roadmap): FHE/MPC inference at useful speed,
  succinct-zk LLM inference. We lead with what's real and show the path to the
  rest — that credibility *is* part of the moat with regulators.
