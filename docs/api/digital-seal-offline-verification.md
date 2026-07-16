# Digital Seal — Offline Quorum Verification

A Digital Seal certifies that, on a given chain, a compute job over a specific
model and input produced a specific output. Its trust anchor is a **validator
quorum of hybrid (secp256k1 + ML-DSA) signatures**: a 2/3+ voting-power quorum of
validators each signed the seal's canonical claim. Anyone — an auditor, a
regulator, an enterprise integrator (e.g. the M42 pilot) — can verify this
**offline**, without running a node.

This document specifies the verification protocol. A runnable reference is the
Go `ExampleVerifySealQuorum` in `x/seal/types`.

## What is signed: the seal claim

Each validator signs the canonical **seal claim** — the deterministic, immutable
assertion the seal makes. Block height is deliberately excluded (validators sign
at their vote-extension height, which differs from the seal's completion height).

```
SealClaim = (chainID, jobID, modelCommitment, inputCommitment, outputCommitment)
```

The signed message is a length-prefixed encoding with a domain separator:

```
signingBytes =
  "aethelred-seal-claim-v1"            (domain separator, raw, no length prefix)
  || be32(len(chainID))          || chainID
  || be32(len(jobID))            || jobID
  || be32(len(modelCommitment))  || modelCommitment
  || be32(len(inputCommitment))  || inputCommitment
  || be32(len(outputCommitment)) || outputCommitment
```

where `be32(n)` is the 4-byte big-endian encoding of `n`. See
`SealClaim.SigningBytes` for the canonical implementation.

## The hybrid signature

Each validator signature is a composite of two signatures over the claim, in a
compact framing:

```
HybridSignature = ecdsaSig(64) || level(1) || mldsaSig
```

- **secp256k1 ECDSA** over `SHA-256(signingBytes)`, low-S normalized (BIP-62 / EIP-2).
- **ML-DSA** (FIPS 204; level 3 = ML-DSA-65) over `signingBytes` directly.

The hybrid **public key** is framed as:

```
HybridPublicKey = ecdsaLen(1) || ecdsaPub(SEC1, 33 compressed) || level(1) || mldsaPub
```

Both components must verify. (See `pqc.VerifyHybrid`.)

## Verification steps

1. **Fetch the seal** and reconstruct its `SealClaim`.
2. **Fetch the quorum signatures** via the pouw query
   `SealQuorum(seal_id)` — REST: `GET /aethelred/pouw/v1/seals/{seal_id}/quorum`,
   or CLI: `aethelredd query pouw seal-quorum <SEAL_ID>`. Each entry has
   `signer_address`, `algorithm` (`hybrid-secp256k1-mldsa`), `public_key`,
   `signature`.
3. **Fetch the validator set**: each validator's **registered** hybrid public key
   (`SealQuorum` returns the embedded key, but a strict verifier should also
   confirm it equals the key the validator registered on-chain) and its voting
   power at the seal's block height.
4. **Verify each signature** against the validator's registered hybrid public key
   over `signingBytes`. Count each validator once.
5. **Apply the threshold**: the seal is quorum-valid when the agreeing validators'
   power is `>= (totalPower * 67 / 100) + 1`.

> Security note: verify against the validator's **registered** key, not the key
> embedded in the signature — otherwise an attacker could attach a key it
> controls and forge a "quorum." `VerifySealQuorum` does this by construction.

## Reference

- Go pure function: `sealtypes.VerifySealQuorum(claim, signatures, validators, thresholdPercent)`.
- Runnable example: `ExampleVerifySealQuorum` (`x/seal/types/example_test.go`).
- Hybrid primitives: `crypto/pqc` (`VerifyHybrid`, `SignHybrid`, `HybridPublicKey`).
