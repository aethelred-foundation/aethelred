# govulncheck exception register

The security workflow runs `govulncheck` at symbol level and fails on every
unreviewed reachable finding. The validator in
`scripts/validate_govulncheck.py` permits only the exact module, version, and
package combinations below. All exceptions expire on **2026-10-31**; changing a
dependency version or reaching another package fails closed.

## GO-2024-2584 — Cosmos SDK slashing range

- Repository version: `github.com/cosmos/cosmos-sdk@v0.50.14`
- Official affected range: `<=0.50.4` on the v0.50 line
- Official patched version: `v0.50.5`
- Decision: reviewed database-range false positive
- Source:
  <https://github.com/cosmos/cosmos-sdk/security/advisories/GHSA-86h5-xcpx-cfqc>

## GO-2024-3218 — libp2p Kademlia DHT range

- Repository version: `github.com/libp2p/go-libp2p-kad-dht@v0.37.1`
- Official affected range: `<=0.20.0`
- Decision: reviewed database-range false positive
- Source: <https://github.com/advisories/GHSA-mqr9-hjr8-2m9w>

## GO-2026-5932 — transitive Cosmos SDK ASCII armor

- Repository version: `golang.org/x/crypto@v0.53.0`
- Reached packages: `openpgp/armor` and `openpgp/errors`
- Upstream status: no fixed `x/crypto/openpgp` version; the Go advisory
  recommends the maintained ProtonMail fork
- Source: <https://pkg.go.dev/vuln/GO-2026-5932>

Cosmos SDK v0.50.14 uses this package only to encode/decode ASCII armor around
private-key bytes that Cosmos separately encrypts with Argon2id and
ChaCha20-Poly1305. Aethelred does not use OpenPGP for signing, encryption, or
trust decisions. The dependency remains present in the current Cosmos SDK
maintenance branch and latest major release, so replacing it safely requires an
upstream fix or a reviewed Cosmos SDK fork.

Compensating controls until migration:

1. `aethelredd keys import` and `keys export` are operator-only commands and are
   not exposed over RPC, REST, gRPC, or the public dApp APIs.
2. Production validators use managed keyrings/HSMs; operators must not import
   armored key files from untrusted sources.
3. The exception covers only `openpgp/armor` and `openpgp/errors`. Reaching the
   broader `openpgp` package fails CI.
4. The exception expires on 2026-10-31 and must not be renewed without a fresh
   upstream review and an explicit migration decision.

## Removed finding

The unused Cosmos SDK `x/crisis` module wiring was removed. It was never
instantiated in Aethelred's module manager, while Aethelred's independent
sovereign crisis keeper remains active. The old `"crisis"` KV-store key remains
mounted as an inert compatibility key, preserving the existing multistore
layout during a binary-only upgrade. No Cosmos crisis code, message route,
genesis handler, or params wiring remains source-reachable; therefore
GO-2023-1821 and GO-2023-1881 are not excepted.
