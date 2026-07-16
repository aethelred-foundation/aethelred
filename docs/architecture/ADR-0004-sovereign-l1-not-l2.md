# ADR-0004: Aethelred is a sovereign Layer 1, not an Ethereum Layer 2

Status: accepted. Audience: developers, regulators, auditors, enterprise
procurement. Companion to ADR-0001 (EVM surface), ADR-0002 (moat), ADR-0003
(CEAP).

## The question this answers

"You expose an EVM (chain-id 7332), Solidity, and JSON-RPC. Why not build
Aethelred as an Ethereum Layer 2 (a rollup) and inherit Ethereum's security and
liquidity? Why is this yet another Layer 1?"

The short answer: **the guarantees Aethelred sells are consensus-layer
properties. A Layer 2 does not have its own consensus — it rents Ethereum's —
so it structurally cannot provide them.** The EVM here is an *execution
surface*, not the settlement layer. Everything that makes Aethelred worth using
happens in the place an L2 does not control: block production and finality.

This is not a branding decision. Each property below is a thing our validators
do while producing a block, points to the code that does it, and states plainly
why an Ethereum-settled rollup cannot.

## What an L2 actually is (so the argument is precise)

An Ethereum rollup executes transactions off-chain and posts data + (validity or
fraud) proofs to Ethereum, which orders and finalizes them. The rollup's
security *reduces to Ethereum's*: its finality is Ethereum finality, its
data availability is Ethereum's, its validator set is Ethereum's. A rollup adds
throughput and custom execution; it does **not** add new consensus primitives,
because it has no consensus of its own to add them to.

Aethelred is a Cosmos-SDK / CometBFT L1: its own validator set, its own BFT
finality, its own block-production logic (ABCI++), its own token economics. That
is precisely the layer the six properties below live in.

## The six properties — each impossible as an L2

### 1. Verifiable AI is the block-production mechanism, not an app on top

Aethelred validators verify AI computation (Proof-of-Useful-Work) as part of
consensus. Verification results are aggregated in **ABCI++ vote extensions**,
and a ≥⅔ quorum mints the Digital Seal during block finalization
(`app/abci.go` PrepareProposal → `x/pouw` consensus handler → `CompleteJob`).
The "useful work" is not a smart contract users call; it is what the validators
*do to produce a block*.

Why not an L2: a rollup's block production is Ethereum's. It cannot make attested
AI verification a consensus primitive because it has no consensus step to put it
in. On an L2, "verifiable AI" degrades to an application-level attestation
service with its own operator/oracle trust — exactly what this design removes.

### 2. The Digital Seal is a consensus artifact signed by the validator set

The Seal carries a quorum of validator signatures gathered in vote extensions
over the seal claim (`app/vote_extension*.go`, `x/seal`). It is a property of
Aethelred's *finalized state*, produced by the same validators that finalize the
block.

Why not an L2: Ethereum's consensus produces no such artifact and cannot be
extended to. A rollup inherits Ethereum finality, so its "seal" could only be an
application-level multisig over off-chain data — not a statement its chain's
consensus made.

### 3. Post-quantum finality

Consensus vote-extension signing and the Seal quorum use **ML-DSA (post-quantum)
alongside classical keys** (`crypto/pqc`, hybrid signing). The assurance that a
sealed result is final is backed by a PQC signature set at the consensus layer.

Why not an L2: a rollup settles to Ethereum, whose finality is secp256k1/BLS —
quantum-vulnerable. No matter what an L2 does internally, its results are only as
final as Ethereum's reorg/finality, which is not post-quantum. A regulator or
institution requiring PQC assurance *on settlement of the attested computation*
cannot obtain it from an Ethereum-settled chain.

### 4. Sovereignty and data residency

Sovereign and regulated clients require that the validator set, transaction
ordering, and data remain inside a jurisdiction or consortium boundary.
Aethelred deploys as a sovereign instance: its own validators in the client's
jurisdiction, data that never leaves the boundary, and only portable Seals
crossing it (ADR-0003 sovereign-deployment model; CEAP `DataResidency` policy).

Why not an L2: a rollup posts its data (blobs/calldata) to Ethereum mainnet and
derives ordering and finality from it — a public, globally distributed network
outside any single jurisdiction. For a sovereign deployment that is a
non-starter: the data and the ordering authority have left the boundary. You
cannot have "sovereign" and "settles to a public chain you don't control" at the
same time.

### 5. The verifiable-AI precompiles read consensus-native state with no bridge

`ISeal` (0x0900), `IVerify` (0x0901), and `IPoUW` (0x0902) expose `x/seal`,
`x/verify`, and `x/pouw` state directly to the EVM **in the same state
transition** (`precompiles/*`, mounted in `x/vm` via `WithStaticPrecompiles`).
A contract reads a Digital Seal, or gates on a confidentiality policy, by
calling the same Go code consensus runs — `internal/confidential.Satisfies` —
with no oracle and no bridge.

Why not an L2: the seals/jobs live on the L1 that runs the consensus. An L2
would need a bridge or oracle to import that state, reintroducing exactly the
trusted third party and latency that CEAP exists to eliminate. On Aethelred the
EVM and the verifiable-AI modules are one state machine; a rollup and its L1 are
two.

### 6. Economic alignment: the useful work is the staking yield

The AI verification that secures the chain (PoUW) is the same work that produces
the yield distributed to stakers. Cruzible's rewarder routes the chain's
verification/commission rewards into the pool, so stAETHEL rebases from
attested useful work (see Cruzible `docs/PROTOCOL_SYNC.md`).

Why not an L2: on a rollup, block rewards and MEV accrue to Ethereum validators
and the sequencer. There is no consensus-economic home for "useful work," so a
staking product on an L2 is staking *someone else's* (Ethereum's) security, not
the chain's own attested compute.

## What the EVM is, then

Not the settlement layer (Ethereum's role for a rollup), but an **execution
surface on top of a sovereign L1**. It exists so the enormous EVM tooling, dApp,
and wallet ecosystem can reach Aethelred's consensus-native guarantees through
familiar interfaces: chain-id 7332, standard JSON-RPC, Solidity + the
verifiable-AI precompiles. **Compatibility at the tooling layer; sovereignty at
the trust layer.** EVM transactions use standard secp256k1 (Ethereum
compatibility); the post-quantum layer stays where it matters — consensus and
the Seal — because the moat is the *attested result*, not the user's tx
signature (ADR-0001).

## Why "not just another Layer 1"

The differentiator is not "a faster or cheaper generic L1." It is that these six
properties are **integrated into one state machine**: attested-compute-as-
consensus, quorum-signed PQC Digital Seals, confidential-execution attestation
(CEAP), sovereign deployment, and an EVM surface that reads all of it without a
bridge. ADR-0002's competitor matrix shows no existing player holds more than
two of these pillars; the product is their *combination*, which is the thing that
cannot be copied by adding a feature.

A useful test for any reviewer: **take a candidate feature and ask whether it
would still hold if Aethelred were an Ethereum rollup.** For seals, PQC finality,
sovereignty, bridge-free precompile reads, and PoUW-yield — the answer is no.
That is the operational definition of "must be an L1."

## Consequences

- Positive: the guarantees are real and defensible; regulators/auditors can
  trace each to consensus code, not marketing; enterprises get sovereignty +
  EVM compatibility without choosing.
- Cost: we run and secure our own validator set and economics (the price of
  sovereignty) and maintain a two-VM surface (Cosmos modules + EVM). ADR-0001
  and the CEAP threat model (docs/security) scope that surface.
- Non-goal: competing as a general-purpose L1 for retail speculation. The target
  is sovereign/regulated verifiable-AI settlement.

## For each audience, in one line

- **Developers:** you get standard EVM + Solidity + JSON-RPC (chain-id 7332),
  plus precompiles that read attested-AI state with no oracle — because it's the
  same chain, not a rollup bridged to one.
- **Regulators:** ordering, data, and validators stay in-jurisdiction; finality
  is post-quantum; the compliance decision is made by consensus, auditable in
  code — none of which an Ethereum-settled L2 can offer.
- **Auditors:** every guarantee maps to consensus-layer code (`x/pouw`,
  `x/seal`, `crypto/pqc`, `app/abci.go`, `precompiles/*`,
  `internal/confidential`), not to an off-chain service.
- **Enterprises:** your assets and your compliance logic live on infrastructure
  you can run sovereignly, reachable by the wallet/dApp ecosystem you already
  use.
