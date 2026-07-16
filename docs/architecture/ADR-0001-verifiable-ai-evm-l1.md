# ADR-0001 — Aethelred as a Verifiable-AI EVM L1

**Status:** Proposed · **Date:** 2026-07-01 · **Decision owner:** Ramesh

## Context

Aethelred's differentiator is a Cosmos SDK L1 with **Proof-of-Useful-Work**
consensus that performs *real* verifiable AI: BN254 Groth16 zkML for small
models, hardware-agnostic TEE attestation (6 platforms) for large ones, and
**post-quantum (ML-DSA/ML-KEM), validator-quorum-signed Digital Seals** as the
settlement primitive. Target customers are regulated industries (finance,
healthcare, identity), where cryptographic auditability and post-quantum
durability matter.

The flagship dApps — **Cruzible, ZeroID, TerraQura, NoblePay** — and the
**Aethelred Wallet** are all **EVM-first** (wagmi / viem / RainbowKit / Solidity;
the wallet is an injected EIP-1193/EIP-6963 provider). But `aethelredd` today is
**Cosmos-only** — no EVM, no JSON-RPC. As built, none of these can connect to the
chain. We need an execution-layer decision that (a) unblocks the EVM dApp
ecosystem and (b) *strengthens*, not dilutes, the moat.

## Decision

Make `aethelredd` a **dual-VM sovereign L1**: keep the Cosmos SDK verifiable-AI
core and add an **EVM execution layer** via `cosmos/evm` (the maintained Cosmos
EVM module, successor to Ethermint), exposing a standard Web3 JSON-RPC. Then —
this is the point — add **custom EVM precompiles that let Solidity contracts call
the verifiable-AI primitives natively**:

| Precompile | Backing module | What a contract can do |
|-----------|----------------|------------------------|
| `IVerify` | `x/verify` | Verify a zkML proof / TEE attestation inline in a tx |
| `ISeal` | `x/seal` | Read and verify a Digital Seal (model+input+output commitment, quorum) |
| `IPoUW` | `x/pouw` | Submit a compute job and read its status/result |

**The EVM is table stakes; the precompiles are the moat.** A Cruzible vault, a
NoblePay settlement, or a ZeroID identity contract can, in a *single EVM
transaction*, invoke an AI computation, verify it, and gate the on-chain action
on a post-quantum, hardware-attested, quorum-signed Digital Seal — then leave a
cryptographic audit trail. No other L1 offers this from Solidity.

## Why this is the moat (and hard to copy)

- **Forking an EVM chain is trivial; forking *this* is not.** The defensible
  asset is the integrated stack — PoUW consensus doing real zkML+TEE
  verification, PQC quorum Digital Seals, and EVM precompiles bridging them into
  Solidity. A competitor must reproduce the verifiable-AI consensus *and* the
  precompile bridge *and* the PQC/TEE integration — years of specialized
  crypto+consensus+VM work, not a `git fork`.
- **Positioning:** *the verifiable-AI settlement layer for regulated
  industries.* Not "another EVM chain" — the EVM chain where smart contracts
  natively consume verifiable AI with auditable, post-quantum attestations.
- **Regulated-industry fit:** post-quantum signatures (long-lived compliance
  data survives a quantum adversary), hardware-agnostic TEE (no cloud-vendor
  lock-in), on-chain cryptographic auditability (Digital Seals), and native
  identity (ZeroID).
- **Ecosystem leverage:** the entire Solidity / wagmi / MetaMask developer world
  can build here with zero new tooling, yet gain a capability no other EVM chain
  has.

## Alternatives considered

1. **Standalone / separate EVM chain for the dApps.** Rejected: the dApps could
   not natively access verifiable AI (the moat), it fragments liquidity and
   identity, and it weakens the "sovereign L1" story.
2. **No EVM (Cosmos-only); rewrite dApps as CosmWasm/CosmJS.** Rejected: discards
   the existing EVM dApp + wallet investment and the Solidity developer market;
   slower adoption; the moat still needs a contract layer.
3. **EVM without verifiable-AI precompiles.** Rejected: that *is* "just another
   EVM chain" — no moat.

## Consequences

- **Positive:** one sovereign chain; existing EVM dApps + wallet work with a
  repoint; verifiable AI reachable from Solidity; strong, defensible positioning.
- **Cost / risk:** `cosmos/evm` integration is substantial (JSON-RPC, EVM
  chain-id, `0x`↔bech32 address unification, fee market, gas). Precompile gas
  metering must be conservative (verification is expensive — meter to the real
  cost; keep heavy zkML/TEE work asynchronous via the PoUW job flow rather than
  synchronous in a precompile where possible). Larger audit surface (two VMs).
- **PQC scope:** user EVM transactions stay standard secp256k1 ECDSA (Ethereum
  compatibility); the post-quantum layer remains where it matters — consensus
  vote-extension signing and the Digital Seal quorum. The moat is the *attested
  result*, not the user's tx signature.

## Roadmap

- **Phase 0 — unblock (days):** local EVM devnet (anvil, `:8545`) + deploy the
  dApp contracts + wire the Wallet (injected provider) + Cruzible/ZeroID/
  TerraQura. Same local substrate needed under any option; de-risks the dApp and
  wallet code independently of the L1 work. Frontend teams work immediately.
- **Phase 1 — EVM on aethelredd (weeks):** integrate `cosmos/evm`; expose
  JSON-RPC; address unification; fee market. dApps repoint from anvil to
  aethelredd's EVM. One sovereign L1.
  - **Execution layer landed (`internal/evmhost`):** the real go-ethereum
    interpreter (core/vm) runs with Aethelred precompiles mounted via
    SetPrecompiles, chain-id 7332, post-merge rules; real contract bytecode is
    deployed and executed against real chain state in tests.
  - **SDK prerequisite satisfied:** the chain upgraded cosmos-sdk
    v0.50.14 → v0.53.7 (zero source changes; 43 packages green; single-node
    boot smoke produced blocks with clean app hashes). CometBFT stays v0.38.
  - **cosmos/evm integration assessment (evidence-based, on v0.53):**
    1. `cosmos/evm` resolves as a dependency against our graph (verified with
       v0.5.1); its go.mod carries
       `replace github.com/ethereum/go-ethereum => github.com/cosmos/go-ethereum
       v1.16.2-cosmos-1`. Replace directives do not propagate — the consumer
       must adopt the fork, which pins the whole module to the fork's
       geth v1.16 API.
    2. Impact when adopted: `internal/evmhost` (written on vanilla geth
       v1.17.4 — GasBudget-era APIs) must be ported to the fork API or retired
       in favor of cosmos/evm's own x/vm keeper (which wraps the same
       core/vm); `precompiles/*` use only `accounts/abi` + `common` — stable
       across fork/vanilla, no changes. The AI-gated vault artifacts are
       compiler output — host-independent.
    3. cosmos/evm ≥ v0.7.0 additionally requires go ≥ 1.25.9 (trivial
       toolchain bump from 1.25.8).
    4. Remaining scope is the evmd-style app wiring: x/vm + x/feemarket +
       x/erc20 + precisebank keepers, EVM ante handlers, JSON-RPC server,
       genesis — a dedicated integration engagement, now UNBLOCKED and
       de-risked (the precompile surface it must expose is finished and
       proven against the real interpreter).
  - **Dependency adopted (commit 63479a145a):** `github.com/cosmos/evm@v0.6.0`
    + the `go-ethereum => cosmos/go-ethereum v1.16.2-cosmos-1` replace are now
    in go.mod. Predicted impact confirmed exactly: the full suite stays green
    (47 packages) against the fork; only `internal/evmhost` needed porting.
    `precompiles/evm` is the mount seam (Adapter →
    `x/vm` `WithStaticPrecompiles`).
  - **EVM config foundation (`app/evmconfig`, tested):** encodes the two
    audit-sensitive decisions in one reviewable place:
    - **Decimal bridge:** `uaethel` is the 6-decimal bank denom; the EVM
      operates in an 18-decimal extended denom `aaethel`, reconciled by
      `x/precisebank` at a fixed 1e12 factor (no wei truncation on the Cosmos
      side). This is cosmos/evm's supported non-18-decimal pattern
      (`SixDecimals` + distinct `ExtendedDenom`).
    - **Precompile permissioning:** `ActiveStaticPrecompiles` = ISeal 0x0900,
      IVerify 0x0901, IPoUW 0x0902 (sorted/unique; accepted by x/vm's own
      `ValidatePrecompiles` and genesis `Validate`).
  - **App wiring LANDED (commit a65b1dc54d):** the four EVM keepers
    (feemarket → precisebank → evm+precompiles → erc20) are constructed in
    `app/evm.go`, registered in the module manager with begin/end-block +
    init-genesis ordering, and seeded from `app/evmconfig`; `uaethel`/`aaethel`/
    `aethel` DenomMetadata is in the bank default genesis; eth_secp256k1
    interface types registered. Our three verifiable-AI precompiles are mounted
    via `WithStaticPrecompiles` directly — NOT the full `DefaultStaticPrecompiles`
    bundle (staking/distr/gov/ICS20) — keeping the EVM surface minimal.
    **Proven:** a fresh single-node genesis (EVM denom `aaethel`, all three
    precompiles active, feemarket/erc20/precisebank present) boots and produces
    blocks with clean app hashes; a chain-config process-global collision from
    the CLI's double app-construction is handled by aligning
    `evmtypes.DefaultEVMChainID` with 7332.
  - **Dual-route ante LANDED (commit a65b1dc54d):** EVM-extension txs take the
    cosmos/evm mono EVM ante chain (Ethereum-sig verification + fee market);
    all else takes the existing Aethelred cosmos chain, now fronted by
    `RejectMessagesDecorator` so a `MsgEthereumTx` cannot bypass Ethereum-sig
    verification via the cosmos route.
  - **eth_call → precompile PROVEN (in-process integration test):** a real
    `eth_call` — the exact query the JSON-RPC `eth_call` endpoint dispatches to
    (`EVMKeeper.EthCall`) — reaches ISeal at 0x0900 through the live cosmos/evm
    StateDB, reads a Digital Seal from chain state, and returns correct
    `verifySeal` / `requireConfidentiality` verdicts (including a consensus-parity
    policy rejection). The whole verifiable-AI moat is reachable from the EVM.
  - **JSON-RPC HTTP transport LANDED (side service, no consensus change):**
    the EVM JSON-RPC HTTP server runs from the node start command's `PostSetup`
    hook (`server.AddCommandsWithStartCmdOptions`), sharing the node's client
    context — it does NOT replace the custom ABCI++/PoUW start logic or the
    consensus mempool. Enabled with `--json-rpc.enable`
    (`--json-rpc.address`, default `127.0.0.1:8545`; namespaces `eth,net,web3`).
    Key design point: cosmos/evm's `eth_sendRawTransaction` broadcasts through
    the standard CometBFT path (`BroadcastTx` → CheckTx → the dual-route ante →
    the PoUW `PrepareProposal`), so EVM-tx block inclusion needs NO experimental
    EVM mempool; `StartJSONRPC` is called with nil mempool + nil indexer (the RPC
    backend guards both — `txpool_*`/tx-by-hash degrade gracefully while the
    read/call/broadcast path is fully live). The app satisfies
    `AppWithPendingTxStream` via `RegisterPendingTxListener` (the
    `newPendingTransactions` websocket push is inert without the experimental
    pool — an honest degradation of one optional feature).
    **Boot-proven over HTTP:** the node produces blocks with JSON-RPC live;
    `eth_chainId` → `0x1ca4` (7332), `net_version` → `7332` (aligned via the
    `evm.evm-chain-id` viper key), `eth_blockNumber` advances, and `eth_call`
    against ISeal at `0x0900` returns a valid ABI bool — the whole verifiable-AI
    moat is reachable over standard Ethereum JSON-RPC. The dApp stack (Wallet,
    Cruzible, ZeroID, TerraQura at chain-id 7332) can now repoint from anvil to
    aethelredd's EVM.
- **Phase 2 — the moat (weeks):** ship the `IVerify` / `ISeal` / `IPoUW`
  precompiles; add Solidity interfaces + a reference "AI-gated vault" example;
  wire Cruzible/NoblePay to gate on Digital Seals.
  - **ISeal shipped** (`precompiles/seal`, ADR-0003 step 3): full ABI +
    Solidity interface + keeper-backed reads + `requireConfidentiality`
    consensus-parity gating, proven end-to-end through the embedded
    interpreter (contract → STATICCALL 0x0900 → seal keeper). IVerify (0x0901)
    and IPoUW (0x0902) reserved.
- **Phase 3 — harden + audit:** precompile gas/DoS review, compliance hooks,
  Tier-1 audit of the combined surface.

## First execution step

Substrate → Wallet → Cruzible. Stand up the local EVM devnet, get the Aethelred
Wallet running as the injected provider against it, then bring up Cruzible as the
first dApp connecting through the wallet (the "prove the EVM adapter path" goal
from the Wallet integration matrix). ZeroID and TerraQura follow the same
pattern.
