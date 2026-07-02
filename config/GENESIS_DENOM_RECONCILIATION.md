# Genesis Denom Reconciliation — `uaethel` vs `aaethel` (RESOLVED)

**Verdict: genesis is composed in `uaethel` (6 decimals). `aaethel` must NOT
appear in genesis, bank balances, or bank metadata.** The 18-decimal
`aaethel` exists only as the EVM's *virtual* view of the same balance,
bridged at a fixed 1e12 by `x/precisebank`. The allocation sheet
(`testnet-genesis-accounts.csv`) has been corrected back to `uaethel`
accordingly.

## Why there appeared to be a contradiction

Two working clones of the same repository (`aethelred-foundation/aethelred`)
are checked out on different branches:

| Clone | Branch | State |
|---|---|---|
| `Downloads/aethelred` | `feat/sdk-export-pqc` | **pre-EVM**: pure Cosmos SDK v0.50.14, no `cosmos/evm`, no `precisebank`; `BondDenom = "uaethel"`, 6 decimals |
| `Downloads/aethelred-demo` | `release/public-testnet-pqc` | **EVM-enabled**: SDK v0.53 line + `cosmos/evm v0.6.0`, `x/precisebank` wired, ISeal/IVerify/IPoUW precompiles, EVM chain-id 7332, JSON-RPC |

Anyone inspecting the first clone correctly concludes "no EVM, 6-dec
uaethel"; anyone inspecting the second correctly concludes "EVM chain 7332,
18-dec balances in MetaMask." Both are right — about different branches.
**The testnet must be built from `release/public-testnet-pqc`** (or its
merge into `main`); `feat/sdk-export-pqc` does not contain the EVM stack.

## The authoritative denom design (already built and proven)

From `app/evm.go` on `release/public-testnet-pqc` (the code, not a plan):

- **Bank denom = `uaethel`, 6 decimals.** It is the only real denom: what
  `x/bank` holds, what genesis allocates, what fees/staking/gov use.
- **EVM face = 18 decimals**, presented automatically by `x/precisebank`
  at a fixed **1e12** factor. `aaethel` is a *virtual* accounting unit —
  "NOT a bank denom and must not appear as a metadata base" (quoting the
  code comment). `params.EvmDenom` points at `uaethel`; bank metadata
  carries `uaethel` (exp 0) → `aethel` (exp 6) and the vm module derives
  the bridge from it.
- This was validated end-to-end by the first live EVM transaction
  (`cmd/aethelred-evm-smoke`): fund in `uaethel` → MetaMask-style EIP-1559
  tx on 7332 → receipt success → recipient shows 1e18-scale balance.
  Mis-setting the EVM denom to `aaethel` was one of the three real bugs
  that exercise flushed out (it bypasses the bridge).

So of the two options previously framed — (a) native 18-dec chain with
`aaethel` base denom, or (b) 6-dec bank + precisebank bridge — **option (b)
is already implemented, tested, and live-proven.** No rebuild to a native
18-dec chain is needed or wanted; it would diverge from every proof and
integration (wallet, dApps, precompile tests) done against 7332.

## What this means practically

1. **Allocation sheet:** amounts are `uaethel` = display tAETHEL × 10⁶
   (validator 10,000 tAETHEL → `10000000000uaethel`). Total supply
   10,000,000,000 tAETHEL = **10¹⁶ uaethel** (16 digits — safely inside
   spreadsheet float precision, unlike the 28-digit aaethel values; the
   text-import caveat is no longer critical, though keeping them as text
   stays good hygiene).
2. **Genesis composition:** `add-genesis-account <addr> <n>uaethel`,
   `--default-denom uaethel`, gentx self-bond in `uaethel`.
3. **Min gas price:** stays `0.001uaethel`. Do NOT convert to an
   `aaethel` figure — the node prices gas in the bank denom; the EVM side
   derives its wei-scale gas price through the bridge (base fee ÷ 1e12
   handling is already in the EVM wiring).
4. **MetaMask/viem sanity check after launch:** a balance funded as
   `X uaethel` must display as `X / 10⁶` AETHEL in an EVM wallet
   (`eth_getBalance` returns `X × 10¹²` wei-style). If it is off by 10¹²,
   the node was built from the wrong branch or `EvmDenom` was changed.
5. **The `Genesis coin string` column** in the CSV is paste-ready for
   `add-genesis-account`.

## Residual to-do that actually remains

- Merge/land the EVM stack (`release/public-testnet-pqc`) into the branch
  the testnet team builds from, so nobody composes genesis against the
  pre-EVM tree again.
- `gen-testnet-accounts.sh` (key generation + address fill-in) should
  create keys with the **eth_secp256k1** algo (coin-type 60) so every
  genesis account works on both faces (native `aethel1…` + EVM `0x…`).
