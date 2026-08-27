# EVM Gas Semantics on Aethelred

Measured behavior of `eth_estimateGas` and gas billing on the Aethelred EVM
JSON-RPC (cosmos/evm v0.6.0, feemarket enabled). Written after field reports of
"transactions reverting with strange gas numbers" during public-testnet
integration; every claim below was reproduced against a live node.

## 1. `eth_estimateGas` is accurate at steady state

The keeper-side estimator (geth-adapted binary search over
`ApplyMessageWithConfig`) returns exact values for settled state. Measured on a
representative state-writing call (`NoblePay.syncBusiness`, two storage writes
plus one event):

| Case | Estimate | Actual usage | Result |
| --- | --- | --- | --- |
| Fresh cold writes | 70,915 | 70,915 | tx sent **at** the estimate succeeds |
| Same-value rewrite (warm) | 31,552 | — | consistent with warm-write pricing |
| Plain transfer | 21,000 | 21,000 | correct |

Do **not** assume the estimator is broken when a transaction reverts — check
the revert reason first (`eth_call` the same payload).

## 2. Billed `gasUsed` can exceed actual usage: the 50% floor

The feemarket param `min_gas_multiplier = 0.5` bills every transaction at
least half of its gas **limit**:

```
billed gasUsed = max(actual usage, gasLimit / 2)
```

Consequences:

- A plain transfer sent with a 100,000 limit shows `gasUsed: 50000` in its
  receipt. This is protocol billing, not extra execution.
- A receipt where `gasUsed == gasLimit / 2` exactly means the limit was far
  above actual usage — not that the tx "used half the gas".
- Wallets that set huge fallback limits get billed accordingly (see §3).
  Keep client gas limits close to the estimate.

A receipt where `gasUsed == gasLimit` exactly (status reverted) is a genuine
out-of-gas.

## 3. Reverting calls: the estimate fails, and wallets fall back badly

For a transaction that would revert (e.g. a NoblePay payment from an
unregistered business), `eth_estimateGas` correctly returns the revert error.
MetaMask then falls back to an enormous default limit (observed: a 1.5B-gas
transaction on the public testnet, billed 751M under the 50% floor — free at a
zero gas price, expensive anywhere else). The transaction still reverts on
chain with the real error.

Client guidance: treat an estimate failure as "this tx will revert — decode
the reason", never as "send anyway with a big limit".

## 4. Scripted deploy→interact flows: pin explicit gas

One transient was observed (not reproducible on demand) where an estimate
issued in the same instant as a fresh deployment's receipt came back near bare
intrinsic gas and the transaction died out-of-gas at exactly
`gasUsed == gasLimit`. Deployment tooling that estimates immediately after a
receipt should either pin an explicit gas limit (the repo's admin scripts use
3–4× the expected cost; unused gas above the 50% floor is not billed at zero
gas price) or re-estimate after one block.

## 5. Verification commands

```bash
# estimate for an arbitrary call
curl -s $RPC -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"eth_estimateGas","params":[{"from":"0x…","to":"0x…","data":"0x…"}],"id":1}'

# feemarket billing params (REST :1317)
curl -s $NODE:1317/cosmos/evm/feemarket/v1/params
```
