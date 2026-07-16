# EVM gas and fees on Aethelred

Aethelred exposes a standard Ethereum JSON-RPC (chain-id `7332`) backed by
`cosmos/evm`. Contract deploys and calls behave as on any EVM chain, with two
node-level behaviours worth knowing when you size gas from a client (viem,
ethers, hardhat, web3). Both are handled with a one-line client convention; there
is no contract change or node patch required.

## 1. `eth_estimateGas` is accurate

For settled state, `eth_estimateGas` returns the true execution cost. Measured on
a live node, first-write `setCompliancePolicy(["tee"],"",[],false,["AE"])`:

| call                       | `eth_estimateGas` | gas actually used |
| -------------------------- | ----------------- | ----------------- |
| SealSettlementGate deploy  | 1,921,091         | 1,921,091         |
| setCompliancePolicy (1st)  | 129,208           | 129,208           |

Submitting a transaction with `gasLimit == estimate` succeeds and consumes
exactly the estimate. The estimate is not inflated and is not intrinsic-only.

## 2. Fees are charged as `max(actualGas, gasLimit/2)`

A gas refund of more than half of the submitted `gasLimit` is capped. In effect
the fee is `max(actualGas, gasLimit/2)`. So an over-large fixed `gasLimit`
**overpays**:

| gasLimit submitted | actual gas | fee charged |
| ------------------ | ---------- | ----------- |
| 200,000            | 129,208    | 129,208     |
| 2,000,000          | 129,208    | 1,000,000   |
| 3,842,182 (2×est)  | 1,921,091  | 1,921,091   |

A blanket "just send 8,000,000" limit therefore bills 4,000,000 regardless of
the real cost. Size the limit instead.

## 3. Brief estimate lag right after a state change

Immediately after a deploy (or any state-changing tx) in a tight scripted loop,
the very next `eth_estimateGas` can momentarily resolve a block whose committed
state does not yet include the new code, returning ~intrinsic gas. The receipt
of the prior tx is already available (`waitForTransactionReceipt` has returned),
so the lag is only on the estimate path and closes within a block. Read calls
(`eth_call`) are not affected.

## Recommended client convention

Size every deploy and write at **twice the estimate, with a floor**:

```
gasLimit = max(eth_estimateGas × 2, floor)
```

- `× 2` keeps the fee at the true cost — `limit/2 == estimate ≈ actualGas`, so
  the refund cap does not bite — while giving 100 % headroom.
- The `floor` (e.g. 800k for writes, 6M for deploys) covers the brief post-write
  estimate lag in §3, where `estimate × 2` alone could under-shoot. It binds only
  during that transient window.
- Keeping estimation on the path (rather than pinning a fixed `gas`) means a
  disallowed call reverts at estimate time instead of being mined as a failed
  transaction — important for scripts that assert on reverts.

viem:

```js
const withHeadroom = (estimate, floor) =>
  estimate * 2n > floor ? estimate * 2n : floor;

const gas = withHeadroom(
  await publicClient.estimateContractGas({ address, abi, functionName, args, account }),
  800_000n,
);
await walletClient.writeContract({ address, abi, functionName, args, gas });
```

hardhat (`hardhat.config`): keep estimation on and add headroom via the network
option, rather than pinning a fixed `gas`:

```ts
networks: {
  aethelred: { url: RPC_URL, chainId: 7332, gasMultiplier: 2 },
}
```

The seal-anchored dApp E2E scripts (ZeroID, Cruzible, NoblePay, TerraQura,
Shiora) all follow this convention.
