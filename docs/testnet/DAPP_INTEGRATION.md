# Connecting dApps & Wallets to Aethelred

How to point a dApp (Cruzible, ZeroID, NoblePay, …) or a wallet at a local node
or the public testnet. This covers the **chain side** — the endpoints and
connection parameters every client needs. The dApp/wallet source lives in its
own repository (see links below); this doc is the contract between them and the
chain.

> The dApp source is **not** in this monorepo — `dApps/` holds pointer stubs
> only. Clone the app's canonical repo and configure it with the values here.

## Canonical repositories

| App | Repository |
|-----|------------|
| Cruzible | https://github.com/aethelred-foundation/cruzible |
| ZeroID | https://github.com/aethelred-foundation/zeroid |
| NoblePay | https://github.com/aethelred-foundation/noblepay |
| TerraQura | https://github.com/aethelred-foundation/terraqura |
| Shiora | https://github.com/aethelred-foundation/shiora |
| Wallet | Aethelred Wallet (separate repo) |

---

## 1. Open the node's dApp-facing endpoints

A node exposes only CometBFT **RPC (26657)** and **gRPC (9090)** by default —
the REST API and **all CORS are OFF**, so a browser dApp/wallet cannot connect.
Turn them on:

```bash
# single local node (default home ~/.aethelredd)
scripts/dapp-endpoints.sh

# a localnet — run per node (ports are base + 100*i)
for i in 0 1 2 3 4; do scripts/dapp-endpoints.sh ~/.aethelred-localnet/node$i; done

# a public host (binds 0.0.0.0 — put TLS + a reverse proxy in front)
PUBLIC=1 scripts/dapp-endpoints.sh ~/.aethelredd
```

It enables the REST API + swagger, turns on dev CORS for REST and RPC, and
prints the connection block. **Restart the node** afterward.

---

## 2. Connection contract

| Field | Value |
|-------|-------|
| chain-id (local) | `aethelred-localnet-1` (localnet) / `aethelred-testnet-1` (single node) |
| chain-id (public) | the public testnet's chain-id (set at genesis) |
| bech32 account prefix | `aethel` (pub `aethelpub`) |
| bech32 validator prefix | `aethelvaloper` (pub `aethelvaloperpub`) |
| bech32 consensus prefix | `aethelvalcons` (pub `aethelvalconspub`) |
| base (minimal) denom | `uaethel` |
| display denom | `aethel` (1 aethel = 1,000,000 uaethel → **6 decimals**) |
| HD coin type | `118` (Cosmos default) |
| min gas price | `0.001uaethel` |

### Endpoints

| Service | Local single node | Localnet node `i` | Public testnet |
|---------|-------------------|-------------------|----------------|
| CometBFT RPC | `http://127.0.0.1:26657` | `26657 + 100*i` | `https://rpc.<host>` |
| REST (LCD/API) | `http://127.0.0.1:1317` | `1317 + 100*i` | `https://api.<host>` |
| gRPC | `127.0.0.1:9090` | `9090 + 100*i` | `<host>:9090` |
| gRPC-web | via the LCD host | — | via the API host |

The 5-node public testnet: point read-heavy dApps at one or more full nodes'
RPC/REST behind a load balancer; never expose a validator's RPC publicly.

---

## 3. CosmJS (query + sign)

```ts
import { SigningStargateClient, GasPrice } from "@cosmjs/stargate";

const rpc = "http://127.0.0.1:26657";           // or the public RPC
const client = await SigningStargateClient.connectWithSigner(rpc, offlineSigner, {
  gasPrice: GasPrice.fromString("0.001uaethel"),
});
// bank/staking/gov/... work out of the box; the custom modules (pouw, seal,
// verify) are reachable over gRPC/REST using their generated protobuf types.
```

Read-only queries can also hit the REST API directly, e.g.
`GET http://127.0.0.1:1317/cosmos/bank/v1beta1/balances/<addr>`, or the custom
modules via their query paths.

---

## 4. Wallet / Keplr chain config

Wallets (the Aethelred Wallet, or Keplr for quick testing) register the chain
with a standard `ChainInfo`:

```ts
await window.keplr.experimentalSuggestChain({
  chainId: "aethelred-testnet-1",
  chainName: "Aethelred Testnet",
  rpc: "http://127.0.0.1:26657",
  rest: "http://127.0.0.1:1317",
  bip44: { coinType: 118 },
  bech32Config: {
    bech32PrefixAccAddr: "aethel",       bech32PrefixAccPub: "aethelpub",
    bech32PrefixValAddr: "aethelvaloper", bech32PrefixValPub: "aethelvaloperpub",
    bech32PrefixConsAddr: "aethelvalcons", bech32PrefixConsPub: "aethelvalconspub",
  },
  currencies: [{ coinDenom: "AETHEL", coinMinimalDenom: "uaethel", coinDecimals: 6 }],
  feeCurrencies: [{
    coinDenom: "AETHEL", coinMinimalDenom: "uaethel", coinDecimals: 6,
    gasPriceStep: { low: 0.001, average: 0.0025, high: 0.01 },
  }],
  stakeCurrency: { coinDenom: "AETHEL", coinMinimalDenom: "uaethel", coinDecimals: 6 },
});
```

---

## 5. Funding a dApp/wallet test account

There is no faucet yet; fund from a genesis validator key over the CLI:

```bash
# validator key is in the node's test keyring (localnet: val0 in node0)
aethelredd tx bank send val0 <dapp-address> 100000000uaethel \
  --keyring-backend test --home ~/.aethelred-localnet/node0 \
  --node tcp://127.0.0.1:26657 --chain-id aethelred-localnet-1 \
  --fees 2000uaethel --yes
```

(A simple HTTP faucet wrapping this is a good follow-up before opening the
public testnet to external developers.)

---

## 6. Local → public switching

A dApp should read its endpoints from env/config, not hardcode them. Only three
things change between local and public:

- `chain-id` (`aethelred-localnet-1` → the public testnet chain-id)
- RPC/REST URLs (localhost → the public hosts)
- the faucet/funding source

Everything else (prefixes, denom, decimals, coin type, message types) is
identical, so a dApp verified locally against a node behaves the same on the
public testnet.

## 7. Before exposing endpoints publicly

- Terminate TLS at a reverse proxy in front of RPC (26657) and REST (1317).
- Replace CORS `"*"` with a per-origin allowlist once dApp origins are known.
- Expose only full-node RPC/REST — never a validator's — and rate-limit them.
- Keep gRPC (9090) internal or behind the proxy; browsers use gRPC-web/REST.
