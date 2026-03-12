<h1 align="center">aethelred-sdk-ts</h1>

<p align="center">
  <strong>Official TypeScript / JavaScript SDK for the Aethelred blockchain</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@aethelred/sdk"><img src="https://img.shields.io/npm/v/@aethelred/sdk?style=flat-square&logo=npm" alt="npm"></a>
  <a href="https://github.com/aethelred/aethelred-sdk-ts/actions"><img src="https://img.shields.io/github/actions/workflow/status/aethelred/aethelred-sdk-ts/ts-ci.yml?style=flat-square&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/types-included-blue?style=flat-square&logo=typescript" alt="TypeScript">
</p>

---

## Install

```bash
npm install @aethelred/sdk
# or
yarn add @aethelred/sdk
# or
pnpm add @aethelred/sdk
```

## Quick Start

```typescript
import { AethelredClient, Wallet } from '@aethelred/sdk';

// Connect to testnet
const client = await AethelredClient.connect('https://rpc.testnet.aethelred.io');

// Create a wallet
const wallet = Wallet.fromMnemonic('your twelve word mnemonic...');

// Submit an AI compute job
const result = await client.pouw.submitJob({
  modelHash: '0xabc123...',
  inputData: Buffer.from(JSON.stringify({ prompt: 'Hello AI' })),
  verificationType: 'hybrid',  // 'tee' | 'zkml' | 'hybrid'
  priority: 'standard',
  signer: wallet,
});

console.log(`Job submitted: ${result.jobId}`);
console.log(`Seal: ${result.sealId}`);

// Query a digital seal
const seal = await client.seal.getSeal(result.sealId);
console.log(`Output hash: ${seal.outputHash}`);
console.log(`Agreement: ${seal.agreementPower}/${seal.totalPower}`);
```

## API Reference

| Module | Description |
|---|---|
| `AethelredClient` | Main entry point - connects to an Aethelred node |
| `client.pouw` | Submit jobs, query job status, get rewards |
| `client.seal` | Query Digital Seals, verify proofs |
| `client.verify` | ZK proof utilities |
| `client.bank` | Token transfers |
| `client.gov` | Governance proposals and voting |
| `client.bridge` | Ethereum bridge operations |
| `Wallet` | Key management, signing |

Full API docs: [docs.aethelred.io/sdk/typescript](https://docs.aethelred.io/sdk/typescript)

---

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm lint
```

---

## Related

- [aethelred/aethelred](https://github.com/aethelred/aethelred) - Core node
- [aethelred/aethelred-cli](https://github.com/aethelred/aethelred-cli) - CLI
