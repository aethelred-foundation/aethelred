# `aethel` Developer CLI

Developer-oriented Aethelred CLI for:

- network diagnostics (`status`, `diagnostics doctor`)
- validator queries (`validator list`, `validator stats`)
- seal verification (`seal verify`, `seal verify-file`)
- token operations (`wallet balance`, `wallet send` unsigned manifests)
- local testnet orchestration (`local up|down|status|logs`)

## Local Dev (Monorepo)

```bash
cd $AETHELRED_REPO_ROOT/sdk/typescript
npm install && npm run build

cd $AETHELRED_REPO_ROOT/cli/aethel
npm install && npm run build
node dist/index.js status --network local
```

## Common Commands

```bash
aethel status --network local
aethel diagnostics doctor --network local
aethel validator list --network local
aethel local up --build
aethel seal verify-file ./seal.json
aethel wallet send --from aethel1... --to aethel1... --amount 1000000uaethel --out tx-send.json
```

