# `aeth` Developer CLI

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

cd $AETHELRED_REPO_ROOT/cli/aeth
npm install && npm run build
node dist/index.js status --network local
```

## Common Commands

```bash
aeth status --network local
aeth diagnostics doctor --network local
aeth validator list --network local
aeth local up --build
aeth seal verify-file ./seal.json
aeth wallet send --from aeth1... --to aeth1... --amount 1000000uaeth --out tx-send.json
```

