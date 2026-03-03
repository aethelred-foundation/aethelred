# Next.js Verifier Sample App

Reference application for the TypeScript SDK Next.js integrations:

- `withAethelredApiRoute()` (Pages Router)
- `withAethelredRouteHandler()` (App Router)

## Routes

- `GET /api/health`
- `POST /api/verify`
- `POST /api/legacy-verify`

## Local Run

```bash
cd $AETHELRED_REPO_ROOT/apps/nextjs-verifier
npm install
npm run dev
```

The app depends on the local SDK package via:

- `@aethelred/sdk: file:../../sdk/typescript`
