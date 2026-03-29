# Verifier Compatibility Reference

Last updated: 2026-03-27

This document describes the endpoint schemas, health checks, expected
request/response formats, failure behavior, and release-candidate checklist for
the two reference verifier applications shipped in `integrations/apps/`.

---

## 1. FastAPI Verifier (`integrations/apps/fastapi-verifier/`)

**Runtime:** Python 3.11+ with FastAPI >= 0.110.0 and Uvicorn >= 0.29.0

### Environment Variables

| Variable                  | Default              | Purpose                               |
|---------------------------|----------------------|---------------------------------------|
| `AETHELRED_VERIFY_MODE`   | `seal-envelope`      | Verification mode tag                 |
| `AETHELRED_RPC_URL`       | `http://localhost:26657` | Chain RPC endpoint               |
| `AETHELRED_HEADER_PREFIX` | `x-aethelred`        | HTTP header prefix for envelope data  |

### Endpoints

#### GET /health

Health check endpoint (excluded from verification middleware).

**Response 200:**
```json
{
  "status": "ok",
  "service": "aethelred-fastapi-verifier",
  "verify_mode": "seal-envelope",
  "rpc_url": "http://localhost:26657"
}
```

#### POST /infer/fraud

Run a demo fraud-detection model.

**Request body (`application/json`):**
```json
{
  "features": [0.5, 0.8, 0.3],
  "threshold": 0.5
}
```
- `features` (list of float, default `[]`) -- feature vector
- `threshold` (float, default `0.5`) -- classification threshold

**Response 200:**
```json
{
  "score": 0.533333,
  "flagged": true,
  "explanation": "demo-linear-risk-score"
}
```

#### POST /infer/text-risk

Run a demo text-risk classifier.

**Request body (`application/json`):**
```json
{
  "text": "please wire money urgently"
}
```
- `text` (string, required)

**Response 200:**
```json
{
  "result": [{"label": "RISK", "score": 0.99, "text": "please wire money urgently"}]
}
```

#### POST /chain/normalize

Run a demo LangChain-style normalizer chain.

**Request body (`application/json`):**
```json
{
  "text": "normalize this"
}
```
- `text` (string, required)

**Response 200:**
```json
{
  "answer": "NORMALIZE THIS",
  "strategy": "demo-rule-chain",
  "config": {"tenant": "demo"}
}
```

#### GET /verify/recent?limit=20

Retrieve recent verification envelopes from in-memory history.

**Query parameters:**
- `limit` (int, optional, clamped to 1..100, default 20)

**Response 200:**
```json
{
  "items": [
    {
      "trace_id": "...",
      "framework": "pytorch",
      "operation": "inference",
      "input_hash": "sha256:...",
      "output_hash": "sha256:...",
      "timestamp_ms": 1711540000000,
      "metadata": {"service": "aethelred-fastapi-verifier", ...}
    }
  ]
}
```

### Middleware

All routes except `/health` and `/metrics` pass through
`AethelredVerificationMiddleware`, which attaches seal-envelope headers using
the configured `AETHELRED_HEADER_PREFIX`.

---

## 2. Next.js Verifier (`integrations/apps/nextjs-verifier/`)

**Runtime:** Node.js 18+ with Next.js >= 15.x

**SDK dependency:** `@aethelred/sdk` (linked from `sdk/typescript/` via
`file:../../../sdk/typescript`)

### Environment Variables

| Variable                  | Default              | Purpose                               |
|---------------------------|----------------------|---------------------------------------|
| `AETHELRED_VERIFY_MODE`   | `seal-envelope`      | Verification mode tag                 |
| `AETHELRED_RPC_URL`       | (none)               | Chain RPC endpoint                    |
| `AETHELRED_HEADER_PREFIX` | `x-aethelred`        | HTTP header prefix for envelope data  |

### Endpoints

#### GET /api/health (App Router)

Health check wrapped with `withAethelredRouteHandler`.

**Response 200:**
```json
{
  "status": "ok",
  "service": "aethelred-nextjs-verifier-sample"
}
```

#### POST /api/verify (App Router)

Classify a prompt for risk, wrapped with `withAethelredRouteHandler`.

**Request body (`application/json`):**
```json
{
  "prompt": "please wire money urgently"
}
```
- `prompt` (string, optional -- defaults to `""` if missing or null)

**Response 200:**
```json
{
  "prompt": "please wire money urgently",
  "label": "RISK",
  "score": 0.98,
  "mode": "seal-envelope",
  "rpcUrl": null
}
```

Risk keywords (case-insensitive): `wire`, `urgent`, `override`, `password`,
`otp`, `bypass`.

#### POST /api/legacy-verify (Pages Router)

Text normalizer wrapped with `withAethelredApiRoute`.

**Request body (`application/json`):**
```json
{
  "text": "  some   text  "
}
```

**Response 200:**
```json
{
  "normalized": "some text",
  "framework": "nextjs-pages-router",
  "headerPrefix": "x-aethelred"
}
```

---

## 3. API Version Compatibility

| Component              | Version   | Source                        |
|------------------------|-----------|-------------------------------|
| OpenAPI spec           | 1.0.0     | `version-matrix.json`         |
| REST path prefix       | `/v1`     | `version-matrix.json`         |
| TypeScript SDK         | 1.0.0     | `sdk/typescript/package.json` |
| Python SDK             | 1.0.0     | `sdk/python/pyproject.toml`   |
| Node RPC default port  | 26657     | CometBFT default              |

Both verifiers are sample/reference apps. They do not call the chain node REST
API (`/v1/...`) directly; instead they use the SDK integration layer which
wraps framework calls with seal-envelope recording.  The SDK versions must
match the node API version (`1.0.0`) to ensure envelope format compatibility.

---

## 4. Failure Behavior

### Timeout

- **FastAPI:** Uvicorn enforces a default keep-alive timeout (5 s). Long-running
  inference stubs complete in-process, so timeouts are unlikely unless the
  upstream RPC node is unreachable during envelope submission. When the RPC is
  down, the middleware records the envelope locally (in-memory sink) without
  blocking the response.
- **Next.js:** Default Vercel function timeout (10 s hobby / 60 s pro) applies.
  The `withAethelredRouteHandler` wrapper catches errors and returns the
  underlying response even when envelope submission fails.

### Malformed Input

- **FastAPI:** Pydantic v2 validation returns HTTP `422 Unprocessable Entity`
  with a JSON body detailing field errors. Missing optional fields use
  defaults. Unknown extra fields are silently ignored.
- **Next.js:** The handler reads `request.json()` and defaults missing `prompt`
  to `""`. Completely unparseable JSON will throw, producing a `400` or `500`
  depending on the SDK wrapper behavior.

### Backend (Chain Node) Down

Both verifiers operate in **demo mode** -- they do not require a live chain
node to return inference results.  Envelope recording proceeds to the
in-memory sink (FastAPI) or is silently skipped (Next.js SDK wrapper).  No
errors are surfaced to the caller when the RPC endpoint is unreachable.

---

## 5. Release-Candidate Checklist

Before tagging a release candidate, verify the following for both verifier
sample apps:

### FastAPI Verifier

- [ ] Install dependencies: `pip install -r requirements.txt && pip install -e
      ../../sdk/python[integrations]`
- [ ] Start server: `uvicorn app.main:app --port 8000`
- [ ] Health check passes: `curl http://localhost:8000/health` returns
      `{"status": "ok", ...}`
- [ ] Inference responds: `curl -X POST http://localhost:8000/infer/fraud
      -H 'Content-Type: application/json' -d '{"features":[0.5]}'` returns
      200 with `score` field
- [ ] Negative-path tests pass: `cd tests && pytest -v`
- [ ] Envelope recording: `curl http://localhost:8000/verify/recent` returns
      items after inference calls

### Next.js Verifier

- [ ] Install dependencies: `npm install` (requires SDK built at
      `sdk/typescript/`)
- [ ] Start dev server: `npm run dev`
- [ ] Health check passes: `curl http://localhost:3000/api/health` returns
      `{"status": "ok", ...}`
- [ ] Verify responds: `curl -X POST http://localhost:3000/api/verify
      -H 'Content-Type: application/json' -d '{"prompt":"test"}'` returns
      200 with `label` field
- [ ] Legacy route responds: `curl -X POST
      http://localhost:3000/api/legacy-verify
      -H 'Content-Type: application/json' -d '{"text":"hello  world"}'`
      returns 200 with `normalized` field
- [ ] Negative-path tests pass: `npx vitest run tests/verify-route.test.ts`
- [ ] Production build succeeds: `npm run build`

### Cross-Verifier

- [ ] Both verifiers use the same `AETHELRED_HEADER_PREFIX` default
      (`x-aethelred`)
- [ ] Both verifiers use the same `AETHELRED_VERIFY_MODE` default
      (`seal-envelope`)
- [ ] SDK versions in `version-matrix.json` match the installed SDK packages
