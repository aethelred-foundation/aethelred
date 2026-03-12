# Lead Backend Runbook

This website now includes a production-style lead intake service at `POST /api/leads`.

## Features

- Strict server-side validation for investor request payloads.
- Anti-spam controls:
  - Hidden honeypot field (`website`).
  - minimum submit-time guard (`startedAt`).
  - IP rate limiting (window + daily caps).
- Durable append-only storage (`data/leads.jsonl`).
- Optional outbound webhook notifications for CRM, Slack, or email automation.
- Security headers and same-origin default posture.

## Quick start

```bash
cd /Users/rameshtamilselvan/Downloads/aethelred/frontend/website/org
cp .env.example .env   # optional; values are read from environment
npm run start
```

Service starts on:

- `http://0.0.0.0:8787` by default
- static pages + API served from one process

## API endpoints

- `POST /api/leads`
- `OPTIONS /api/leads`
- `GET /api/leads/health`

## Expected payload

```json
{
  "name": "Jane Smith",
  "email": "jane@fund.com",
  "institution": "Example Capital",
  "type": "Venture Capital",
  "region": "MENA",
  "timeline": "Q2 2026 diligence",
  "message": "Interested in private round docs.",
  "consent": true,
  "website": "",
  "startedAt": "2026-03-04T20:15:00.000Z",
  "sourcePath": "/investors.html",
  "sourceUrl": "https://www.aethelred.org/investors"
}
```

## Environment variables

See `.env.example`.

Most important production values:

- `LEAD_WEBHOOK_URL`: endpoint for downstream automation.
- `LEAD_WEBHOOK_TOKEN`: bearer token for webhook auth.
- `LEAD_PII_SALT`: salt used to hash source IP values.
- `ALLOWED_ORIGINS`: comma-separated list for cross-origin API clients.

## Webhook contract

When configured, the backend sends:

```json
{
  "event": "investor_lead.created",
  "lead": {
    "id": "lead_xxx",
    "createdAt": "...",
    "lead": { "...": "..." },
    "meta": { "ipHash": "...", "userAgent": "...", "referer": "..." }
  }
}
```

## Operational note

`data/leads.jsonl` should be mounted on persistent storage in production and ingested by your CRM/warehouse pipeline.
