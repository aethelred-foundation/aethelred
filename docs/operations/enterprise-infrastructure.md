# Enterprise Infrastructure and Deployment Plan

## CI/CD Pipeline Split

Workflows are now split by concern:

1. `.github/workflows/ci.yml` (Go core + SDK release gate)
2. `.github/workflows/contracts-ci.yml` (Hardhat + Foundry)
3. `.github/workflows/rust-crates-ci.yml` (Rust crates)
4. `.github/workflows/security-scans.yml` (SAST, secrets, vuln audits)
5. `.github/workflows/sandbox-ci.yml` (Infinity Sandbox offline tests + warnings gate)
6. `.github/workflows/loadtest.yml` (smoke + scheduled stress tests)
7. `.github/workflows/staging-canary-deploy.yml` (staging/canary/prod deploy)

## Required PR Gates

Configure GitHub branch protection with these required checks:

1. `Audit Signoff Required Gate` (required on `main` and `release/*`)
2. `Core Required Gate`
3. `Contracts Required Gate`
4. `Rust Required Gate`
5. `Security Required Gate`
6. `Sandbox Required Gate`
7. `Load Test Required Gate`

You can apply these branch protections with:

```bash
scripts/setup_required_github_checks.sh <owner/repo> main develop
```

Required check mappings are maintained in:
`.github/branch-protection/required-checks.json`.

## Kubernetes Packaging

Production Helm chart added:

- `deploy/helm/aethelred-validator`

Key features:

1. Stateful validator deployment with TEE + zkML sidecars.
2. PodDisruptionBudget and NetworkPolicy defaults.
3. ServiceMonitor support.
4. Values overlays for staging/canary/production.
5. SecretProviderClass integration switch.

## Staging and Canary Delivery

Workflow:

1. Push to `main` auto-deploys to staging.
2. Manual dispatch `target=canary` deploys a one-replica canary release.
3. Manual dispatch `target=production` promotes validated image tag.

Required repo secrets:

1. `KUBE_CONFIG_STAGING`
2. `KUBE_CONFIG_PRODUCTION`
3. `PYPI_API_TOKEN` (environment: `sdk-pypi`)
4. `NPM_TOKEN` (environment: `sdk-npm`)
5. `CARGO_REGISTRY_TOKEN` (environment: `sdk-crates`)

## Secret Management

Integration examples:

1. External Secrets + AWS Secrets Manager:
- `infrastructure/kubernetes/secrets/aws-secretstore.yaml`

2. External Secrets + HashiCorp Vault:
- `infrastructure/kubernetes/secrets/vault-secretstore.yaml`

3. Secrets Store CSI:
- `infrastructure/kubernetes/secrets/secretproviderclass-aws.yaml`

## Rollout Policy

1. Deploy image tag to staging and run smoke checks.
2. Deploy same image tag to canary namespace.
3. Observe canary for 30-60 minutes with no SLO regressions.
4. Promote unchanged image tag to production.
