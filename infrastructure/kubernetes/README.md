# Kubernetes Deployment Assets

## Production Path

Use the Helm chart for production deployments:

- `deploy/helm/aethelred-validator`

## Legacy Static Manifests

The `validator/` manifests are retained as reference snapshots and for quick local experiments.
For mainnet/staging/canary, use Helm overlays instead of applying static YAML directly.

## Secrets

Enterprise secret-integration examples are in:

- `infrastructure/kubernetes/secrets`
