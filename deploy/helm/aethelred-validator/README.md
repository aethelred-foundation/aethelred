# Aethelred Validator Helm Chart

Production Helm chart for deploying Aethelred validator nodes with optional TEE and zkML sidecars.

## Deploy

```bash
helm upgrade --install aethelred-validator ./deploy/helm/aethelred-validator \
  --namespace aethelred \
  --create-namespace \
  -f ./deploy/helm/aethelred-validator/values.yaml \
  -f ./deploy/helm/aethelred-validator/values/production.yaml
```

## Environment Profiles

- `values/staging.yaml`: staging-safe defaults.
- `values/canary.yaml`: single-replica canary rollout.
- `values/production.yaml`: hardened production baseline.

## Key Production Flags

- `networkPolicy.enabled=true`
- `serviceMonitor.enabled=true`
- `secretProviderClass.enabled=true`
- `podDisruptionBudget.enabled=true`

## Upgrade Canary First

```bash
helm upgrade --install aethelred-validator-canary ./deploy/helm/aethelred-validator \
  --namespace aethelred-canary \
  --create-namespace \
  -f ./deploy/helm/aethelred-validator/values.yaml \
  -f ./deploy/helm/aethelred-validator/values/canary.yaml \
  --set validator.image.tag=<new-tag>
```

After canary checks pass, promote the same image tag to the production release.
