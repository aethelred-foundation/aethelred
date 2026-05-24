# Aethelred Validator Helm Chart

Production Helm chart for deploying Aethelred validator nodes with optional TEE and zkML sidecars.

## Deploy

```bash
helm upgrade --install aethelred-validator integrations/deploy/helm/aethelred-validator \
  --namespace aethelred \
  --create-namespace \
  -f integrations/deploy/helm/aethelred-validator/values.yaml \
  -f integrations/deploy/helm/aethelred-validator/values/production.yaml
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
- `service.rpc.enabled=false` unless an internal, authenticated RPC exposure path has been approved.
- Container security contexts drop Linux capabilities, disable privilege escalation, use read-only root filesystems, and set `RuntimeDefault` seccomp.
- `teeWorker.privileged=false` by default. Hardware TEE deployments must document the runtime class, node labels, device plugin, and attestation flow before enabling privileged access.

## Preflight

```bash
helm lint integrations/deploy/helm/aethelred-validator \
  -f integrations/deploy/helm/aethelred-validator/values.yaml \
  -f integrations/deploy/helm/aethelred-validator/values/production.yaml

helm template aethelred-validator integrations/deploy/helm/aethelred-validator \
  --namespace aethelred \
  -f integrations/deploy/helm/aethelred-validator/values.yaml \
  -f integrations/deploy/helm/aethelred-validator/values/production.yaml
```

## Upgrade Canary First

```bash
helm upgrade --install aethelred-validator-canary integrations/deploy/helm/aethelred-validator \
  --namespace aethelred-canary \
  --create-namespace \
  -f integrations/deploy/helm/aethelred-validator/values.yaml \
  -f integrations/deploy/helm/aethelred-validator/values/canary.yaml \
  --set validator.image.tag=<new-tag>
```

After canary checks pass, promote the same image tag to the production release.
