# Secret Management (Vault and AWS Secrets Manager)

## Objective

Keep validator, node, and TEE keys outside Git and outside static Kubernetes manifests.

## Supported Backends

1. AWS Secrets Manager via External Secrets Operator.
2. HashiCorp Vault via External Secrets Operator.
3. Optional direct CSI volume mounting via Secrets Store CSI.

## Manifests

1. `infrastructure/kubernetes/secrets/aws-secretstore.yaml`
2. `infrastructure/kubernetes/secrets/vault-secretstore.yaml`
3. `infrastructure/kubernetes/secrets/secretproviderclass-aws.yaml`

## Rotation Policy

1. Validator consensus signing keys are long-lived identity keys. Do not rotate them on a calendar schedule; rotate only for compromise, cryptographic deprecation, or a coordinated validator replacement event.
2. Rotate TEE, TLS, API, session, faucet, bridge relayer, and other operational secrets at least quarterly.
3. Keep two active non-consensus secret versions during rolling upgrade windows.
4. Trigger controlled rollout (`helm upgrade`) after non-consensus secret rotation.
5. Validate signing and attestation health before revoking prior versions.

## Access Control Baseline

1. Namespace-scoped service account with least privilege.
2. Cloud IAM role per environment (`staging`, `canary`, `production`).
3. Vault role scoped to `kv/aethelred/<env>/*` only.
4. Audit log retention >= 365 days for secret access events.
