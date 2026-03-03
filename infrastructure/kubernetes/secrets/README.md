# Secret Management Manifests

This directory contains enterprise secret-management integration examples for Kubernetes.

## External Secrets Operator

- `aws-secretstore.yaml`: AWS Secrets Manager integration with IRSA/JWT auth.
- `vault-secretstore.yaml`: HashiCorp Vault integration with Kubernetes auth.

## CSI Driver

- `secretproviderclass-aws.yaml`: Secrets Store CSI example for direct pod mounting and optional K8s secret sync.

## Recommended Production Pattern

1. Store long-lived validator and TEE keys in Vault or AWS Secrets Manager.
2. Sync to namespaced Kubernetes secrets with External Secrets Operator.
3. Mount through CSI only when direct file mount is required.
4. Rotate keys using remote secret versioning and controlled rollout windows.
