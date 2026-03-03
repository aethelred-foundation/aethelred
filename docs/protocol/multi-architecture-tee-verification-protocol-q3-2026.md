# Aethelred Multi-Architecture TEE Verification Protocol (Q3 2026)

## Document Metadata

| Attribute | Value |
|-----------|-------|
| Status | Drafted for Q3 2026 delivery |
| Scope | `x/verify` hardware-diversity attestation pipeline |
| Effective Window | Testnet rollout after AWS Nitro-only phase |
| References | AMD SEV-SNP Firmware ABI (doc 56860), Intel SGX DCAP quote format, `x/verify/tee/dcap/verifier.go` |

## Objective

Keep Testnet velocity on AWS Nitro while proving there is no long-term vendor lock-in by defining deterministic parsing and normalization for:

- Intel SGX DCAP quotes
- AMD SEV-SNP attestation reports

The normalization target remains the existing protobuf surface (`TEEAttestation` in `x/verify/types/verify.proto`) so consensus state schema does not change.

## Canonical Ingestion Contract (No State Migration)

All TEEs are translated into the same canonical evidence envelope already used by `x/verify`:

- `platform`: `TEE_PLATFORM_INTEL_SGX`, `TEE_PLATFORM_AMD_SEV`, or `TEE_PLATFORM_AWS_NITRO`
- `measurement`: enclave measurement (`MRENCLAVE` for SGX, `measurement` for SNP, `PCR0` for Nitro)
- `quote`: full raw vendor report bytes
- `user_data`: quote-bound payload (`report_data`, challenge/nonce hash, output hash binding)
- `certificate_chain`: vendor cert chain (Intel PCK collateral or AMD ARK/ASK/VCEK)
- `timestamp`: attestation freshness anchor

This preserves deterministic protobuf and store keys across hardware families.

## Intel SGX DCAP Byte Parsing

The parser implemented in `x/verify/tee/dcap/verifier.go` is authoritative.

### SGX Quote Header (48 bytes, little-endian scalar fields)

| Offset | Size | Field |
|--------|------|-------|
| `0x000` | 2 | `version` |
| `0x002` | 2 | `att_key_type` |
| `0x004` | 4 | `reserved` |
| `0x008` | 2 | `qe_svn` |
| `0x00A` | 2 | `pce_svn` |
| `0x00C` | 16 | `qe_id` |
| `0x01C` | 20 | `user_data` |

### SGX Report Body (384 bytes)

| Offset | Size | Field |
|--------|------|-------|
| `0x030` | 16 | `cpu_svn` |
| `0x040` | 4 | `misc_select` |
| `0x044` | 12 | `reserved1` |
| `0x050` | 16 | `isv_ext_prod_id` |
| `0x060` | 8 | `attributes.flags` |
| `0x068` | 8 | `attributes.xfrm` |
| `0x070` | 32 | `MRENCLAVE` |
| `0x090` | 32 | `reserved2` |
| `0x0B0` | 32 | `MRSIGNER` |
| `0x0D0` | 32 | `reserved3` |
| `0x0F0` | 64 | `config_id` |
| `0x130` | 2 | `isv_prod_id` |
| `0x132` | 2 | `isv_svn` |
| `0x134` | 2 | `config_svn` |
| `0x136` | 42 | `reserved4` |
| `0x160` | 16 | `isv_family_id` |
| `0x170` | 64 | `report_data` |

### SGX Signature Section

- `0x1B0`..`0x1B3`: `signature_size` (`uint32`)
- Remaining bytes parse as ECDSA Quote Signature Data:
1. ISV signature (`r||s`, 64 bytes)
2. Attestation key (`x||y`, 64 bytes)
3. QE report body (384 bytes)
4. QE report signature (64 bytes)
5. QE auth data length + data
6. Cert data type + cert data length + cert data

`x/verify` verifies:

- quote ECDSA signature
- QE report signature
- report-data binding for `sha256(nonce || output_hash)` in first 32 bytes
- certificate chain, revocation, and TCB policy

## AMD SEV-SNP Byte Parsing

Parser target is AMD SEV-SNP attestation report layout (doc 56860, Table 22). Scalars are little-endian.

### SNP Report Fixed Header

| Offset | Size | Field |
|--------|------|-------|
| `0x000` | 4 | `version` |
| `0x004` | 4 | `guest_svn` |
| `0x008` | 8 | `policy` |
| `0x010` | 16 | `family_id` |
| `0x020` | 16 | `image_id` |
| `0x030` | 4 | `vmpl` |
| `0x034` | 4 | `signature_algo` |
| `0x038` | 8 | `current_tcb` |
| `0x040` | 8 | `platform_info` |
| `0x048` | 4 | `signer_info_or_flags` |
| `0x04C` | 4 | `reserved0` |

### SNP Body Region (versioned fields, v2 baseline)

| Offset | Size | Field |
|--------|------|-------|
| `0x050` | 64 | `report_data` |
| `0x090` | 48 | `measurement` |
| `0x0C0` | 32 | `host_data` |
| `0x0E0` | 48 | `id_key_digest` |
| `0x110` | 48 | `author_key_digest` |
| `0x140` | 32 | `report_id` |
| `0x160` | 32 | `report_id_ma` |
| `0x180` | 8 | `reported_tcb` |
| `0x188` | 64 | `chip_id` |
| `0x1C8` | 8 | `committed_tcb` |
| `0x1D0` | 3 | `current_build_triplet` |
| `0x1D3` | 3 | `committed_build_triplet` |
| `0x1D6` | 8 | `launch_tcb` |
| `0x1DE`..`0x29F` | 194 | `reserved_or_version_extensions` |

### SNP Signature Region

- `0x2A0`..`0x49F` (512 bytes): signature block (ECDSA P-384 structure; implementation parses `r`, `s`, and reserved bytes per report version policy).

## Universal Translation Rules in `x/verify`

The translation contract is adapter-only, not state-schema:

1. Parse vendor bytes into a transient `ParsedTEEEvidence`.
2. Map measurement/user-data into `TEEAttestation.measurement` and `TEEAttestation.user_data`.
3. Preserve vendor report bytes in `TEEAttestation.quote`.
4. Keep verification decisions in `VerificationResult` only.

No protobuf message IDs, store keys, or consensus parameters are changed by adding SGX/SNP parser support.

## Consensus-Safe Rollout Plan

1. Add parser code behind platform dispatch in `verifyPlatformAttestationAdapter`.
2. Keep `x/verify/types` unchanged.
3. Add parser test vectors and malformed-quote negative tests.
4. Activate SGX/SNP platforms via governance `TEEConfig` updates, not schema migrations.

## Acceptance Mapping

- SGX DCAP byte parsing: fully specified and already aligned with `x/verify/tee/dcap/verifier.go`.
- SEV-SNP byte parsing: fixed offsets and signature region specified with version-aware extension window.
- Universal translation: explicitly mapped to existing `TEEAttestation` protobuf fields.
- Consensus safety: no state migrations required; activation is config-level only.
