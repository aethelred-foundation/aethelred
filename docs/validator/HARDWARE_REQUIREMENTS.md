# Aethelred Validator Hardware Requirements

> **Document Version:** 1.0
> **Classification:** Partner Distribution
> **Target Audience:** Institutional Partners, Professional Validator Operators
> **Last Updated:** 2024

---

## Executive Summary

The Aethelred network operates a dual-tier validator architecture designed to balance decentralization with high-performance AI computation requirements. This specification provides hardware requirements for both **Standard Validator Nodes** (consensus participation) and **Compute Prover Nodes** (AI inference and proof generation).

**Key Network Characteristics:**
- Target throughput: **8,500+ TPS**
- Block finality: **<6 seconds**
- Hybrid verification: **TEE + zkML**
- Quantum-safe cryptography: **Dilithium/ECDSA dual-signing**

---

## Table of Contents

1. [Node Types Overview](#node-types-overview)
2. [Standard Validator Node](#standard-validator-node)
3. [Compute Prover Node](#compute-prover-node)
4. [Network Requirements](#network-requirements)
5. [TEE Requirements](#tee-requirements)
6. [Reference Architectures](#reference-architectures)
7. [Certification Process](#certification-process)
8. [FAQ](#faq)

---

## Node Types Overview

| Node Type | Role | Revenue Share | TEE Required | FPGA/GPU Required |
|-----------|------|---------------|--------------|-------------------|
| **Standard Validator** | Consensus, block proposal, light verification | 30% of fees | Optional | No |
| **Compute Prover** | AI inference, zkML proofs, heavy TEE workloads | 70% of fees | **Mandatory** | **Yes** |

Operators may run both node types simultaneously to maximize revenue potential.

---

## Standard Validator Node

### Role & Responsibilities

Standard validators participate in:
- Block proposal and consensus voting (CometBFT)
- Transaction ordering and mempool management
- Signature verification (Dilithium + ECDSA)
- Light verification of compute results
- Network relay and state sync

### Hardware Specifications

| Component | Minimum Specification | Recommended Specification | Rationale |
|-----------|----------------------|---------------------------|-----------|
| **CPU** | 16-Core AMD EPYC 7000 series or Intel Xeon Scalable (3rd Gen+) | **32-Core AMD EPYC 9004 (Genoa)** or Intel Xeon Sapphire Rapids | High core count needed for parallel signature verification (Dilithium/ECDSA hybrid). Each block requires ~1000 signature verifications. |
| **RAM** | 64 GB DDR4 ECC | **128 GB DDR5 ECC** | Large in-memory state management for high throughput. State trie caching significantly improves block processing speed. |
| **Storage** | 2 TB NVMe SSD (Enterprise Grade) | **4 TB NVMe SSD (RAID 1)** | Low latency I/O (<100μs) critical for maintaining <6s block finality. RAID 1 provides redundancy for state data. |
| **Storage IOPS** | 100,000 IOPS | 500,000+ IOPS | High IOPS required for concurrent state reads during block validation. |
| **Network** | 1 Gbps symmetric | **10 Gbps SFP+** | Fast block propagation prevents orphan blocks. Validators exchange ~5MB per block. |
| **TEE** | Optional | Intel SGX (Ice Lake+) or AMD SEV-SNP | Enables participation in basic Oracle attestation duties for additional revenue. |

### Recommended CPU Models

| Vendor | Model | Cores/Threads | Base Clock | L3 Cache | Notes |
|--------|-------|---------------|------------|----------|-------|
| AMD | EPYC 9354 | 32/64 | 3.25 GHz | 256 MB | Best price/performance |
| AMD | EPYC 9454 | 48/96 | 2.75 GHz | 256 MB | Higher parallelism |
| Intel | Xeon w5-3435X | 16/32 | 3.1 GHz | 45 MB | SGX support |
| Intel | Xeon 8462Y+ | 32/64 | 2.8 GHz | 60 MB | Enterprise reliability |

### Storage Recommendations

| Vendor | Model | Capacity | Read IOPS | Write IOPS | Endurance |
|--------|-------|----------|-----------|------------|-----------|
| Samsung | PM1733 | 3.84 TB | 1,500,000 | 250,000 | 1 DWPD |
| Intel | D7-P5620 | 3.2 TB | 1,000,000 | 220,000 | 3 DWPD |
| Micron | 9400 PRO | 3.84 TB | 1,600,000 | 300,000 | 1 DWPD |
| Kioxia | CM7-V | 3.2 TB | 2,000,000 | 400,000 | 3 DWPD |

---

## Compute Prover Node

### Role & Responsibilities

Compute Prover nodes are high-performance machines that:
- Execute AI model inference inside TEE enclaves
- Generate zkML proofs (EZKL/Halo2)
- Perform hardware-accelerated cryptographic operations
- Participate in the Multi-Vendor TEE pool
- Handle compute jobs for enterprises

**Revenue Model:** Compute Prover nodes earn **70% of all compute fees** based on jobs completed.

### Hardware Specifications

| Component | Specification | Specific Models | Rationale |
|-----------|--------------|-----------------|-----------|
| **FPGA Accelerator** | Xilinx Alveo U-Series | **Xilinx Alveo U280** (Priority Support), Alveo U250, U55C | Required for hardware-accelerated zkML circuit evaluation (MSM/NTT operations). Provides 10-100x speedup over CPU. |
| **GPU Accelerator** | NVIDIA Ampere/Hopper | **NVIDIA A100 (80GB HBM2e)**, H100 (80GB HBM3) | Massive matrix multiplications for AI inference and parallel proof generation. 80GB VRAM supports 100M+ parameter models. |
| **CPU** | 64-Core High-Performance | **AMD EPYC 7763** (Milan), EPYC 9654 (Genoa), AMD Threadripper PRO 5995WX | Managing data flow between storage and accelerators. Orchestrating parallel proof generation. |
| **RAM** | 256 GB DDR4/5 ECC | **512 GB DDR5 ECC Recommended** | Storing large model weights (100M+ parameters) entirely in memory. Reduces inference latency significantly. |
| **TEE Enclave** | **MANDATORY** | Intel SGX (Ice Lake/Sapphire Rapids), **AMD SEV-SNP** (EPYC 7003/9004) | Required to participate in the Multi-Vendor TEE pool. Enables attestation-based verification. |
| **Storage** | 8 TB NVMe | Samsung PM9A3, Intel D7-P5620 | Fast model loading and checkpoint storage. |
| **Network** | 25 Gbps | Mellanox ConnectX-6 | High bandwidth for model distribution and proof submission. |

### FPGA Requirements Detail

The Xilinx Alveo U280 is the **primary supported accelerator** for zkML operations:

| Feature | Alveo U280 | Alveo U250 | Alveo U55C |
|---------|-----------|------------|------------|
| HBM2 Memory | 8 GB | - | 16 GB |
| DDR4 Memory | 32 GB | 64 GB | - |
| Logic Cells | 1.3M | 1.3M | 1.3M |
| DSP Slices | 9,024 | 12,288 | 9,024 |
| Peak Memory BW | 460 GB/s | 77 GB/s | 460 GB/s |
| **Aethelred Support** | **Priority** | Supported | Supported |

**FPGA Use Cases:**
- Multi-Scalar Multiplication (MSM) for zkSNARK proofs
- Number Theoretic Transform (NTT) for polynomial operations
- SHA3/Poseidon hash acceleration
- Elliptic curve operations (BN254, BLS12-381)

### GPU Requirements Detail

| Model | VRAM | Memory BW | FP16 TFLOPS | Tensor TFLOPS | Power |
|-------|------|-----------|-------------|---------------|-------|
| **NVIDIA H100 SXM** | 80 GB HBM3 | 3.35 TB/s | 1,979 | 3,958 | 700W |
| **NVIDIA A100 SXM** | 80 GB HBM2e | 2.0 TB/s | 312 | 624 | 400W |
| NVIDIA A100 PCIe | 80 GB HBM2e | 2.0 TB/s | 312 | 624 | 300W |
| NVIDIA L40S | 48 GB GDDR6 | 864 GB/s | 362 | 724 | 350W |

**Minimum Requirement:** 1x NVIDIA A100 (80GB)
**Recommended:** 2x NVIDIA A100 (80GB) or 1x NVIDIA H100

### TEE Platform Comparison

| Platform | Vendor | Memory Encryption | Max Enclave Size | Attestation | Aethelred Support |
|----------|--------|-------------------|------------------|-------------|-------------------|
| **SGX** | Intel | MEE/MKTME | 512 GB (Ice Lake+) | DCAP/EPID | **Full Support** |
| **SEV-SNP** | AMD | SME/SEV | Full RAM | vTPM | **Full Support** |
| **TDX** | Intel | MKTME | Full VM | DCAP | Beta Support |
| **Nitro Enclaves** | AWS | Nitro | 8 GB | PCR | **Full Support** |

---

## Network Requirements

### Bandwidth Requirements

| Node Type | Minimum | Recommended | Peak Usage |
|-----------|---------|-------------|------------|
| Standard Validator | 1 Gbps | 10 Gbps | 5 Gbps |
| Compute Prover | 10 Gbps | 25 Gbps | 20 Gbps |

### Latency Requirements

| Metric | Requirement | Optimal |
|--------|-------------|---------|
| RTT to peers | <100ms | <50ms |
| Jitter | <20ms | <5ms |
| Packet loss | <0.1% | <0.01% |

### Port Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 26656 | TCP | P2P communication |
| 26657 | TCP | RPC endpoint |
| 26658 | TCP | ABCI++ |
| 26660 | TCP | Prometheus metrics |
| 1317 | TCP | REST API |
| 9090 | TCP | gRPC |

### Recommended Network Configuration

```
# /etc/sysctl.d/99-aethelred.conf
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_max_syn_backlog = 8096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
```

---

## TEE Requirements

### Intel SGX Configuration

**Required Hardware:**
- Intel Ice Lake or Sapphire Rapids processor with SGX2 support
- BIOS with SGX enabled and configured
- Linux kernel 5.11+ with SGX driver

**Required Software:**
```bash
# Intel SGX SDK & PSW
sudo apt install libsgx-dcap-quote-verify libsgx-dcap-ql

# Gramine (for enclave deployment)
sudo apt install gramine-sgx
```

**BIOS Settings:**
```
SGX Control: Enabled
SGX Factory Reset: Disabled
SGX Owner Epoch Update: Disabled
PRMRR Size: 128MB minimum (512MB recommended)
```

### AMD SEV-SNP Configuration

**Required Hardware:**
- AMD EPYC 7003 (Milan) or 9004 (Genoa) series
- BIOS with SEV-SNP enabled

**Required Software:**
```bash
# SEV firmware and tools
sudo apt install sev-tool amd-sev-snp-attestation

# Verify SEV support
dmesg | grep -i sev
```

**BIOS Settings:**
```
Memory Encryption: SEV-SNP
ASID Space Limit: 509
Minimum SEV Non-ES ASID: 1
SMT Control: Enabled
SNP Memory Coverage: Full
```

---

## Reference Architectures

### Standard Validator - Entry Level ($15,000-$20,000)

```
┌─────────────────────────────────────────────────────┐
│                  STANDARD VALIDATOR                  │
├─────────────────────────────────────────────────────┤
│  CPU: AMD EPYC 7313 (16-Core)                       │
│  RAM: 64 GB DDR4 ECC (4x16GB)                       │
│  Storage: 2x 1.92TB Samsung PM9A3 (RAID 1)          │
│  Network: Intel X710 10GbE dual-port                │
│  Chassis: 1U Supermicro AS-1124US-TNRP              │
│  Power: 2x 750W Platinum PSU                        │
└─────────────────────────────────────────────────────┘
```

### Standard Validator - Recommended ($30,000-$40,000)

```
┌─────────────────────────────────────────────────────┐
│               STANDARD VALIDATOR (REC)              │
├─────────────────────────────────────────────────────┤
│  CPU: AMD EPYC 9354 (32-Core)                       │
│  RAM: 128 GB DDR5 ECC (8x16GB)                      │
│  Storage: 2x 3.84TB Samsung PM1733 (RAID 1)         │
│  Network: Mellanox ConnectX-6 25GbE                 │
│  Chassis: 2U Supermicro AS-2124GQ-NART              │
│  Power: 2x 1200W Titanium PSU                       │
│  TEE: Intel SGX via separate compute blade          │
└─────────────────────────────────────────────────────┘
```

### Compute Prover - Entry Level ($80,000-$100,000)

```
┌─────────────────────────────────────────────────────┐
│                COMPUTE PROVER (ENTRY)               │
├─────────────────────────────────────────────────────┤
│  CPU: AMD EPYC 7763 (64-Core)                       │
│  RAM: 256 GB DDR4 ECC (16x16GB)                     │
│  GPU: 1x NVIDIA A100 80GB SXM                       │
│  FPGA: 1x Xilinx Alveo U280                         │
│  Storage: 4x 3.84TB NVMe (RAID 10)                  │
│  Network: Mellanox ConnectX-6 100GbE                │
│  Chassis: 4U NVIDIA DGX-compatible                   │
│  Power: 2x 2000W Titanium PSU                       │
│  TEE: AMD SEV-SNP (built-in)                        │
└─────────────────────────────────────────────────────┘
```

### Compute Prover - High Performance ($200,000-$300,000)

```
┌─────────────────────────────────────────────────────┐
│              COMPUTE PROVER (HIGH PERF)             │
├─────────────────────────────────────────────────────┤
│  CPU: 2x AMD EPYC 9654 (96-Core each)               │
│  RAM: 512 GB DDR5 ECC (32x16GB)                     │
│  GPU: 4x NVIDIA H100 80GB SXM5                      │
│  FPGA: 2x Xilinx Alveo U280                         │
│  Storage: 8x 7.68TB Samsung PM1733 (RAID 10)        │
│  Network: 2x Mellanox ConnectX-7 200GbE             │
│  Chassis: NVIDIA DGX H100 or equivalent             │
│  Power: 4x 3000W Titanium PSU                       │
│  TEE: AMD SEV-SNP + Intel TDX capability            │
└─────────────────────────────────────────────────────┘
```

---

## Certification Process

### Step 1: Hardware Registration

Submit your hardware configuration via the Aethelred Validator Portal:

```bash
aethelred-cli validator register \
  --hardware-spec ./hardware-manifest.json \
  --operator "Deutsche Bank AG" \
  --jurisdiction "Germany" \
  --tee-attestation ./attestation.bin
```

### Step 2: TEE Attestation

Generate and submit TEE attestation report:

```bash
# For Intel SGX
aethelred-cli attestation generate --platform sgx

# For AMD SEV-SNP
aethelred-cli attestation generate --platform sev-snp
```

### Step 3: Benchmark Verification

Run the official benchmark suite:

```bash
aethelred-cli benchmark run \
  --test-suite validator-certification \
  --output ./benchmark-results.json
```

**Minimum Benchmark Requirements:**

| Test | Standard Validator | Compute Prover |
|------|-------------------|----------------|
| Block validation | >1000 blocks/sec | >500 blocks/sec |
| Signature verification | >10,000/sec | >5,000/sec |
| zkML proof generation | N/A | <30 seconds |
| TEE attestation | <1 second | <1 second |
| Network throughput | >500 MB/s | >2 GB/s |

### Step 4: Stake Requirement

| Node Type | Minimum Stake | Recommended Stake |
|-----------|---------------|-------------------|
| Standard Validator | 100,000 AETH | 500,000 AETH |
| Compute Prover | 250,000 AETH | 1,000,000 AETH |

---

## FAQ

### Q: Can I run both node types on the same machine?

**A:** Yes, if your hardware meets the Compute Prover requirements. Configure separate processes with dedicated resources.

### Q: What happens if my TEE attestation fails?

**A:** Your node will be placed in "degraded mode" and can only participate in non-TEE consensus tasks. Revenue will be reduced by 50%.

### Q: Are cloud providers supported?

**A:** Yes, with caveats:
- **AWS:** Nitro Enclaves supported for TEE
- **Azure:** SGX-enabled VMs (DC-series) supported
- **GCP:** Confidential VMs (AMD SEV) supported

### Q: What is the expected ROI?

**A:** Based on projected network fees:
- Standard Validator: 8-12% annual yield
- Compute Prover: 15-25% annual yield (depends on utilization)

### Q: How often should I upgrade hardware?

**A:** We recommend hardware refresh every 3-4 years. The network will announce required upgrades with 12 months notice.

---

## Support & Contact

- **Technical Support:** validators@aethelred.io
- **Hardware Certification:** certification@aethelred.io
- **Discord:** #validator-ops channel
- **Documentation:** https://docs.aethelred.io/validators

---

*This document is confidential and intended for distribution to qualified institutional partners and professional validator operators only.*
