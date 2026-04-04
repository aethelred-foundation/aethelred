# Changelog

All notable changes to the Aethelred protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0](https://github.com/aethelred-foundation/aethelred/compare/v2.0.0...v2.1.0) (2026-04-04)


### Features

* add aethelred.io and aethelred.org websites, tokenomics and whitepaper docs ([f494657](https://github.com/aethelred-foundation/aethelred/commit/f4946570fc0ae6bb0952ff04dcf195e66af2eda9))
* add Crucible — TEE-verified liquid staking vault for Aethelred ([d9cba14](https://github.com/aethelred-foundation/aethelred/commit/d9cba14e0be7c2d4f505d112300b822b81fabac8))
* add Cruzible dApp — blockchain explorer and liquid staking interface ([41634bf](https://github.com/aethelred-foundation/aethelred/commit/41634bfc084f20b34d0eaf042032723d87d0b82d))
* add NoblePay dApp — enterprise cross-border payments with TEE compliance ([5cea4e1](https://github.com/aethelred-foundation/aethelred/commit/5cea4e19fe414c37662326fd34ad8161ed095e02))
* add Shiora, ZeroID dApps and protocol-wide updates ([b9f168b](https://github.com/aethelred-foundation/aethelred/commit/b9f168b892c6fe45d539168fc16a519cf0d0f843))
* **docs:** complete documentation site for docs.aethelred.io ([f5d56c7](https://github.com/aethelred-foundation/aethelred/commit/f5d56c708d05e09f36079939120fda1954dbce41))
* **docs:** complete documentation site for docs.aethelred.io ([2138e23](https://github.com/aethelred-foundation/aethelred/commit/2138e2365b0507e982651ca578dccac92260b910))
* harden Aethelred L1 — consensus, contracts, SDK, and security improvements ([ed40b6e](https://github.com/aethelred-foundation/aethelred/commit/ed40b6ee31448691e532d39aa442cd881e339a7c))
* initial commit — Aethelred sovereign L1 for verifiable AI ([fcf18bf](https://github.com/aethelred-foundation/aethelred/commit/fcf18bf2186a5eaac2435d0a1a1f9733881d762d))
* initial commit — Aethelred sovereign L1 for verifiable AI ([031d2e9](https://github.com/aethelred-foundation/aethelred/commit/031d2e9ee689489ebc9e4482babaaac491cab4e6))
* land enterprise hybrid runtime and canonical public docs ([bfc7066](https://github.com/aethelred-foundation/aethelred/commit/bfc7066b1f0049405bce249cecb2ac3715f59245))
* **noblepay:** comprehensive security hardening, CI, and production readiness ([23b9ca5](https://github.com/aethelred-foundation/aethelred/commit/23b9ca5e72ceeaace7a2569be68f99faa4ebff0c))
* **testnet:** complete testnet readiness — Helm charts, Alertmanager, RISC0 docs ([8478a8a](https://github.com/aethelred-foundation/aethelred/commit/8478a8a84866a6c93ea6be358d6286c9a6133cd7))


### Bug Fixes

* **abci:** resolve proto typeURL conflict and TEE attestation test gaps ([926faa6](https://github.com/aethelred-foundation/aethelred/commit/926faa68f1b1c2600b974c1d457c8686af613dbd))
* **bench:** correct p50 percentile assertion (off-by-one in nearest-rank) ([1640889](https://github.com/aethelred-foundation/aethelred/commit/164088949654d62246259d26b865ce90931d8fb8))
* **ci:** add change detection and skip-safe gates to dApp and contract workflows ([24f0e49](https://github.com/aethelred-foundation/aethelred/commit/24f0e49efb3276fed08b3eb415eb69e3b5ff973c))
* **ci:** cargo fmt, SubmitApplication return values, and Trivy SARIF upload ([56c49a2](https://github.com/aethelred-foundation/aethelred/commit/56c49a2cb2771cea71a147615199c22d9860ed13))
* **ci:** make Rust cargo-fuzz advisory (fuzzing discovers, not gates) ([9e1bb4d](https://github.com/aethelred-foundation/aethelred/commit/9e1bb4ded94ab52459e5852c69ce42d21221c54d))
* **ci:** mark Foundry Deep Checks as advisory (not required gate) ([94d156d](https://github.com/aethelred-foundation/aethelred/commit/94d156d717dcb849ed8a3b13111e77dbf877f528))
* **ci:** relax CI gates for pre-existing lint and test issues ([d21c7e3](https://github.com/aethelred-foundation/aethelred/commit/d21c7e39e2ccff62472a9d4e61f229454e818152))
* **ci:** resolve Go lint errcheck and Rust clippy failures ([9f43b7b](https://github.com/aethelred-foundation/aethelred/commit/9f43b7b308a22e5ddbb9446650df028c4bf445b4))
* **ci:** scope Rust tests to core protocol crates only ([3a346c8](https://github.com/aethelred-foundation/aethelred/commit/3a346c890766be8980c5e7a3bc3533f8bb53a385))
* **consensus:** clamp job complexity to prevent fuzz crash in reputation scoring ([0ca8c72](https://github.com/aethelred-foundation/aethelred/commit/0ca8c7275e022b936a09476631abb1f78ec12830))
* **dapps:** point App links to deployed app subdomains ([0810869](https://github.com/aethelred-foundation/aethelred/commit/081086978dfb48ba87c03c6ec0f3fe43151eae17))
* **dapps:** point App links to deployed app subdomains ([5ba80ad](https://github.com/aethelred-foundation/aethelred/commit/5ba80ad9ff4d0f5f3fc544411ee9ccf46814572c))
* **dapps:** stabilize NoblePay, Cruzible, and Shiora CI configs ([546cc2f](https://github.com/aethelred-foundation/aethelred/commit/546cc2f569aa64f4bd357fb4e6701465c175d803))
* **dapps:** standardize license to Apache 2.0 and fix app URLs ([91a378a](https://github.com/aethelred-foundation/aethelred/commit/91a378a3168fc4503c4e8916e06c0e0b2649b27a))
* **dapps:** standardize license to Apache 2.0 and fix app URLs ([551a2bc](https://github.com/aethelred-foundation/aethelred/commit/551a2bcf381012e3115a518401b3f0ae4f6a8d28))
* **demo:** add thousands separators to MonetaryAmount::formatted() ([7a49495](https://github.com/aethelred-foundation/aethelred/commit/7a494957e52bf95b71a9338f185f1d8872bc7066))
* **deps:** remediate 182 Dependabot CVEs across Go, npm, Rust, and Python ([fc46287](https://github.com/aethelred-foundation/aethelred/commit/fc462873b76c1ccca6d8d7247d27ee129a28f865))
* **docs:** point README docs badge to live GitHub Pages URL ([4cfd20f](https://github.com/aethelred-foundation/aethelred/commit/4cfd20f74309a904351e07d34c87bd1c20a102e1))
* **docs:** point README docs badge to live GitHub Pages URL ([5360088](https://github.com/aethelred-foundation/aethelred/commit/5360088b6e7a7ee0c8937a2c115afc0fa51cad0e))
* **docs:** serve from GitHub Pages project URL until DNS is configured ([0a8903d](https://github.com/aethelred-foundation/aethelred/commit/0a8903d96a3bc6677b8945086aca751cc40c2804))
* **docs:** serve from GitHub Pages project URL until DNS is configured ([26adbda](https://github.com/aethelred-foundation/aethelred/commit/26adbdaaa03e21a83539a436f9914161d6e99d74))
* **lint:** handle ignored error returns in x/verify test HTTP handlers ([567655e](https://github.com/aethelred-foundation/aethelred/commit/567655edb8e2f329243e5c19b5f29db141285d31))
* **noblepay:** add migration deploy checks to release gate and CI ([8df13da](https://github.com/aethelred-foundation/aethelred/commit/8df13dadf335bf727c19d0561d8f07094a2f773f))
* **noblepay:** add sitemap config and suppress MetaMask build warning ([212e3a1](https://github.com/aethelred-foundation/aethelred/commit/212e3a178fba944b0c3a791df6713f620dabfe31))
* **noblepay:** align local and CI lint gates, zero warnings ([9f7d1ff](https://github.com/aethelred-foundation/aethelred/commit/9f7d1ffa3000fd427516e3611fc004fd1879bc2f))
* **noblepay:** fix migration gate CLI flags and add CI Postgres service ([5114ea6](https://github.com/aethelred-foundation/aethelred/commit/5114ea6fe369692f29de0fe7ac54f9bd4476e407))
* replace unstable is_multiple_of with modulo and fix golangci.yml syntax ([75038c9](https://github.com/aethelred-foundation/aethelred/commit/75038c994dfd50fb2925c92c189a705c3e70745a))
* resolve all golangci-lint violations across Go codebase ([98ac9d6](https://github.com/aethelred-foundation/aethelred/commit/98ac9d6879f33cba0eac78c0f36fe6652685e369))
* resolve all golangci-lint violations and Rust compilation errors ([e44fe7d](https://github.com/aethelred-foundation/aethelred/commit/e44fe7da428053c258d3cb66fbbee446634fbacf))
* resolve all remaining lint violations and Rust unstable feature ([9ab2ee9](https://github.com/aethelred-foundation/aethelred/commit/9ab2ee9ebf765b44966146cfa5e9081395f53b05))
* restore general-context AI provider references ([d270e0c](https://github.com/aethelred-foundation/aethelred/commit/d270e0c04b603ed6db96a29359d7a05ac6668a8b))
* restore general-context provider references ([c7f5f73](https://github.com/aethelred-foundation/aethelred/commit/c7f5f73eaa36f5210e076164163b75c7613a5f37))
* revert broken EZKL proof validation and fix Rust formatting ([02d28c8](https://github.com/aethelred-foundation/aethelred/commit/02d28c8dd97e006dafb9f70e53ce00a6eaa61f6a))
* **security:** align SAST gates with STRICT_SECURITY_GATES env var ([3539749](https://github.com/aethelred-foundation/aethelred/commit/3539749ccd9819b73b0c63110a6b8d0d7052bd43))
* **security:** exclude gosec G115 integer overflow false positives ([b2e4954](https://github.com/aethelred-foundation/aethelred/commit/b2e4954fc650a2c8187595e23374fb5a0c43f90b))
* **security:** gate Gitleaks on STRICT_SECURITY_GATES (requires GITLEAKS_LICENSE secret) ([508c960](https://github.com/aethelred-foundation/aethelred/commit/508c9602108f97f401ad4ce7db5d3474d522ac28))
* **test:** add missing on_suite_complete call in JUnit reporter test ([f5897a1](https://github.com/aethelred-foundation/aethelred/commit/f5897a19bf572da098b98b9ec0f8f3340e66a622))
* **zeroid:** isolate jest config, fix type compatibility, update testnet configs ([12f7c93](https://github.com/aethelred-foundation/aethelred/commit/12f7c93e00254f7731bd3af6825fcf33436029c2))

## [Unreleased]

### Security
- Bound TEE attestation `UserData` to block height + chain ID (`SHA256(outputHash || LE64(height) || chainID)`)
- Strict vote extension validation: unsigned extensions rejected in production mode
- Eliminated `float64` in consensus-critical emission schedule (audit fix M-05)
- Added `AllowSimulated` fail-closed guard to `cryptographicVerify` (production path)

### Added
- ABCI++ `ExtendVoteHandler` and `VerifyVoteExtensionHandler` for PoUW consensus
- On-chain ZK proof verifier (`x/verify`) with EZKL, RISC Zero, Groth16, Halo2, Plonky2 support
- Verifying key and circuit registry with tamper-proof SHA-256 hash enforcement
- Fee distribution: 40% validators / 30% treasury / 20% burn / 10% insurance (integer math, no dust loss)
- Reputation-scaled validator rewards: `reward * (50 + rep/2) / 100`
- `AethelredBridge.sol`: enterprise-grade Ethereum bridge with 2-of-N guardian multi-sig
- Dynamic fee market: congestion-based multiplier (1x → 5x at 70% utilization)
- Exponential emission decay (deterministic integer arithmetic, halving every 6 years)
- Four slashing tiers: minor_fault (0.5%) → critical_byzantine (100% + permaban)
- Encrypted mempool bridge (threshold encryption, anti-front-running)
- VRF-based validator job assignment scheduler
- `make local-testnet-up` / `make local-testnet-doctor` for local development
- Exploit simulation suite (network partition, eclipse attack, Byzantine scenarios)
- Post-quantum Dilithium3 signature support in Rust `crates/core`

### Changed
- Default consensus threshold raised from 51% to **67%** (BFT-safe floor enforced on-chain)
- `UaethelToWeiScaleFactor = 10^12` canonical conversion (audit fix C-02)
- Validator commission floor raised to 5% minimum

---

## [0.1.0] - 2026-01-15

### Added
- Initial Aethelred L1 implementation
- `x/pouw`, `x/seal`, `x/verify` core modules
- CometBFT consensus integration
- IBC support (cross-chain proof relay)
- Basic TEE client interface (Nitro / SGX / simulated)
