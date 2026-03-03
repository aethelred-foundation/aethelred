// Package config provides configurable constants for Aethelred.
//
// This package addresses the consultant finding regarding "magic numbers"
// by centralizing all configurable constants with documentation explaining
// their purpose and derivation.
//
// # Configuration Hierarchy
//
// Constants are organized by subsystem:
//   - HTTP client configuration
//   - Proof verification limits
//   - TEE attestation parameters
//   - Circuit breaker settings
//   - Rate limiting defaults
//
// # Override Mechanisms
//
// Many constants can be overridden via:
//  1. Module parameters (on-chain governance)
//  2. Environment variables (node operator)
//  3. Configuration files (app.toml)
//
// This package provides sensible defaults when overrides are not specified.
package config

import (
	"time"
)

// =============================================================================
// HTTP CLIENT CONFIGURATION
// =============================================================================

// HTTPConfig contains HTTP client settings for external service calls.
// These values balance security, reliability, and performance.
type HTTPConfig struct {
	// Timeout is the maximum duration for HTTP requests.
	// Rationale: 30s allows for slow responses while preventing hangs.
	Timeout time.Duration

	// MaxResponseSize is the maximum size of HTTP responses in bytes.
	// Rationale: 10MB allows for large proofs while preventing OOM attacks.
	MaxResponseSize int64

	// MaxIdleConns is the maximum number of idle connections in the pool.
	// Rationale: 10 connections provide good concurrency without resource waste.
	MaxIdleConns int

	// IdleConnTimeout is the timeout for idle connections.
	// Rationale: 90s matches common load balancer timeouts.
	IdleConnTimeout time.Duration

	// TLSHandshakeTimeout is the timeout for TLS handshake.
	// Rationale: 10s allows for slow handshakes over poor networks.
	TLSHandshakeTimeout time.Duration

	// MinTLSVersion specifies the minimum TLS version (1.2 or 1.3).
	// Rationale: TLS 1.2 is the minimum secure version as of 2024.
	MinTLSVersion uint16
}

// DefaultHTTPConfig returns the default HTTP configuration.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		Timeout:             30 * time.Second,
		MaxResponseSize:     10 * 1024 * 1024, // 10 MB
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		MinTLSVersion:       0x0303, // TLS 1.2
	}
}

// =============================================================================
// PROOF VERIFICATION LIMITS
// =============================================================================

// ProofLimits contains size limits for cryptographic proofs.
// These limits are based on the mathematical properties of each proof system.
type ProofLimits struct {
	// Groth16MinSize is the minimum valid Groth16 proof size.
	// Derivation: 3 curve points on BN254 = 3 * 64 bytes = 192 bytes
	Groth16MinSize int

	// EZKLMinSize is the minimum valid EZKL proof size.
	// Derivation: Based on EZKL circuit structure with header.
	EZKLMinSize int

	// Halo2MinSize is the minimum valid Halo2 proof size.
	// Derivation: Polynomial commitment structure requires ~384 bytes minimum.
	Halo2MinSize int

	// Plonky2MinSize is the minimum valid Plonky2 proof size.
	// Derivation: Based on FRI commitment layer requirements.
	Plonky2MinSize int

	// RISC0MinSize is the minimum valid RISC-Zero proof size.
	// Derivation: zkVM receipt structure minimum.
	RISC0MinSize int

	// STARKMinSize is the minimum valid STARK proof size.
	// Derivation: FRI layer commitments minimum.
	STARKMinSize int

	// MaxVerifyingKeySize is the maximum verifying key size.
	// Rationale: Large keys indicate malicious input or misconfiguration.
	MaxVerifyingKeySize int64

	// MaxCircuitSize is the maximum circuit definition size.
	// Rationale: Prevents resource exhaustion during circuit processing.
	MaxCircuitSize int64

	// MaxPublicInputs is the maximum number of public inputs.
	// Rationale: Prevents excessive verification time.
	MaxPublicInputs int
}

// DefaultProofLimits returns the default proof size limits.
func DefaultProofLimits() ProofLimits {
	return ProofLimits{
		// Minimum proof sizes based on proof system mathematics
		Groth16MinSize:  192,  // 3 BN254 points
		EZKLMinSize:     256,  // EZKL header + minimal proof
		Halo2MinSize:    384,  // KZG commitments minimum
		Plonky2MinSize:  256,  // FRI minimum structure
		RISC0MinSize:    512,  // zkVM receipt minimum
		STARKMinSize:    1024, // FRI layers minimum

		// Maximum sizes to prevent abuse
		MaxVerifyingKeySize: 10 * 1024 * 1024, // 10 MB
		MaxCircuitSize:      50 * 1024 * 1024, // 50 MB
		MaxPublicInputs:     1024,             // Reasonable circuit complexity
	}
}

// GetMinProofSize returns the minimum proof size for a given proof system.
func (p ProofLimits) GetMinProofSize(proofSystem string) int {
	switch proofSystem {
	case "groth16":
		return p.Groth16MinSize
	case "ezkl":
		return p.EZKLMinSize
	case "halo2":
		return p.Halo2MinSize
	case "plonky2":
		return p.Plonky2MinSize
	case "risc0":
		return p.RISC0MinSize
	case "stark":
		return p.STARKMinSize
	default:
		return 128 // Conservative default
	}
}

// =============================================================================
// TEE ATTESTATION PARAMETERS
// =============================================================================

// TEEConfig contains configuration for TEE attestation verification.
type TEEConfig struct {
	// SGXMinQuoteSize is the minimum valid Intel SGX DCAP quote size.
	// Derivation: SGX quote header (48) + report body (384) = 432 bytes minimum.
	SGXMinQuoteSize int

	// TDXMinQuoteSize is the minimum valid Intel TDX quote size.
	// Derivation: TDX quote has additional fields over SGX.
	TDXMinQuoteSize int

	// SEVMinReportSize is the minimum valid AMD SEV attestation report size.
	// Derivation: SEV-SNP report structure is 672 bytes.
	SEVMinReportSize int

	// NitroMinDocSize is the minimum valid AWS Nitro attestation document size.
	// Derivation: CBOR-encoded document with PCRs minimum.
	NitroMinDocSize int

	// MaxQuoteAge is the maximum age of an attestation quote.
	// Rationale: Prevents replay attacks while allowing clock skew.
	MaxQuoteAge time.Duration

	// DefaultMREnclaveLen is the expected length of MRENCLAVE measurement.
	// Derivation: SHA-256 hash = 32 bytes.
	DefaultMREnclaveLen int

	// DefaultMRSignerLen is the expected length of MRSIGNER measurement.
	// Derivation: SHA-256 hash = 32 bytes.
	DefaultMRSignerLen int
}

// DefaultTEEConfig returns the default TEE configuration.
func DefaultTEEConfig() TEEConfig {
	return TEEConfig{
		SGXMinQuoteSize:     432,               // Header + report body
		TDXMinQuoteSize:     584,               // Larger than SGX
		SEVMinReportSize:    672,               // SEV-SNP report structure
		NitroMinDocSize:     1000,              // CBOR overhead
		MaxQuoteAge:         5 * time.Minute,   // Allow 5 min clock skew
		DefaultMREnclaveLen: 32,                // SHA-256
		DefaultMRSignerLen:  32,                // SHA-256
	}
}

// =============================================================================
// CIRCUIT BREAKER CONFIGURATION
// =============================================================================

// CircuitBreakerConfig contains settings for circuit breaker patterns.
// These values follow industry best practices for resilience.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of failures before opening the circuit.
	// Rationale: 5 failures indicate a persistent problem.
	FailureThreshold int

	// SuccessThreshold is the number of successes to close the circuit.
	// Rationale: 3 successes indicate recovery.
	SuccessThreshold int

	// HalfOpenTimeout is the time to wait before testing a closed circuit.
	// Rationale: 30s allows transient issues to resolve.
	HalfOpenTimeout time.Duration

	// OpenTimeout is the time a circuit stays open before half-opening.
	// Rationale: 60s provides meaningful cooldown.
	OpenTimeout time.Duration

	// MaxConcurrent is the maximum concurrent requests during half-open.
	// Rationale: 1 request tests recovery without overload.
	MaxConcurrent int
}

// DefaultCircuitBreakerConfig returns the default circuit breaker configuration.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold: 5,
		SuccessThreshold: 3,
		HalfOpenTimeout:  30 * time.Second,
		OpenTimeout:      60 * time.Second,
		MaxConcurrent:    1,
	}
}

// =============================================================================
// VERIFICATION TIMEOUTS
// =============================================================================

// VerificationTimeouts contains timeout settings for verification operations.
type VerificationTimeouts struct {
	// ZKProofTimeout is the maximum time for ZK proof verification.
	// Rationale: Complex proofs may take up to 5 seconds.
	ZKProofTimeout time.Duration

	// TEEAttestationTimeout is the maximum time for TEE attestation verification.
	// Rationale: Remote attestation services may be slow.
	TEEAttestationTimeout time.Duration

	// SignatureTimeout is the maximum time for signature verification.
	// Rationale: PQC signatures are slower than classical.
	SignatureTimeout time.Duration

	// HashTimeout is the maximum time for hash computation.
	// Rationale: Large inputs may take time to hash.
	HashTimeout time.Duration
}

// DefaultVerificationTimeouts returns the default verification timeouts.
func DefaultVerificationTimeouts() VerificationTimeouts {
	return VerificationTimeouts{
		ZKProofTimeout:        5 * time.Second,
		TEEAttestationTimeout: 10 * time.Second,
		SignatureTimeout:      1 * time.Second,
		HashTimeout:           5 * time.Second,
	}
}

// =============================================================================
// JOB PROCESSING LIMITS
// =============================================================================

// JobLimits contains limits for compute job processing.
type JobLimits struct {
	// MaxPendingJobs is the maximum number of pending jobs per validator.
	// Rationale: Prevents queue exhaustion.
	MaxPendingJobs int

	// MaxJobExpiry is the maximum job expiry height (blocks).
	// Rationale: ~7 days at 6-second blocks.
	MaxJobExpiry int64

	// DefaultJobExpiry is the default job expiry height (blocks).
	// Rationale: ~1 day at 6-second blocks.
	DefaultJobExpiry int64

	// MaxInputSize is the maximum job input size.
	// Rationale: 1MB allows for reasonable model inputs.
	MaxInputSize int64

	// MaxOutputSize is the maximum job output size.
	// Rationale: 10MB allows for detailed results.
	MaxOutputSize int64

	// MaxVerificationResults is the maximum verification results per job.
	// Rationale: Matches expected validator set participation.
	MaxVerificationResults int
}

// DefaultJobLimits returns the default job limits.
func DefaultJobLimits() JobLimits {
	return JobLimits{
		MaxPendingJobs:         1000,
		MaxJobExpiry:           100800,           // ~7 days at 6s blocks
		DefaultJobExpiry:       14400,            // ~1 day at 6s blocks
		MaxInputSize:           1 * 1024 * 1024,  // 1 MB
		MaxOutputSize:          10 * 1024 * 1024, // 10 MB
		MaxVerificationResults: 100,
	}
}

// =============================================================================
// CRYPTOGRAPHIC PARAMETERS
// =============================================================================

// CryptoParams contains cryptographic algorithm parameters.
type CryptoParams struct {
	// Dilithium3PubKeySize is the public key size for Dilithium3.
	// Derivation: NIST FIPS 204 specification.
	Dilithium3PubKeySize int

	// Dilithium3SigSize is the signature size for Dilithium3.
	// Derivation: NIST FIPS 204 specification.
	Dilithium3SigSize int

	// Dilithium5PubKeySize is the public key size for Dilithium5.
	// Derivation: NIST FIPS 204 specification.
	Dilithium5PubKeySize int

	// Dilithium5SigSize is the signature size for Dilithium5.
	// Derivation: NIST FIPS 204 specification.
	Dilithium5SigSize int

	// Kyber768PubKeySize is the public key size for Kyber768.
	// Derivation: NIST FIPS 203 specification.
	Kyber768PubKeySize int

	// Kyber768CiphertextSize is the ciphertext size for Kyber768.
	// Derivation: NIST FIPS 203 specification.
	Kyber768CiphertextSize int

	// ECDSASecp256k1PubKeySize is the compressed public key size.
	// Derivation: secp256k1 curve point compression.
	ECDSASecp256k1PubKeySize int

	// ECDSASecp256k1SigSize is the signature size (r + s).
	// Derivation: Two 32-byte scalars.
	ECDSASecp256k1SigSize int

	// SHA256Size is the output size of SHA-256.
	SHA256Size int

	// SHA3_256Size is the output size of SHA3-256.
	SHA3_256Size int

	// BLAKE3Size is the default output size of BLAKE3.
	BLAKE3Size int
}

// DefaultCryptoParams returns the default cryptographic parameters.
func DefaultCryptoParams() CryptoParams {
	return CryptoParams{
		// Dilithium (ML-DSA) - NIST FIPS 204
		Dilithium3PubKeySize: 1952,
		Dilithium3SigSize:    3293,
		Dilithium5PubKeySize: 2592,
		Dilithium5SigSize:    4595,

		// Kyber (ML-KEM) - NIST FIPS 203
		Kyber768PubKeySize:     1184,
		Kyber768CiphertextSize: 1088,

		// ECDSA secp256k1
		ECDSASecp256k1PubKeySize: 33, // Compressed
		ECDSASecp256k1SigSize:    64, // r + s

		// Hash functions
		SHA256Size:   32,
		SHA3_256Size: 32,
		BLAKE3Size:   32,
	}
}

// =============================================================================
// NETWORK PARAMETERS
// =============================================================================

// NetworkConfig contains network-related configuration.
type NetworkConfig struct {
	// DefaultRPCTimeout is the default timeout for RPC calls.
	DefaultRPCTimeout time.Duration

	// DefaultP2PTimeout is the default timeout for P2P operations.
	DefaultP2PTimeout time.Duration

	// MaxPeers is the maximum number of P2P peers.
	MaxPeers int

	// BlockTime is the expected block time.
	BlockTime time.Duration
}

// DefaultNetworkConfig returns the default network configuration.
func DefaultNetworkConfig() NetworkConfig {
	return NetworkConfig{
		DefaultRPCTimeout: 10 * time.Second,
		DefaultP2PTimeout: 30 * time.Second,
		MaxPeers:          50,
		BlockTime:         6 * time.Second,
	}
}

// =============================================================================
// GLOBAL CONFIGURATION
// =============================================================================

// Config aggregates all configuration sections.
type Config struct {
	HTTP            HTTPConfig
	Proof           ProofLimits
	TEE             TEEConfig
	CircuitBreaker  CircuitBreakerConfig
	Verification    VerificationTimeouts
	Jobs            JobLimits
	Crypto          CryptoParams
	Network         NetworkConfig
}

// DefaultConfig returns the complete default configuration.
func DefaultConfig() Config {
	return Config{
		HTTP:           DefaultHTTPConfig(),
		Proof:          DefaultProofLimits(),
		TEE:            DefaultTEEConfig(),
		CircuitBreaker: DefaultCircuitBreakerConfig(),
		Verification:   DefaultVerificationTimeouts(),
		Jobs:           DefaultJobLimits(),
		Crypto:         DefaultCryptoParams(),
		Network:        DefaultNetworkConfig(),
	}
}

// Global is the global configuration instance.
// It can be overridden during initialization.
var Global = DefaultConfig()
