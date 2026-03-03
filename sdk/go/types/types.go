// Package types provides core types for the Aethelred SDK.
package types

import (
	"errors"
	"time"
)

// Common errors
var (
	ErrRateLimited   = errors.New("rate limit exceeded")
	ErrNotFound      = errors.New("not found")
	ErrUnauthorized  = errors.New("unauthorized")
	ErrTimeout       = errors.New("timeout")
)

// JobStatus represents the status of a compute job.
type JobStatus string

const (
	JobStatusUnspecified JobStatus = "JOB_STATUS_UNSPECIFIED"
	JobStatusPending     JobStatus = "JOB_STATUS_PENDING"
	JobStatusAssigned    JobStatus = "JOB_STATUS_ASSIGNED"
	JobStatusComputing   JobStatus = "JOB_STATUS_COMPUTING"
	JobStatusVerifying   JobStatus = "JOB_STATUS_VERIFYING"
	JobStatusCompleted   JobStatus = "JOB_STATUS_COMPLETED"
	JobStatusFailed      JobStatus = "JOB_STATUS_FAILED"
	JobStatusCancelled   JobStatus = "JOB_STATUS_CANCELLED"
	JobStatusExpired     JobStatus = "JOB_STATUS_EXPIRED"
)

// SealStatus represents the status of a digital seal.
type SealStatus string

const (
	SealStatusUnspecified SealStatus = "SEAL_STATUS_UNSPECIFIED"
	SealStatusActive      SealStatus = "SEAL_STATUS_ACTIVE"
	SealStatusRevoked     SealStatus = "SEAL_STATUS_REVOKED"
	SealStatusExpired     SealStatus = "SEAL_STATUS_EXPIRED"
	SealStatusSuperseded  SealStatus = "SEAL_STATUS_SUPERSEDED"
)

// ProofType represents the type of cryptographic proof.
type ProofType string

const (
	ProofTypeUnspecified ProofType = "PROOF_TYPE_UNSPECIFIED"
	ProofTypeTEE         ProofType = "PROOF_TYPE_TEE"
	ProofTypeZKML        ProofType = "PROOF_TYPE_ZKML"
	ProofTypeHybrid      ProofType = "PROOF_TYPE_HYBRID"
	ProofTypeOptimistic  ProofType = "PROOF_TYPE_OPTIMISTIC"
)

// TEEPlatform represents a TEE platform.
type TEEPlatform string

const (
	TEEPlatformUnspecified  TEEPlatform = "TEE_PLATFORM_UNSPECIFIED"
	TEEPlatformIntelSGX     TEEPlatform = "TEE_PLATFORM_INTEL_SGX"
	TEEPlatformAMDSEV       TEEPlatform = "TEE_PLATFORM_AMD_SEV"
	TEEPlatformAWSNitro     TEEPlatform = "TEE_PLATFORM_AWS_NITRO"
	TEEPlatformARMTrustZone TEEPlatform = "TEE_PLATFORM_ARM_TRUSTZONE"
)

// UtilityCategory represents a utility category.
type UtilityCategory string

const (
	UtilityCategoryUnspecified   UtilityCategory = "UTILITY_CATEGORY_UNSPECIFIED"
	UtilityCategoryMedical       UtilityCategory = "UTILITY_CATEGORY_MEDICAL"
	UtilityCategoryScientific    UtilityCategory = "UTILITY_CATEGORY_SCIENTIFIC"
	UtilityCategoryFinancial     UtilityCategory = "UTILITY_CATEGORY_FINANCIAL"
	UtilityCategoryLegal         UtilityCategory = "UTILITY_CATEGORY_LEGAL"
	UtilityCategoryEducational   UtilityCategory = "UTILITY_CATEGORY_EDUCATIONAL"
	UtilityCategoryEnvironmental UtilityCategory = "UTILITY_CATEGORY_ENVIRONMENTAL"
	UtilityCategoryGeneral       UtilityCategory = "UTILITY_CATEGORY_GENERAL"
)

// ComputeJob represents a compute job.
type ComputeJob struct {
	ID               string            `json:"id"`
	Creator          string            `json:"creator"`
	ModelHash        string            `json:"model_hash"`
	InputHash        string            `json:"input_hash"`
	OutputHash       string            `json:"output_hash,omitempty"`
	Status           JobStatus         `json:"status"`
	ProofType        ProofType         `json:"proof_type"`
	Priority         uint32            `json:"priority"`
	MaxGas           string            `json:"max_gas"`
	TimeoutBlocks    uint32            `json:"timeout_blocks"`
	CreatedAt        time.Time         `json:"created_at"`
	CompletedAt      *time.Time        `json:"completed_at,omitempty"`
	ValidatorAddress string            `json:"validator_address,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

// DigitalSeal represents a digital seal.
type DigitalSeal struct {
	ID               string                 `json:"id"`
	JobID            string                 `json:"job_id"`
	ModelHash        string                 `json:"model_hash"`
	InputCommitment  string                 `json:"input_commitment"`
	OutputCommitment string                 `json:"output_commitment"`
	ModelCommitment  string                 `json:"model_commitment"`
	Status           SealStatus             `json:"status"`
	Requester        string                 `json:"requester"`
	Validators       []ValidatorAttestation `json:"validators"`
	TEEAttestation   *TEEAttestation        `json:"tee_attestation,omitempty"`
	ZKMLProof        *ZKMLProof             `json:"zkml_proof,omitempty"`
	RegulatoryInfo   *RegulatoryInfo        `json:"regulatory_info,omitempty"`
	CreatedAt        time.Time              `json:"created_at"`
	ExpiresAt        *time.Time             `json:"expires_at,omitempty"`
	RevokedAt        *time.Time             `json:"revoked_at,omitempty"`
	RevocationReason string                 `json:"revocation_reason,omitempty"`
}

// ValidatorAttestation represents an attestation from a validator.
type ValidatorAttestation struct {
	ValidatorAddress string    `json:"validator_address"`
	Signature        string    `json:"signature"`
	Timestamp        time.Time `json:"timestamp"`
	VotingPower      string    `json:"voting_power"`
}

// TEEAttestation represents TEE attestation data.
type TEEAttestation struct {
	Platform    TEEPlatform       `json:"platform"`
	Quote       string            `json:"quote"`
	EnclaveHash string            `json:"enclave_hash"`
	Timestamp   time.Time         `json:"timestamp"`
	PCRValues   map[string]string `json:"pcr_values,omitempty"`
	Nonce       string            `json:"nonce,omitempty"`
}

// ZKMLProof represents a zero-knowledge ML proof.
type ZKMLProof struct {
	ProofSystem      string   `json:"proof_system"`
	Proof            string   `json:"proof"`
	PublicInputs     []string `json:"public_inputs"`
	VerifyingKeyHash string   `json:"verifying_key_hash"`
}

// RegulatoryInfo represents regulatory compliance information.
type RegulatoryInfo struct {
	Jurisdiction         string   `json:"jurisdiction"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	DataClassification   string   `json:"data_classification"`
	RetentionPeriod      string   `json:"retention_period"`
	AuditTrailHash       string   `json:"audit_trail_hash,omitempty"`
}

// RegisteredModel represents a registered model.
type RegisteredModel struct {
	ModelHash    string          `json:"model_hash"`
	Name         string          `json:"name"`
	Owner        string          `json:"owner"`
	Architecture string          `json:"architecture"`
	Version      string          `json:"version"`
	Category     UtilityCategory `json:"category"`
	InputSchema  string          `json:"input_schema"`
	OutputSchema string          `json:"output_schema"`
	StorageURI   string          `json:"storage_uri"`
	RegisteredAt time.Time       `json:"registered_at"`
	Verified     bool            `json:"verified"`
	TotalJobs    uint64          `json:"total_jobs"`
}

// ValidatorStats represents validator statistics.
type ValidatorStats struct {
	Address              string              `json:"address"`
	JobsCompleted        uint64              `json:"jobs_completed"`
	JobsFailed           uint64              `json:"jobs_failed"`
	AverageLatencyMs     uint64              `json:"average_latency_ms"`
	UptimePercentage     float64             `json:"uptime_percentage"`
	ReputationScore      float64             `json:"reputation_score"`
	TotalRewards         string              `json:"total_rewards"`
	SlashingEvents       uint32              `json:"slashing_events"`
	HardwareCapabilities *HardwareCapability `json:"hardware_capabilities,omitempty"`
}

// HardwareCapability represents validator hardware capabilities.
type HardwareCapability struct {
	TEEPlatforms   []TEEPlatform `json:"tee_platforms"`
	ZKMLSupported  bool          `json:"zkml_supported"`
	MaxModelSizeMB uint64        `json:"max_model_size_mb"`
	GPUMemoryGB    uint32        `json:"gpu_memory_gb"`
	CPUCores       uint32        `json:"cpu_cores"`
	MemoryGB       uint32        `json:"memory_gb"`
}

// NodeInfo represents node information.
type NodeInfo struct {
	DefaultNodeID string `json:"default_node_id"`
	ListenAddr    string `json:"listen_addr"`
	Network       string `json:"network"`
	Version       string `json:"version"`
	Moniker       string `json:"moniker"`
}

// PageRequest represents pagination parameters.
type PageRequest struct {
	Key        []byte `json:"key,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	Limit      uint64 `json:"limit,omitempty"`
	CountTotal bool   `json:"count_total,omitempty"`
	Reverse    bool   `json:"reverse,omitempty"`
}
