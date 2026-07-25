package keeper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/crypto/bls"
	"github.com/aethelred/aethelred/x/pouw/types"
	verifytee "github.com/aethelred/aethelred/x/verify/tee"
)

// ConsensusHandler handles the Proof-of-Useful-Work consensus logic
// It integrates with CometBFT's ABCI++ to enable computation verification during consensus.
//
// NOTE: The canonical vote extension types (VoteExtension, ComputeVerification,
// TEEAttestationData, ZKProofData) are defined in app/vote_extension.go.
// This handler uses its own internal wire format (VoteExtensionWire) for
// parsing vote extensions received from the ABCI layer. The ABCI layer in
// app/abci.go handles the authoritative type definitions and serialization.
type ConsensusHandler struct {
	logger    log.Logger
	keeper    *Keeper
	scheduler *JobScheduler
	verifier  JobVerifier

	// Evidence collection for misbehavior detection
	evidenceCollector *EvidenceCollector

	// Evidence processing for downtime slashing and double-vote penalties.
	// Wired to BlockMissTracker + DoubleVotingDetector + SlashingIntegration.
	evidenceProcessor *EvidenceProcessor

	// Configuration
	consensusThreshold int // Percentage required for consensus (e.g., 67 for 2/3)
	maxJobsPerBlock    int
}

const compactValidatorSignatureVersion = 1

// Scheduler returns the job scheduler used by the consensus handler.
// It enables graceful shutdown coordination from the app layer.
func (ch *ConsensusHandler) Scheduler() *JobScheduler {
	if ch == nil {
		return nil
	}
	return ch.scheduler
}

// JobVerifier allows pluggable verification implementations (TEE/zkML).
// In production, this should call real enclave workers and proof verifiers.
type JobVerifier interface {
	VerifyJob(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, validatorAddr string) (types.VerificationResult, error)
}

// NewConsensusHandler creates a new consensus handler
func NewConsensusHandler(logger log.Logger, keeper *Keeper, scheduler *JobScheduler) *ConsensusHandler {
	return &ConsensusHandler{
		logger:            logger,
		keeper:            keeper,
		scheduler:         scheduler,
		evidenceCollector: NewEvidenceCollector(logger, keeper),
		evidenceProcessor: NewEvidenceProcessor(
			logger, keeper,
			DefaultBlockMissConfig(),
			DefaultEvidenceSlashingConfig(),
		),
		consensusThreshold: 0, // Will be read from params dynamically; 0 means "use params"
		maxJobsPerBlock:    10,
	}
}

// getConsensusThreshold returns the consensus threshold from params or default (67%).
// This ensures the threshold is always read from on-chain governance params rather
// than a hardcoded value, while maintaining BFT safety with a minimum of 67%.
func (ch *ConsensusHandler) getConsensusThreshold(ctx sdk.Context) int {
	// If explicitly set (for testing), use that value
	if ch.consensusThreshold > 0 {
		return ch.consensusThreshold
	}

	// Read from on-chain params
	if ch.keeper != nil {
		params, err := ch.keeper.GetParams(ctx)
		if err == nil && params != nil && params.ConsensusThreshold >= 67 {
			return int(params.ConsensusThreshold)
		}
	}

	// Default to BFT-safe 67% if params unavailable or invalid
	return 67
}

func (ch *ConsensusHandler) simulatedVerificationEnabled(ctx sdk.Context) bool {
	if !allowSimulatedInThisBuild() {
		return false
	}
	if ch.keeper == nil {
		return false
	}
	params, err := ch.keeper.GetParams(ctx)
	if err != nil || params == nil {
		return false
	}
	return params.AllowSimulated
}

func (ch *ConsensusHandler) productionVerificationMode(ctx sdk.Context) bool {
	return !ch.simulatedVerificationEnabled(ctx)
}

func isSupportedTEEPlatform(platform string) bool {
	switch platform {
	case "aws-nitro", "intel-sgx", "intel-tdx", "amd-sev", "arm-trustzone",
		"simulated", "nitro-simulated", "mock-tee":
		return true
	default:
		return false
	}
}

func isSimulatedTEEPlatform(platform string) bool {
	switch platform {
	case "simulated", "nitro-simulated", "mock-tee":
		return true
	default:
		return false
	}
}

// requiredThresholdCount computes ceil(total * threshold / 100) using integer
// math only and caps the requirement at total when threshold <= 100.
func requiredThresholdCount[T ~int | ~int64](total T, threshold int) T {
	if total <= 0 || threshold <= 0 {
		return 0
	}
	if threshold >= 100 {
		return total
	}
	// Split the multiplication so total*threshold cannot overflow near the
	// CometBFT voting-power limit.
	whole := (total / 100) * T(threshold)
	remainder := total % 100
	required := whole + (remainder*T(threshold)+99)/100
	if required > total {
		return total
	}
	return required
}

// SetVerifier injects a verifier implementation for production use.
func (ch *ConsensusHandler) SetVerifier(verifier JobVerifier) {
	ch.verifier = verifier
}

// GetEvidenceCollector returns the handler's evidence collector for use by
// the ABCI layer or tests. Returns nil if the handler was created without
// a keeper (which means the evidence collector is also nil).
func (ch *ConsensusHandler) GetEvidenceCollector() *EvidenceCollector {
	return ch.evidenceCollector
}

// VoteExtensionWire is the wire format for deserializing vote extensions
// received from the ABCI layer. This mirrors the canonical VoteExtension
// type in app/vote_extension.go to avoid circular imports.
type VoteExtensionWire struct {
	Version          int32              `json:"version"`
	Height           int64              `json:"height"`
	ChainID          string             `json:"chain_id"`
	ValidatorAddress json.RawMessage    `json:"validator_address"`
	Verifications    []VerificationWire `json:"verifications"`
	Timestamp        time.Time          `json:"timestamp"`
	Signature        json.RawMessage    `json:"signature"`
	ExtensionHash    json.RawMessage    `json:"extension_hash"`

	// BLS12-381 signature over the extension hash for aggregation.
	// Optional: validators that have BLS keys configured include this.
	BLSSignature []byte `json:"bls_signature,omitempty"`
	BLSPubKey    []byte `json:"bls_pub_key,omitempty"`
}

// VerificationWire is the wire format for a single verification result.
// Mirrors ComputeVerification from app/vote_extension.go.
type VerificationWire struct {
	JobID                     string          `json:"job_id"`
	ModelHash                 []byte          `json:"model_hash"`
	InputHash                 []byte          `json:"input_hash"`
	OutputHash                []byte          `json:"output_hash"`
	AttestationType           string          `json:"attestation_type"`
	TEEAttestation            json.RawMessage `json:"tee_attestation,omitempty"`
	ZKProof                   json.RawMessage `json:"zk_proof,omitempty"`
	ExecutionTimeMs           int64           `json:"execution_time_ms"`
	Success                   bool            `json:"success"`
	ErrorCode                 string          `json:"error_code,omitempty"`
	ErrorMessage              string          `json:"error_message,omitempty"`
	Nonce                     []byte          `json:"nonce"`
	ValidatorSignatureVersion int32           `json:"validator_signature_version,omitempty"`
	VoteBlockHash             []byte          `json:"vote_block_hash,omitempty"`
	ExtensionNonce            []byte          `json:"extension_nonce,omitempty"`
	ValidatorSignature        []byte          `json:"validator_signature,omitempty"`
}

// AggregatedResult represents consensus results for a job.
// This is the keeper's output format, consumed by the ABCI layer.
type AggregatedResult struct {
	JobID            string
	ModelHash        []byte
	InputHash        []byte
	OutputHash       []byte
	ValidatorResults []ValidatorResult
	TotalVotes       int
	TotalPower       int64
	AgreementCount   int
	AgreementPower   int64
	HasConsensus     bool

	// BLS aggregate signature over the consensus result.
	// When present, this single 96-byte signature replaces N individual
	// validator signatures, reducing on-chain data and verification cost.
	BLSAggregateSignature []byte   `json:"bls_aggregate_signature,omitempty"`
	BLSSignerPubKeys      [][]byte `json:"bls_signer_pub_keys,omitempty"`
}

// ValidatorResult represents a single validator's result
type ValidatorResult struct {
	ValidatorAddress          string              `json:"validator_address"`
	ValidatorConsensusAddress []byte              `json:"validator_consensus_address"`
	OutputHash                []byte              `json:"output_hash"`
	AttestationType           string              `json:"attestation_type"`
	TEEAttestation            *TEEAttestationWire `json:"tee_attestation,omitempty"`
	ZKProof                   *ZKProofWire        `json:"zk_proof,omitempty"`
	Nonce                     []byte              `json:"nonce"`
	ExecutionTimeMs           int64               `json:"execution_time_ms"`
	Timestamp                 time.Time           `json:"timestamp"`
	ValidatorSignatureVersion int32               `json:"validator_signature_version"`
	VoteBlockHash             []byte              `json:"vote_block_hash"`
	ExtensionNonce            []byte              `json:"extension_nonce"`
	ValidatorSignature        []byte              `json:"validator_signature"`

	// BLS signature components for aggregation
	BLSSignature []byte `json:"-"`
	BLSPubKey    []byte `json:"-"`
}

// PrepareVoteExtension creates verification data for the current validator.
// Returns raw verification results that the ABCI layer wraps into a VoteExtension.
func (ch *ConsensusHandler) PrepareVoteExtension(ctx sdk.Context, validatorAddr string) ([]types.VerificationResult, error) {
	// Get jobs assigned to this validator
	jobs := ch.scheduler.GetJobsForValidator(ctx, validatorAddr)
	if len(jobs) == 0 {
		return nil, nil
	}

	// Execute verifications for each job
	var results []types.VerificationResult
	for _, job := range jobs {
		result := ch.executeVerification(ctx, job, validatorAddr)
		results = append(results, result)
	}

	return results, nil
}

// executeVerification executes a single compute job verification
func (ch *ConsensusHandler) executeVerification(ctx sdk.Context, job *types.ComputeJob, validatorAddr string) types.VerificationResult {
	startTime := time.Now()

	result := types.VerificationResult{
		ValidatorAddress: validatorAddr,
		Success:          false,
		Timestamp:        timestamppb.Now(),
	}

	// Get registered model to verify against
	model, err := ch.keeper.GetRegisteredModel(ctx, job.ModelHash)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("model not found: %s", err)
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	// If a real verifier is configured, use it
	if ch.verifier != nil {
		verified, vErr := ch.verifier.VerifyJob(ctx, job, model, validatorAddr)
		if vErr != nil {
			result.ErrorMessage = vErr.Error()
			result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
			return result
		}
		verified.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		return verified
	}

	// ================================================================
	// SIMULATION GUARD: Only testnet/devnet may reach this code path.
	// In production, ch.verifier MUST be set. If AllowSimulated is
	// false (the default), this path returns an error.
	// ================================================================
	if ch.productionVerificationMode(ctx) {
		result.ErrorMessage = "SECURITY: no verifier configured and AllowSimulated=false; " +
			"set a real JobVerifier via ConsensusHandler.SetVerifier(); " +
			"production builds ignore governance attempts to enable simulation"
		result.ExecutionTimeMs = time.Since(startTime).Milliseconds()
		ch.logger.Error("Verification blocked: no real verifier and simulation disabled",
			"job_id", job.Id,
			"validator", validatorAddr,
		)
		return result
	}

	ch.logger.Warn("SIMULATED verification - NOT FOR PRODUCTION",
		"job_id", job.Id,
		"validator", validatorAddr,
		"proof_type", job.ProofType,
	)

	// Execute verification based on proof type (SIMULATED)
	switch job.ProofType {
	case types.ProofTypeTEE:
		result.AttestationType = "tee"
		ch.executeTEEVerification(ctx, job, model, &result)

	case types.ProofTypeZKML:
		result.AttestationType = "zkml"
		ch.executeZKMLVerification(ctx, job, model, &result)

	case types.ProofTypeHybrid:
		result.AttestationType = "hybrid"
		ch.executeHybridVerification(ctx, job, model, &result)

	default:
		result.ErrorMessage = fmt.Sprintf("unknown proof type: %s", job.ProofType)
	}

	result.ExecutionTimeMs = time.Since(startTime).Milliseconds()

	ch.logger.Info("Verification executed",
		"job_id", job.Id,
		"validator", validatorAddr,
		"success", result.Success,
		"execution_time_ms", result.ExecutionTimeMs,
		"attestation_type", result.AttestationType,
	)

	return result
}

// executeTEEVerification performs SIMULATED TEE-based verification.
// WARNING: This function produces deterministic fake attestations.
// Production validators MUST use ConsensusHandler.SetVerifier() with a
// real JobVerifier that communicates with a TEE enclave.
// This code path is only reachable when AllowSimulated=true in module params.
func (ch *ConsensusHandler) executeTEEVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	outputHash := computeDeterministicOutput(job.ModelHash, job.InputHash)

	// Generate attestation data
	quote := generateAttestationQuote(outputHash, model.TeeMeasurement)

	result.OutputHash = outputHash
	result.TeePlatform = "aws-nitro"
	result.AttestationData = quote
	result.Success = true
}

// executeZKMLVerification performs SIMULATED zkML-based verification.
// WARNING: This function produces fake proofs. See executeTEEVerification doc.
func (ch *ConsensusHandler) executeZKMLVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	// Compute deterministic output
	outputHash := computeDeterministicOutput(job.ModelHash, job.InputHash)

	// Generate simulated zkML proof
	zkProof := generateZKProof(job.ModelHash, job.InputHash, outputHash, model.CircuitHash)

	result.OutputHash = outputHash
	result.AttestationData = zkProof
	result.Success = true
}

// executeHybridVerification performs SIMULATED hybrid verification.
// WARNING: This function produces fake attestations and proofs. See executeTEEVerification doc.
func (ch *ConsensusHandler) executeHybridVerification(ctx sdk.Context, job *types.ComputeJob, model *types.RegisteredModel, result *types.VerificationResult) {
	// Execute TEE first
	ch.executeTEEVerification(ctx, job, model, result)

	if result.Success {
		// Also generate zkML proof (stored alongside TEE attestation)
		zkProof := generateZKProof(job.ModelHash, job.InputHash, result.OutputHash, model.CircuitHash)
		// Append zkML proof after TEE attestation data, separated by marker
		result.AttestationData = append(result.AttestationData, []byte("|ZKML|")...)
		result.AttestationData = append(result.AttestationData, zkProof...)
	}
}

// computeDeterministicOutput generates a deterministic output hash.
// All validators must produce the same output for the same input.
func computeDeterministicOutput(modelHash, inputHash []byte) []byte {
	combined := make([]byte, 0, len(modelHash)+len(inputHash)+len("aethelred_compute_v1"))
	combined = append(combined, modelHash...)
	combined = append(combined, inputHash...)
	combined = append(combined, []byte("aethelred_compute_v1")...)
	return sha256Hash(combined)
}

// generateAttestationQuote generates a SIMULATED attestation quote (testnet only).
func generateAttestationQuote(outputHash, measurement []byte) []byte {
	data := make([]byte, 0, len("NITRO_QUOTE_V1:")+len(measurement)+len(outputHash))
	data = append(data, []byte("NITRO_QUOTE_V1:")...)
	data = append(data, measurement...)
	data = append(data, outputHash...)
	return sha256Hash(data)
}

// generateZKProof generates a SIMULATED zkML proof (testnet only).
func generateZKProof(modelHash, inputHash, outputHash, circuitHash []byte) []byte {
	data := make([]byte, 0, len("EZKL_PROOF_V1:")+len(modelHash)+len(inputHash)+len(outputHash)+len(circuitHash))
	data = append(data, []byte("EZKL_PROOF_V1:")...)
	data = append(data, modelHash...)
	data = append(data, inputHash...)
	data = append(data, outputHash...)
	if circuitHash != nil {
		data = append(data, circuitHash...)
	}
	return sha256Hash(data)
}

// VerifyVoteExtension validates a vote extension from another validator.
// In production mode (AllowSimulated=false), this applies strict validation
// that rejects simulated TEE platforms and enforces signature presence.
func (ch *ConsensusHandler) VerifyVoteExtension(ctx sdk.Context, extensionBytes []byte) error {
	var extension VoteExtensionWire
	if err := json.Unmarshal(extensionBytes, &extension); err != nil {
		return fmt.Errorf("failed to unmarshal vote extension: %w", err)
	}

	// Check version
	if extension.Version != 1 {
		return fmt.Errorf("unsupported vote extension version: %d", extension.Version)
	}

	// Check height matches
	if extension.Height != ctx.BlockHeight() {
		return fmt.Errorf("vote extension height mismatch: expected %d, got %d", ctx.BlockHeight(), extension.Height)
	}
	if extension.ChainID == "" || extension.ChainID != ctx.ChainID() {
		return fmt.Errorf("vote extension chain ID mismatch: expected %q, got %q", ctx.ChainID(), extension.ChainID)
	}

	// SECURITY FIX (P1): Use deterministic block time instead of time.Now()
	// This ensures all validators make the same acceptance decision.
	// We allow a 1-minute window after block time to account for propagation delays.
	blockTime := ctx.BlockTime()
	if extension.Timestamp.After(blockTime.Add(time.Minute)) {
		return fmt.Errorf("vote extension timestamp is in the future (extension: %v, block: %v)",
			extension.Timestamp.Format(time.RFC3339), blockTime.Format(time.RFC3339))
	}

	// Determine if we're in production mode.
	// If the keeper is nil (e.g. in tests), default to production mode (fail-closed).
	isProduction := ch.productionVerificationMode(ctx)

	// ── Production guard: require signature ──
	if isProduction && isNullOrEmpty(extension.Signature) {
		return fmt.Errorf("SECURITY: unsigned vote extension rejected in production mode")
	}

	// ── Production guard: require extension hash ──
	if isProduction && isNullOrEmpty(extension.ExtensionHash) {
		return fmt.Errorf("SECURITY: missing extension hash in production mode")
	}

	seenJobs := make(map[string]struct{}, len(extension.Verifications))

	// Validate each verification
	for i, v := range extension.Verifications {
		if _, duplicate := seenJobs[v.JobID]; duplicate {
			return fmt.Errorf("duplicate job ID %q in vote extension", v.JobID)
		}
		seenJobs[v.JobID] = struct{}{}

		if err := ch.validateVerificationWireWithCtx(&ctx, &v); err != nil {
			return fmt.Errorf("invalid verification at index %d: %w", i, err)
		}
		teeEvidence, _, err := ch.parseVerificationEvidence(&v)
		if err != nil {
			return fmt.Errorf("invalid verification evidence at index %d: %w", i, err)
		}
		if teeEvidence != nil {
			if err := validateTEEAttestationDomain(
				teeEvidence,
				v.OutputHash,
				extension.Height,
				extension.ChainID,
			); err != nil {
				return fmt.Errorf("verification %d TEE domain rejected: %w", i, err)
			}
		}

		// Production: reject simulated TEE at the keeper level too
		if isProduction && v.AttestationType == "tee" {
			if err := ch.validateTEEAttestationWireStrict(ctx, &v); err != nil {
				return fmt.Errorf("verification %d TEE rejected in production: %w", i, err)
			}
		}
		if isProduction && v.AttestationType == "hybrid" {
			if err := ch.validateTEEAttestationWireStrict(ctx, &v); err != nil {
				return fmt.Errorf("verification %d hybrid TEE rejected in production: %w", i, err)
			}
		}

		// Verify the job exists on-chain (prevent phantom job votes)
		if v.Success && ch.keeper != nil {
			job, err := ch.keeper.GetJob(ctx, v.JobID)
			if err != nil {
				return fmt.Errorf("verification %d references unknown job %s", i, v.JobID)
			}
			if !bytes.Equal(v.ModelHash, job.ModelHash) {
				return fmt.Errorf("verification %d model hash does not match job %s", i, v.JobID)
			}
			if !bytes.Equal(v.InputHash, job.InputHash) {
				return fmt.Errorf("verification %d input hash does not match job %s", i, v.JobID)
			}
		}
	}

	return nil
}

// TEEAttestationWire is the wire format for TEE attestation data inside a verification.
type TEEAttestationWire struct {
	Platform         string    `json:"platform"`
	EnclaveID        string    `json:"enclave_id"`
	Measurement      []byte    `json:"measurement"`
	Quote            []byte    `json:"quote"`
	UserData         []byte    `json:"user_data"`
	CertificateChain [][]byte  `json:"certificate_chain,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	Nonce            []byte    `json:"nonce"`
	Signature        []byte    `json:"signature,omitempty"`
	BlockHeight      int64     `json:"block_height,omitempty"`
	ChainID          string    `json:"chain_id,omitempty"`
}

// ZKProofWire is the wire format for ZK proof data inside a verification.
type ZKProofWire struct {
	ProofSystem      string `json:"proof_system"`
	Proof            []byte `json:"proof"`
	PublicInputs     []byte `json:"public_inputs"`
	VerifyingKeyHash []byte `json:"verifying_key_hash"`
	CircuitHash      []byte `json:"circuit_hash"`
	ProofSize        int64  `json:"proof_size"`
}

// validateVerificationWire validates a single verification result from wire format.
// This now goes beyond presence checks and validates the structural integrity
// of attestations and proofs before they are counted toward consensus.
func (ch *ConsensusHandler) validateVerificationWire(v *VerificationWire) error {
	return ch.validateVerificationWireWithCtx(nil, v)
}

// validateVerificationWireWithCtx validates a single verification result from wire format.
// When ctxPtr is provided, deterministic block-time checks are enforced.
func (ch *ConsensusHandler) validateVerificationWireWithCtx(ctxPtr *sdk.Context, v *VerificationWire) error {
	if len(v.JobID) == 0 {
		return fmt.Errorf("missing job ID")
	}

	// Verify the job exists on-chain (prevent phantom job votes)
	// NOTE: ctx is not available here; this check is deferred to VerifyVoteExtension caller.

	if v.Success {
		if len(v.OutputHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte output hash")
		}

		// Model hash and input hash must be present for successful verifications
		if len(v.ModelHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte model hash")
		}
		if len(v.InputHash) != 32 {
			return fmt.Errorf("successful verification must have 32-byte input hash")
		}

		// Nonce is required for replay protection
		if len(v.Nonce) == 0 {
			return fmt.Errorf("missing nonce for replay protection")
		}
		if len(v.Nonce) != 32 {
			return fmt.Errorf("nonce must be 32 bytes, got %d", len(v.Nonce))
		}

		// Execution time must be positive
		if v.ExecutionTimeMs <= 0 {
			return fmt.Errorf("execution time must be positive for successful verification")
		}

		// Validate attestation based on type - parse and structurally verify
		switch v.AttestationType {
		case "tee":
			if err := ch.validateTEEAttestationWireWithCtx(ctxPtr, v); err != nil {
				return fmt.Errorf("TEE attestation invalid: %w", err)
			}
		case "zkml":
			if err := ch.validateZKProofWire(v); err != nil {
				return fmt.Errorf("zkML proof invalid: %w", err)
			}
		case "hybrid":
			if err := ch.validateTEEAttestationWireWithCtx(ctxPtr, v); err != nil {
				return fmt.Errorf("hybrid TEE part invalid: %w", err)
			}
			if err := ch.validateZKProofWire(v); err != nil {
				return fmt.Errorf("hybrid zkML part invalid: %w", err)
			}
		default:
			return fmt.Errorf("unknown attestation type: %s", v.AttestationType)
		}
	}

	return nil
}

// validateTEEAttestationWire parses and validates the TEE attestation payload.
func (ch *ConsensusHandler) validateTEEAttestationWire(v *VerificationWire) error {
	return ch.validateTEEAttestationWireWithCtx(nil, v)
}

// validateTEEAttestationWireStrict parses and validates the TEE attestation
// using production-mode rules (rejects simulated platform when AllowSimulated=false).
func (ch *ConsensusHandler) validateTEEAttestationWireStrict(ctx sdk.Context, v *VerificationWire) error {
	return ch.validateTEEAttestationWireWithCtx(&ctx, v)
}

// validateTEEAttestationWireWithCtx is the internal implementation.
// When ctxPtr is non-nil, production-mode checks apply (reject simulated TEE).
func (ch *ConsensusHandler) validateTEEAttestationWireWithCtx(ctxPtr *sdk.Context, v *VerificationWire) error {
	if len(v.TEEAttestation) == 0 {
		return fmt.Errorf("missing TEE attestation data")
	}

	var attestation TEEAttestationWire
	if err := json.Unmarshal(v.TEEAttestation, &attestation); err != nil {
		return fmt.Errorf("failed to parse TEE attestation: %w", err)
	}

	// Validate platform
	if !isSupportedTEEPlatform(attestation.Platform) {
		return fmt.Errorf("unknown TEE platform: %s", attestation.Platform)
	}

	// ── Production guard: reject simulated TEE platform ──
	if ctxPtr != nil && isSimulatedTEEPlatform(attestation.Platform) {
		// Default: reject (fail-closed)
		allowSimulated := ch.simulatedVerificationEnabled(*ctxPtr)
		if !allowSimulated {
			return fmt.Errorf("SECURITY: simulated TEE platform rejected in production mode")
		}
	}

	// Measurement must match the model (checked at a higher level,
	// but must at least be present and non-empty)
	if len(attestation.Measurement) == 0 {
		return fmt.Errorf("missing enclave measurement")
	}

	// Enforce global trusted-measurement registry membership for supported
	// hardware attestation formats.
	if ctxPtr != nil && ch.keeper != nil {
		var (
			isRegistered   bool
			measurementHex string
			err            error
		)
		switch attestation.Platform {
		case "aws-nitro":
			isRegistered, measurementHex, err = ch.keeper.IsRegisteredMeasurement(
				*ctxPtr,
				"aws-nitro",
				attestation.Measurement,
			)
		case "intel-sgx":
			isRegistered, measurementHex, err = ch.keeper.IsRegisteredMeasurement(
				*ctxPtr,
				"intel-sgx",
				attestation.Measurement,
			)
		}
		if err != nil {
			return fmt.Errorf("failed TEE measurement registry lookup: %w", err)
		}
		if (attestation.Platform == "aws-nitro" || attestation.Platform == "intel-sgx") && !isRegistered {
			return fmt.Errorf("unregistered %s measurement: %s", attestation.Platform, measurementHex)
		}
	}

	// Quote must be present and meet minimum size
	if len(attestation.Quote) < 64 {
		return fmt.Errorf("attestation quote too short: %d bytes (minimum 64)", len(attestation.Quote))
	}

	// UserData should bind the attestation to the output
	if len(attestation.UserData) == 0 {
		return fmt.Errorf("TEE attestation missing user data binding")
	}

	if attestation.BlockHeight > 0 || attestation.ChainID != "" {
		if attestation.BlockHeight <= 0 || attestation.ChainID == "" {
			return fmt.Errorf("TEE attestation domain binding is incomplete")
		}
		expected := verifytee.ComputeAttestationUserData(
			v.OutputHash,
			attestation.BlockHeight,
			attestation.ChainID,
		)
		if !bytes.Equal(attestation.UserData, expected) {
			return fmt.Errorf("TEE attestation domain-bound user data does not match output hash")
		}
	} else if !bytes.Equal(attestation.UserData, v.OutputHash) {
		return fmt.Errorf("legacy TEE attestation user data does not match output hash")
	}

	// Nonce must be present for freshness
	if len(attestation.Nonce) == 0 {
		return fmt.Errorf("TEE attestation missing nonce")
	}

	// The quote timestamp must be present. Freshness is not compared to the
	// current proposal time here: this validator result belongs to the prior
	// vote height, and a long inter-block gap must not make an authenticated
	// quorum certificate unprocessable. Height/chain/output bindings prevent
	// replay; platform-specific quote-age policy belongs at attestation
	// verification time.
	if attestation.Timestamp.IsZero() {
		return fmt.Errorf("TEE attestation missing timestamp")
	}

	return nil
}

func validateTEEAttestationDomain(
	attestation *TEEAttestationWire,
	outputHash []byte,
	expectedHeight int64,
	expectedChainID string,
) error {
	if attestation == nil {
		return nil
	}
	if expectedHeight <= 0 || expectedChainID == "" {
		return fmt.Errorf("missing expected TEE consensus domain")
	}
	if attestation.BlockHeight != expectedHeight {
		return fmt.Errorf(
			"TEE block height mismatch: got %d, expected %d",
			attestation.BlockHeight,
			expectedHeight,
		)
	}
	if attestation.ChainID != expectedChainID {
		return fmt.Errorf(
			"TEE chain ID mismatch: got %q, expected %q",
			attestation.ChainID,
			expectedChainID,
		)
	}
	expected := verifytee.ComputeAttestationUserData(outputHash, expectedHeight, expectedChainID)
	if !bytes.Equal(attestation.UserData, expected) {
		return fmt.Errorf("TEE user data does not match the expected consensus domain")
	}
	return nil
}

// validateZKProofWire parses and validates the ZK proof payload.
func (ch *ConsensusHandler) validateZKProofWire(v *VerificationWire) error {
	if len(v.ZKProof) == 0 {
		return fmt.Errorf("missing zkML proof data")
	}

	var proof ZKProofWire
	if err := json.Unmarshal(v.ZKProof, &proof); err != nil {
		return fmt.Errorf("failed to parse zkML proof: %w", err)
	}

	// Validate proof system
	validSystems := map[string]bool{
		"ezkl": true, "risc0": true, "plonky2": true, "halo2": true,
	}
	if !validSystems[proof.ProofSystem] {
		return fmt.Errorf("unknown proof system: %s", proof.ProofSystem)
	}

	// Proof must meet minimum size
	if len(proof.Proof) < 128 {
		return fmt.Errorf("proof data too short: %d bytes (minimum 128)", len(proof.Proof))
	}

	// Verifying key hash must be present
	if len(proof.VerifyingKeyHash) != 32 {
		return fmt.Errorf("verifying key hash must be 32 bytes")
	}

	// Public inputs must be present (contains model_hash, input_hash, output binding)
	if len(proof.PublicInputs) == 0 {
		return fmt.Errorf("missing public inputs in zkML proof")
	}

	return nil
}

func (ch *ConsensusHandler) resolveValidatorIdentity(
	ctx sdk.Context,
	vote abci.ExtendedVoteInfo,
	extension *VoteExtensionWire,
) (string, []byte, error) {
	if extension == nil {
		return "", nil, fmt.Errorf("vote extension is nil")
	}

	var extensionAddr []byte
	if err := json.Unmarshal(extension.ValidatorAddress, &extensionAddr); err != nil || len(extensionAddr) == 0 {
		// Legacy unit-test fixtures used a plain string without a consensus
		// address. Never permit that representation for a real commit vote.
		if len(vote.Validator.Address) > 0 {
			return "", nil, fmt.Errorf("invalid consensus address in vote extension")
		}
		var legacyAddr string
		if legacyErr := json.Unmarshal(extension.ValidatorAddress, &legacyAddr); legacyErr != nil || legacyAddr == "" {
			return "", nil, fmt.Errorf("invalid validator address in vote extension")
		}
		return legacyAddr, nil, nil
	}

	if len(vote.Validator.Address) == 0 {
		return sdk.ConsAddress(extensionAddr).String(), extensionAddr, nil
	}
	if !bytes.Equal(extensionAddr, vote.Validator.Address) {
		return "", nil, fmt.Errorf("vote extension validator address does not match commit validator")
	}

	// Persist the account address used by scheduler assignments and economics,
	// while retaining the consensus address separately for quorum identity.
	if ch.keeper != nil && ch.keeper.stakingKeeper != nil {
		stakingKeeper, ok := ch.keeper.stakingKeeper.(StakingKeeperFull)
		if !ok {
			return "", nil, fmt.Errorf("staking keeper cannot resolve consensus validators")
		}
		validator, err := stakingKeeper.GetValidatorByConsAddr(ctx, sdk.ConsAddress(extensionAddr))
		if err != nil {
			return "", nil, fmt.Errorf("consensus validator is not present in staking state: %w", err)
		}
		operatorAddr, err := sdk.ValAddressFromBech32(validator.GetOperator())
		if err != nil {
			return "", nil, fmt.Errorf("decode validator operator address: %w", err)
		}
		return sdk.AccAddress(operatorAddr).String(), extensionAddr, nil
	}

	return sdk.ConsAddress(extensionAddr).String(), extensionAddr, nil
}

func (ch *ConsensusHandler) parseVerificationEvidence(
	v *VerificationWire,
) (*TEEAttestationWire, *ZKProofWire, error) {
	var teeEvidence *TEEAttestationWire
	var zkEvidence *ZKProofWire

	if v.AttestationType == "tee" || v.AttestationType == "hybrid" {
		var tee TEEAttestationWire
		if err := json.Unmarshal(v.TEEAttestation, &tee); err != nil {
			return nil, nil, fmt.Errorf("decode TEE evidence: %w", err)
		}
		teeEvidence = &tee
	}
	if v.AttestationType == "zkml" || v.AttestationType == "hybrid" {
		var proof ZKProofWire
		if err := json.Unmarshal(v.ZKProof, &proof); err != nil {
			return nil, nil, fmt.Errorf("decode zkML evidence: %w", err)
		}
		zkEvidence = &proof
	}

	return teeEvidence, zkEvidence, nil
}

// AggregateVoteExtensions combines vote extensions from all validators
// and determines consensus on computation results
func (ch *ConsensusHandler) AggregateVoteExtensions(ctx sdk.Context, votes []abci.ExtendedVoteInfo) map[string]*AggregatedResult {
	start := time.Now()
	aggregated := make(map[string]*AggregatedResult)
	outputVotes := make(map[string]map[string][]ValidatorResult) // jobID -> outputHashHex -> results
	outputPower := make(map[string]map[string]int64)             // jobID -> outputHashHex -> power

	totalVotes := len(votes)
	totalPower := int64(0)
	seenCommitValidators := make(map[string]struct{}, len(votes))
	for _, vote := range votes {
		if vote.Validator.Power < 0 {
			ch.logger.Error("SECURITY: negative validator voting power in extended commit")
			return aggregated
		}
		if len(vote.Validator.Address) > 0 {
			key := hex.EncodeToString(vote.Validator.Address)
			if _, duplicate := seenCommitValidators[key]; duplicate {
				ch.logger.Error("SECURITY: duplicate validator in extended commit", "validator", key)
				return aggregated
			}
			seenCommitValidators[key] = struct{}{}
		}
		if totalPower > math.MaxInt64-vote.Validator.Power {
			ch.logger.Error("SECURITY: total voting power overflow")
			return aggregated
		}
		totalPower += vote.Validator.Power
	}

	// SECURITY FIX (P2): Only allow voting power fallback in simulated/test mode.
	// In production (AllowSimulated=false), zero voting power indicates misconfiguration
	// and should fail closed rather than silently proceeding with equal-weight votes.
	useFallbackPower := false
	if totalPower == 0 && totalVotes > 0 {
		// Check if we're in production mode
		allowSimulated := ch.simulatedVerificationEnabled(ctx)

		if allowSimulated {
			// Dev/test mode: allow fallback to 1 power per vote
			totalPower = int64(totalVotes)
			useFallbackPower = true
			ch.logger.Warn("Total voting power is zero; falling back to 1 power per vote (allowed in simulated mode)",
				"total_votes", totalVotes,
			)
		} else {
			// Production mode: fail closed - this is a configuration error
			ch.logger.Error("SECURITY: Total voting power is zero in production mode - this indicates misconfiguration",
				"total_votes", totalVotes,
			)
			// Return empty results - no consensus possible with zero power
			return aggregated
		}
	}

	// Get consensus threshold from on-chain params (BFT-safe, minimum 67%)
	consensusThreshold := ch.getConsensusThreshold(ctx)
	requiredPower := requiredThresholdCount(totalPower, consensusThreshold)

	for _, vote := range votes {
		if vote.BlockIdFlag != cmtproto.BlockIDFlagCommit {
			continue
		}
		if len(vote.VoteExtension) == 0 {
			continue
		}

		votePower := vote.Validator.Power
		if useFallbackPower {
			votePower = 1
		}

		// Parse vote extension from wire format
		var extension VoteExtensionWire
		if err := json.Unmarshal(vote.VoteExtension, &extension); err != nil {
			ch.logger.Warn("Failed to unmarshal vote extension", "error", err)
			continue
		}
		if ch.keeper != nil {
			expectedHeight := ctx.BlockHeight() - 1
			if extension.Height != expectedHeight || extension.ChainID != ctx.ChainID() {
				ch.logger.Warn("Skipping vote extension from the wrong consensus domain",
					"extension_height", extension.Height,
					"expected_height", expectedHeight,
					"extension_chain_id", extension.ChainID,
					"expected_chain_id", ctx.ChainID(),
				)
				continue
			}
		}

		// ── Mandatory Signing Enforcement ──
		// In production mode, reject vote extensions without a signature.
		// Unsigned extensions could be spoofed by a network-level adversary.
		if ch.productionVerificationMode(ctx) {
			if len(extension.Signature) == 0 || string(extension.Signature) == "null" {
				ch.logger.Warn("SECURITY: Rejecting unsigned vote extension in production mode")
				continue
			}
			if len(extension.ExtensionHash) == 0 || string(extension.ExtensionHash) == "null" {
				ch.logger.Warn("SECURITY: Rejecting vote extension without hash in production mode")
				continue
			}
		}

		validatorAddr, validatorConsAddr, err := ch.resolveValidatorIdentity(ctx, vote, &extension)
		if err != nil {
			ch.logger.Warn("Invalid validator identity in vote extension", "error", err)
			continue
		}

		// Process each verification. Each successful result carries its own
		// compact validator signature; the ABCI verifier authenticates it before
		// this pure aggregation step.
		seenJobs := make(map[string]struct{}, len(extension.Verifications))
		for _, v := range extension.Verifications {
			if _, duplicate := seenJobs[v.JobID]; duplicate {
				ch.logger.Warn("Skipping duplicate job in validator vote extension",
					"job_id", v.JobID,
					"validator", validatorAddr,
				)
				continue
			}
			seenJobs[v.JobID] = struct{}{}

			if !v.Success {
				continue
			}

			var canonicalModelHash = v.ModelHash
			var canonicalInputHash = v.InputHash
			if ch.keeper != nil {
				if err := ch.validateVerificationWireWithCtx(&ctx, &v); err != nil {
					ch.logger.Warn("Skipping invalid consensus verification",
						"job_id", v.JobID,
						"validator", validatorAddr,
						"error", err,
					)
					continue
				}
				job, err := ch.keeper.GetJob(ctx, v.JobID)
				if err != nil ||
					!bytes.Equal(job.ModelHash, v.ModelHash) ||
					!bytes.Equal(job.InputHash, v.InputHash) {
					ch.logger.Warn("Skipping verification not bound to canonical job",
						"job_id", v.JobID,
						"validator", validatorAddr,
						"error", err,
					)
					continue
				}
				assigned, assignErr := IsValidatorAssigned(job, validatorAddr)
				if assignErr != nil || !assigned {
					ch.logger.Warn(
						"Skipping verification from unassigned validator",
						"job_id", v.JobID,
						"validator", validatorAddr,
						"error", assignErr,
					)
					continue
				}
				canonicalModelHash = job.ModelHash
				canonicalInputHash = job.InputHash
			}

			teeEvidence, zkEvidence, evidenceErr := ch.parseVerificationEvidence(&v)
			if evidenceErr != nil && ch.keeper != nil {
				ch.logger.Warn("Skipping verification with malformed evidence",
					"job_id", v.JobID,
					"validator", validatorAddr,
					"error", evidenceErr,
				)
				continue
			}
			if ch.keeper != nil && teeEvidence != nil {
				if err := validateTEEAttestationDomain(
					teeEvidence,
					v.OutputHash,
					extension.Height,
					extension.ChainID,
				); err != nil {
					ch.logger.Warn("Skipping TEE evidence from the wrong consensus domain",
						"job_id", v.JobID,
						"validator", validatorAddr,
						"error", err,
					)
					continue
				}
			}

			if ch.keeper != nil && teeEvidence != nil {
				if teeEvidence.Platform == "aws-nitro" || teeEvidence.Platform == "intel-sgx" {
					if err := ch.keeper.ValidateTEEAttestationMeasurement(
						ctx,
						validatorAddr,
						teeEvidence.Platform,
						teeEvidence.Measurement,
					); err != nil {
						ch.logger.Warn("Rejected verification due to untrusted TEE measurement",
							"job_id", v.JobID,
							"validator", validatorAddr,
							"platform", teeEvidence.Platform,
							"error", err,
						)
						continue
					}
				}
			}

			outputHashHex := hex.EncodeToString(v.OutputHash)

			// Initialize maps
			if outputVotes[v.JobID] == nil {
				outputVotes[v.JobID] = make(map[string][]ValidatorResult)
			}
			if outputPower[v.JobID] == nil {
				outputPower[v.JobID] = make(map[string]int64)
			}

			// Create validator result, including BLS signature if present
			valResult := ValidatorResult{
				ValidatorAddress:          validatorAddr,
				ValidatorConsensusAddress: validatorConsAddr,
				OutputHash:                append([]byte(nil), v.OutputHash...),
				AttestationType:           v.AttestationType,
				TEEAttestation:            teeEvidence,
				ZKProof:                   zkEvidence,
				Nonce:                     append([]byte(nil), v.Nonce...),
				ExecutionTimeMs:           v.ExecutionTimeMs,
				Timestamp:                 extension.Timestamp,
				ValidatorSignatureVersion: v.ValidatorSignatureVersion,
				VoteBlockHash:             append([]byte(nil), v.VoteBlockHash...),
				ExtensionNonce:            append([]byte(nil), v.ExtensionNonce...),
				ValidatorSignature:        append([]byte(nil), v.ValidatorSignature...),
				BLSSignature:              append([]byte(nil), extension.BLSSignature...),
				BLSPubKey:                 append([]byte(nil), extension.BLSPubKey...),
			}

			outputVotes[v.JobID][outputHashHex] = append(outputVotes[v.JobID][outputHashHex], valResult)
			outputPower[v.JobID][outputHashHex] += votePower

			// Initialize aggregated result
			if aggregated[v.JobID] == nil {
				aggregated[v.JobID] = &AggregatedResult{
					JobID:            v.JobID,
					ModelHash:        append([]byte(nil), canonicalModelHash...),
					InputHash:        append([]byte(nil), canonicalInputHash...),
					TotalVotes:       totalVotes,
					TotalPower:       totalPower,
					ValidatorResults: make([]ValidatorResult, 0),
				}
			}
		}
	}

	// Determine consensus for each job
	hasConsensus := false
	jobIDs := make([]string, 0, len(outputVotes))
	for jobID := range outputVotes {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Strings(jobIDs)
	for _, jobID := range jobIDs {
		outputs := outputVotes[jobID]
		agg := aggregated[jobID]

		outputHashes := make([]string, 0, len(outputs))
		for outputHashHex := range outputs {
			outputHashes = append(outputHashes, outputHashHex)
		}
		sort.Strings(outputHashes)
		for _, outputHashHex := range outputHashes {
			results := outputs[outputHashHex]
			agreementPower := outputPower[jobID][outputHashHex]
			if agreementPower >= requiredPower {
				outputHash, err := hex.DecodeString(outputHashHex)
				if err != nil {
					ch.logger.Error("Failed to decode output hash - skipping",
						"job_id", jobID,
						"output_hash_hex", outputHashHex,
						"error", err,
					)
					continue
				}
				agg.OutputHash = outputHash
				agg.ValidatorResults = results
				agg.AgreementCount = len(results)
				agg.AgreementPower = agreementPower
				agg.HasConsensus = true
				hasConsensus = true

				ch.logger.Info("Consensus reached for job",
					"job_id", jobID,
					"validators_agreed", len(results),
					"agreement_power", agreementPower,
					"total_votes", totalVotes,
					"total_power", totalPower,
					"output_hash", outputHashHex[:16],
				)
				break
			}
		}
	}

	if ch.keeper != nil && ch.keeper.metrics != nil {
		ch.keeper.metrics.RecordConsensus(time.Since(start), hasConsensus)
	}

	// Aggregation is intentionally pure. PrepareProposal and ProcessProposal
	// may run repeatedly, on rejected candidates, and after cache loss; they
	// must never mutate keeper state, audit chains, schedulers, or slashing
	// trackers. Deterministic state transitions occur only in FinalizeBlock.

	return aggregated
}

// aggregateBLSSignatures collects BLS signatures from validator results and
// produces a single aggregate signature for compact on-chain storage.
func (ch *ConsensusHandler) aggregateBLSSignatures(ctx sdk.Context, jobID string, agg *AggregatedResult) {
	var (
		sigs    []*bls.Signature
		pubKeys [][]byte
	)

	// Collect all valid BLS signatures from agreeing validators
	for _, result := range agg.ValidatorResults {
		if len(result.BLSSignature) == 0 || len(result.BLSPubKey) == 0 {
			continue
		}

		sig, err := bls.SignatureFromBytes(result.BLSSignature)
		if err != nil {
			ch.logger.Debug("Skipping invalid BLS signature",
				"validator", result.ValidatorAddress,
				"job_id", jobID,
				"error", err,
			)
			continue
		}

		// Verify individual signature before including in aggregate
		pk, err := bls.PublicKeyFromBytes(result.BLSPubKey)
		if err != nil {
			ch.logger.Debug("Skipping invalid BLS public key",
				"validator", result.ValidatorAddress,
				"job_id", jobID,
				"error", err,
			)
			continue
		}

		// The signed message is the output hash (the value validators agreed on)
		valid, err := bls.Verify(pk, agg.OutputHash, sig)
		if err != nil || !valid {
			ch.logger.Warn("BLS signature verification failed for validator",
				"validator", result.ValidatorAddress,
				"job_id", jobID,
			)
			continue
		}

		sigs = append(sigs, sig)
		pubKeys = append(pubKeys, result.BLSPubKey)
	}

	if len(sigs) < 2 {
		// Need at least 2 signatures to make aggregation worthwhile
		return
	}

	// Aggregate all valid signatures into one
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		ch.logger.Error("BLS signature aggregation failed",
			"job_id", jobID,
			"signer_count", len(sigs),
			"error", err,
		)
		return
	}

	agg.BLSAggregateSignature = aggSig.Bytes()
	agg.BLSSignerPubKeys = pubKeys

	ch.logger.Info("BLS signatures aggregated",
		"job_id", jobID,
		"signers", len(sigs),
		"aggregate_size", len(agg.BLSAggregateSignature),
		"replaced_size", len(sigs)*bls.SignatureSize,
	)
}

const verificationEvidenceVersion = 2

// VerificationEvidenceEnvelope preserves both halves of hybrid verification
// evidence while using the existing VerificationResult attestation_data field.
type VerificationEvidenceEnvelope struct {
	Version        int                 `json:"version"`
	TEEAttestation *TEEAttestationWire `json:"tee_attestation,omitempty"`
	ZKProof        *ZKProofWire        `json:"zk_proof,omitempty"`
}

func encodeVerificationEvidence(result ValidatorResult) ([]byte, error) {
	return json.Marshal(VerificationEvidenceEnvelope{
		Version:        verificationEvidenceVersion,
		TEEAttestation: result.TEEAttestation,
		ZKProof:        result.ZKProof,
	})
}

func decodeVerificationEvidence(data []byte) (*VerificationEvidenceEnvelope, error) {
	var evidence VerificationEvidenceEnvelope
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, fmt.Errorf("decode verification evidence: %w", err)
	}
	if evidence.Version != verificationEvidenceVersion {
		return nil, fmt.Errorf("unsupported verification evidence version: %d", evidence.Version)
	}
	return &evidence, nil
}

// SealCreationTx represents a transaction to create a Digital Seal
type SealCreationTx struct {
	Type             string            `json:"type"`
	JobID            string            `json:"job_id"`
	ModelHash        []byte            `json:"model_hash"`
	InputHash        []byte            `json:"input_hash"`
	OutputHash       []byte            `json:"output_hash"`
	ValidatorCount   int               `json:"validator_count"`
	TotalVotes       int               `json:"total_votes"`
	AgreementPower   int64             `json:"agreement_power"`
	TotalPower       int64             `json:"total_power"`
	ValidatorResults []ValidatorResult `json:"validator_results"`
	BlockHeight      int64             `json:"block_height"`
	Timestamp        time.Time         `json:"timestamp"`
}

// CreateSealTransactions creates transactions for jobs that reached consensus
func (ch *ConsensusHandler) CreateSealTransactions(ctx sdk.Context, results map[string]*AggregatedResult) [][]byte {
	var txs [][]byte

	jobIDs := make([]string, 0, len(results))
	for jobID := range results {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Strings(jobIDs)

	for _, jobID := range jobIDs {
		result := results[jobID]
		if result == nil || !result.HasConsensus {
			continue
		}
		validatorResults := append([]ValidatorResult(nil), result.ValidatorResults...)
		sort.Slice(validatorResults, func(i, j int) bool {
			return bytes.Compare(
				validatorResults[i].ValidatorConsensusAddress,
				validatorResults[j].ValidatorConsensusAddress,
			) < 0
		})

		// SECURITY FIX: Use deterministic block time instead of time.Now()
		// This ensures all validators create identical seal transactions.
		sealTx := SealCreationTx{
			Type:             "create_seal_from_consensus",
			JobID:            result.JobID,
			ModelHash:        result.ModelHash,
			InputHash:        result.InputHash,
			OutputHash:       result.OutputHash,
			ValidatorCount:   len(validatorResults),
			TotalVotes:       result.TotalVotes,
			AgreementPower:   result.AgreementPower,
			TotalPower:       result.TotalPower,
			ValidatorResults: validatorResults,
			BlockHeight:      ctx.BlockHeight(),
			Timestamp:        ctx.BlockTime().UTC(),
		}

		txBytes, err := json.Marshal(sealTx)
		if err != nil {
			ch.logger.Error("Failed to marshal seal transaction", "error", err)
			continue
		}

		txs = append(txs, txBytes)

		ch.logger.Info("Seal transaction created",
			"job_id", result.JobID,
			"validator_count", result.AgreementCount,
		)
	}

	return txs
}

// ValidateSealTransaction validates a seal creation transaction
func (ch *ConsensusHandler) ValidateSealTransaction(ctx sdk.Context, txBytes []byte) error {
	var sealTx SealCreationTx
	if err := json.Unmarshal(txBytes, &sealTx); err != nil {
		return fmt.Errorf("failed to unmarshal seal transaction: %w", err)
	}

	if sealTx.Type != "create_seal_from_consensus" {
		return fmt.Errorf("invalid seal transaction type: %s", sealTx.Type)
	}

	if len(sealTx.JobID) == 0 {
		return fmt.Errorf("missing job ID")
	}

	if len(sealTx.OutputHash) != 32 {
		return fmt.Errorf("invalid output hash length")
	}
	if len(sealTx.ModelHash) != 32 {
		return fmt.Errorf("invalid model hash length")
	}
	if len(sealTx.InputHash) != 32 {
		return fmt.Errorf("invalid input hash length")
	}
	if sealTx.BlockHeight != ctx.BlockHeight() {
		return fmt.Errorf("seal transaction height mismatch: got %d, expected %d", sealTx.BlockHeight, ctx.BlockHeight())
	}
	if sealTx.Timestamp.IsZero() || !sealTx.Timestamp.Equal(ctx.BlockTime().UTC()) {
		return fmt.Errorf("seal transaction timestamp does not match block time")
	}
	if ch.keeper == nil {
		return fmt.Errorf("pouw keeper is not configured")
	}

	// Validate job exists
	job, err := ch.keeper.GetJob(ctx, sealTx.JobID)
	if err != nil {
		return fmt.Errorf("job not found: %s", sealTx.JobID)
	}

	// Validate model and input hashes match
	if !bytes.Equal(job.ModelHash, sealTx.ModelHash) {
		return fmt.Errorf("model hash mismatch")
	}

	if !bytes.Equal(job.InputHash, sealTx.InputHash) {
		return fmt.Errorf("input hash mismatch")
	}
	if job.Status != types.JobStatusProcessing {
		return fmt.Errorf("job %s is not processing", sealTx.JobID)
	}

	if sealTx.ValidatorCount <= 0 || sealTx.TotalVotes <= 0 {
		return fmt.Errorf("validator counts must be positive")
	}
	if sealTx.ValidatorCount > sealTx.TotalVotes {
		return fmt.Errorf("validator count exceeds total votes")
	}
	if sealTx.ValidatorCount != len(sealTx.ValidatorResults) {
		return fmt.Errorf("validator count does not match validator results")
	}
	if sealTx.TotalPower <= 0 {
		return fmt.Errorf("total voting power must be positive")
	}
	if sealTx.AgreementPower <= 0 || sealTx.AgreementPower > sealTx.TotalPower {
		return fmt.Errorf("invalid agreement voting power")
	}

	expectedType := ""
	switch job.ProofType {
	case types.ProofTypeTEE:
		expectedType = "tee"
	case types.ProofTypeZKML:
		expectedType = "zkml"
	case types.ProofTypeHybrid:
		expectedType = "hybrid"
	default:
		return fmt.Errorf("unsupported job proof type: %s", job.ProofType)
	}

	seenAccounts := make(map[string]struct{}, len(sealTx.ValidatorResults))
	seenConsensusAddresses := make(map[string]struct{}, len(sealTx.ValidatorResults))
	var previousConsensusAddress []byte
	var voteBlockHash []byte
	for i := range sealTx.ValidatorResults {
		result := &sealTx.ValidatorResults[i]
		if i > 0 && bytes.Compare(previousConsensusAddress, result.ValidatorConsensusAddress) >= 0 {
			return fmt.Errorf("validator results are not in canonical consensus-address order")
		}
		previousConsensusAddress = append(
			previousConsensusAddress[:0],
			result.ValidatorConsensusAddress...,
		)
		if result.ValidatorAddress == "" {
			return fmt.Errorf("validator result %d has empty validator address", i)
		}
		if _, duplicate := seenAccounts[result.ValidatorAddress]; duplicate {
			return fmt.Errorf("duplicate validator account in seal evidence: %s", result.ValidatorAddress)
		}
		seenAccounts[result.ValidatorAddress] = struct{}{}
		assigned, err := IsValidatorAssigned(job, result.ValidatorAddress)
		if err != nil {
			return fmt.Errorf("validate validator result %d assignment: %w", i, err)
		}
		if !assigned {
			return fmt.Errorf(
				"validator result %d account %s is not assigned to job %s",
				i,
				result.ValidatorAddress,
				sealTx.JobID,
			)
		}

		if len(result.ValidatorConsensusAddress) == 0 {
			return fmt.Errorf("validator result %d is missing consensus address", i)
		}
		if result.ValidatorSignatureVersion != compactValidatorSignatureVersion {
			return fmt.Errorf(
				"validator result %d has unsupported signature version %d",
				i,
				result.ValidatorSignatureVersion,
			)
		}
		if len(result.VoteBlockHash) != sha256.Size {
			return fmt.Errorf("validator result %d has invalid vote block hash length", i)
		}
		if i == 0 {
			voteBlockHash = append([]byte(nil), result.VoteBlockHash...)
		} else if !bytes.Equal(voteBlockHash, result.VoteBlockHash) {
			return fmt.Errorf("validator results attest different proposal block hashes")
		}
		if len(result.ExtensionNonce) != 32 {
			return fmt.Errorf("validator result %d has invalid extension nonce length", i)
		}
		if len(result.ValidatorSignature) != 64 {
			return fmt.Errorf("validator result %d has invalid compact signature length", i)
		}
		consensusKey := hex.EncodeToString(result.ValidatorConsensusAddress)
		if _, duplicate := seenConsensusAddresses[consensusKey]; duplicate {
			return fmt.Errorf("duplicate validator consensus address in seal evidence: %s", consensusKey)
		}
		seenConsensusAddresses[consensusKey] = struct{}{}

		if !bytes.Equal(result.OutputHash, sealTx.OutputHash) {
			return fmt.Errorf("validator result %d output hash mismatch", i)
		}
		if result.AttestationType != expectedType {
			return fmt.Errorf(
				"validator result %d attestation type %q does not match job type %q",
				i,
				result.AttestationType,
				expectedType,
			)
		}

		teeJSON, err := json.Marshal(result.TEEAttestation)
		if err != nil {
			return fmt.Errorf("marshal validator result %d TEE evidence: %w", i, err)
		}
		zkJSON, err := json.Marshal(result.ZKProof)
		if err != nil {
			return fmt.Errorf("marshal validator result %d zkML evidence: %w", i, err)
		}
		wire := VerificationWire{
			JobID:           sealTx.JobID,
			ModelHash:       sealTx.ModelHash,
			InputHash:       sealTx.InputHash,
			OutputHash:      result.OutputHash,
			AttestationType: result.AttestationType,
			TEEAttestation:  teeJSON,
			ZKProof:         zkJSON,
			ExecutionTimeMs: result.ExecutionTimeMs,
			Success:         true,
			Nonce:           result.Nonce,
		}
		if err := ch.validateVerificationWireWithCtx(&ctx, &wire); err != nil {
			return fmt.Errorf("validator result %d evidence is invalid: %w", i, err)
		}
		if result.TEEAttestation != nil {
			if err := validateTEEAttestationDomain(
				result.TEEAttestation,
				result.OutputHash,
				sealTx.BlockHeight-1,
				ctx.ChainID(),
			); err != nil {
				return fmt.Errorf("validator result %d TEE domain is invalid: %w", i, err)
			}
		}
	}

	// Validate consensus threshold was met.
	consensusThreshold := ch.getConsensusThreshold(ctx)
	requiredPower := requiredThresholdCount(sealTx.TotalPower, consensusThreshold)
	if sealTx.AgreementPower < requiredPower {
		return fmt.Errorf("insufficient validator power: got %d, need %d", sealTx.AgreementPower, requiredPower)
	}

	return nil
}

// ProcessSealTransaction processes a validated seal transaction
func (ch *ConsensusHandler) ProcessSealTransaction(ctx context.Context, txBytes []byte) error {
	var sealTx SealCreationTx
	if err := json.Unmarshal(txBytes, &sealTx); err != nil {
		return fmt.Errorf("failed to unmarshal seal transaction: %w", err)
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if err := ch.ValidateSealTransaction(sdkCtx, txBytes); err != nil {
		return fmt.Errorf("invalid seal transaction: %w", err)
	}

	// Convert validator results to verification results
	var verificationResults []types.VerificationResult
	for _, vr := range sealTx.ValidatorResults {
		evidence, err := encodeVerificationEvidence(vr)
		if err != nil {
			return fmt.Errorf("encode validator %s evidence: %w", vr.ValidatorAddress, err)
		}
		teePlatform := ""
		if vr.TEEAttestation != nil {
			teePlatform = vr.TEEAttestation.Platform
		}
		verificationResults = append(verificationResults, types.VerificationResult{
			ValidatorAddress: vr.ValidatorAddress,
			OutputHash:       vr.OutputHash,
			AttestationType:  vr.AttestationType,
			TeePlatform:      teePlatform,
			AttestationData:  evidence,
			Signature:        vr.ValidatorSignature,
			ExecutionTimeMs:  vr.ExecutionTimeMs,
			Timestamp:        timestamppb.New(vr.Timestamp),
			Success:          true,
		})
	}

	// Complete the job (this creates the Digital Seal)
	if err := ch.keeper.CompleteJob(ctx, sealTx.JobID, sealTx.OutputHash, verificationResults); err != nil {
		return fmt.Errorf("failed to complete job: %w", err)
	}

	ch.logger.Info("Seal transaction processed",
		"job_id", sealTx.JobID,
		"validator_count", sealTx.ValidatorCount,
	)

	return nil
}

// IsSealTransaction checks if a transaction is a seal creation transaction
func IsSealTransaction(txBytes []byte) bool {
	var data map[string]interface{}
	if err := json.Unmarshal(txBytes, &data); err != nil {
		return false
	}
	txType, ok := data["type"].(string)
	return ok && txType == "create_seal_from_consensus"
}

// sha256Hash computes SHA-256 hash
func sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// isNullOrEmpty checks if a json.RawMessage is null, empty, or represents
// an empty JSON string. json.RawMessage(nil) marshals to "null" (4 bytes),
// so checking len() == 0 alone is insufficient.
func isNullOrEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	// JSON null literal
	if string(raw) == "null" {
		return true
	}
	// Empty JSON string ""
	if string(raw) == `""` {
		return true
	}
	return false
}
