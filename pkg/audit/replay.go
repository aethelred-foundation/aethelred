package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Computation Replay Engine
// ---------------------------------------------------------------------------
//
// The replay engine re-executes a recorded computation using the original
// inputs and compares the output to the original result. This provides
// deterministic verification that a computation was performed correctly.
//
// Replay is central to the Aethelred auditability model:
//   - Regulators can re-run any computation months later
//   - Discrepancies produce cryptographic evidence of misbehavior
//   - Replay results are themselves audit records
//
// The engine is designed to be deterministic: given the same inputs, it
// must always produce the same comparison result.
// ---------------------------------------------------------------------------

// ReplayConfig controls the behavior of the replay engine.
type ReplayConfig struct {
	// VerifyInputs enables verification that the original inputs are
	// unchanged (hash comparison against recorded input hashes).
	VerifyInputs bool `json:"verify_inputs"`

	// VerifyOutputs enables comparison of replayed output against the
	// original recorded output.
	VerifyOutputs bool `json:"verify_outputs"`

	// CompareResults enables detailed diff generation when outputs differ.
	CompareResults bool `json:"compare_results"`

	// StrictMode treats any difference (including acceptable floating-point
	// variance) as a failure.
	StrictMode bool `json:"strict_mode"`

	// Tolerance is the maximum allowed difference for numeric comparisons
	// when StrictMode is false. Expressed as a fraction (e.g., 0.0001 for
	// 0.01% tolerance).
	Tolerance float64 `json:"tolerance"`
}

// ReplayEngine manages computation replay operations.
type ReplayEngine struct {
	config ReplayConfig
	source LogSource

	// JobResolver looks up the original job details (inputs, outputs,
	// model hash) from the audit log or on-chain state.
	jobResolver JobResolver
}

// JobResolver abstracts the lookup of original computation details for
// replay. Implementations may query on-chain state, IPFS, or local storage.
type JobResolver interface {
	// ResolveJob returns the original job details for the given job ID.
	ResolveJob(ctx context.Context, jobID string) (*JobDetails, error)

	// ExecuteComputation re-runs the computation with the given inputs.
	ExecuteComputation(ctx context.Context, details *JobDetails) (*ComputationOutput, error)
}

// JobDetails contains everything needed to replay a computation.
type JobDetails struct {
	JobID       string            `json:"job_id"`
	ModelHash   string            `json:"model_hash"`
	InputHash   string            `json:"input_hash"`
	InputData   []byte            `json:"input_data,omitempty"`
	OutputHash  string            `json:"output_hash"`
	OutputData  []byte            `json:"output_data,omitempty"`
	ProofType   string            `json:"proof_type"`
	Operator    string            `json:"operator"`
	BlockHeight int64             `json:"block_height"`
	Timestamp   string            `json:"timestamp"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ComputationOutput holds the result of a replayed computation.
type ComputationOutput struct {
	OutputHash string `json:"output_hash"`
	OutputData []byte `json:"output_data,omitempty"`
	Duration   time.Duration `json:"duration"`
	Success    bool   `json:"success"`
	Error      string `json:"error,omitempty"`
}

// ReplayResult captures the full outcome of a replay operation.
type ReplayResult struct {
	// JobID identifies the replayed computation.
	JobID string `json:"job_id"`

	// OriginalOutput is the hash of the original computation output.
	OriginalOutput string `json:"original_output"`

	// ReplayOutput is the hash of the replayed computation output.
	ReplayOutput string `json:"replay_output"`

	// Match is true if the original and replayed outputs are identical.
	Match bool `json:"match"`

	// Differences lists specific discrepancies when Match is false.
	Differences []Difference `json:"differences,omitempty"`

	// Duration is the wall-clock time of the replay.
	Duration time.Duration `json:"duration"`

	// Evidence contains cryptographic evidence generated from the replay.
	Evidence *ReplayEvidence `json:"evidence,omitempty"`

	// Timestamp records when the replay was performed.
	Timestamp string `json:"timestamp"`

	// InputVerified indicates whether the inputs were verified.
	InputVerified bool `json:"input_verified"`
}

// Difference describes a specific discrepancy between original and replayed
// outputs.
type Difference struct {
	// Field identifies the location of the difference.
	Field string `json:"field"`

	// OriginalValue is the original value (hex-encoded if binary).
	OriginalValue string `json:"original_value"`

	// ReplayValue is the replayed value (hex-encoded if binary).
	ReplayValue string `json:"replay_value"`

	// Description explains the nature of the difference.
	Description string `json:"description"`
}

// ReplayEvidence is a cryptographic proof of the replay result, suitable
// for inclusion in an evidence bundle.
type ReplayEvidence struct {
	// ReplayHash is the SHA-256 of the canonical replay result.
	ReplayHash string `json:"replay_hash"`

	// InputHash is the hash of the inputs used for replay.
	InputHash string `json:"input_hash"`

	// OriginalOutputHash is the hash of the original output.
	OriginalOutputHash string `json:"original_output_hash"`

	// ReplayOutputHash is the hash of the replayed output.
	ReplayOutputHash string `json:"replay_output_hash"`

	// Timestamp records when the evidence was generated.
	Timestamp string `json:"timestamp"`

	// Match records the comparison outcome.
	Match bool `json:"match"`
}

// NewReplayEngine creates a new replay engine with the given configuration.
func NewReplayEngine(cfg ReplayConfig, source LogSource, resolver JobResolver) *ReplayEngine {
	return &ReplayEngine{
		config:      cfg,
		source:      source,
		jobResolver: resolver,
	}
}

// ---------------------------------------------------------------------------
// Core replay operations
// ---------------------------------------------------------------------------

// Replay re-executes the computation for the given job ID and compares the
// result to the originally recorded output.
func (re *ReplayEngine) Replay(ctx context.Context, jobID string) (*ReplayResult, error) {
	if re.jobResolver == nil {
		return nil, fmt.Errorf("audit/replay: JobResolver is not configured")
	}

	// Resolve the original job details.
	details, err := re.jobResolver.ResolveJob(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("audit/replay: failed to resolve job %s: %w", jobID, err)
	}

	result := &ReplayResult{
		JobID:          jobID,
		OriginalOutput: details.OutputHash,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}

	// Optionally verify inputs.
	if re.config.VerifyInputs && len(details.InputData) > 0 {
		inputHash := hashBytes(details.InputData)
		if inputHash != details.InputHash {
			return nil, fmt.Errorf("audit/replay: input data integrity check failed for job %s: "+
				"expected %s, computed %s", jobID, details.InputHash, inputHash)
		}
		result.InputVerified = true
	}

	// Execute the replay.
	start := time.Now()
	output, err := re.jobResolver.ExecuteComputation(ctx, details)
	result.Duration = time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("audit/replay: computation failed for job %s: %w", jobID, err)
	}

	result.ReplayOutput = output.OutputHash

	// Compare results.
	result.Match = result.OriginalOutput == result.ReplayOutput

	if !result.Match && re.config.CompareResults {
		result.Differences = Compare(details.OutputData, output.OutputData)
	}

	// Generate evidence.
	result.Evidence = GenerateReplayEvidence(result)

	return result, nil
}

// Compare performs a deterministic comparison of two output byte slices and
// returns a list of differences. If the outputs are identical, the returned
// slice is empty.
func Compare(original, replayed []byte) []Difference {
	var diffs []Difference

	if bytes.Equal(original, replayed) {
		return diffs
	}

	// Report a high-level hash difference.
	diffs = append(diffs, Difference{
		Field:         "output_hash",
		OriginalValue: hashBytes(original),
		ReplayValue:   hashBytes(replayed),
		Description:   "output hashes differ",
	})

	// Report length difference.
	if len(original) != len(replayed) {
		diffs = append(diffs, Difference{
			Field:         "output_length",
			OriginalValue: fmt.Sprintf("%d", len(original)),
			ReplayValue:   fmt.Sprintf("%d", len(replayed)),
			Description:   "output lengths differ",
		})
	}

	// Find first divergence point.
	minLen := len(original)
	if len(replayed) < minLen {
		minLen = len(replayed)
	}
	for i := 0; i < minLen; i++ {
		if original[i] != replayed[i] {
			diffs = append(diffs, Difference{
				Field:         fmt.Sprintf("byte_offset_%d", i),
				OriginalValue: fmt.Sprintf("0x%02x", original[i]),
				ReplayValue:   fmt.Sprintf("0x%02x", replayed[i]),
				Description:   fmt.Sprintf("first byte difference at offset %d", i),
			})
			break
		}
	}

	return diffs
}

// GenerateReplayEvidence creates cryptographic evidence from a replay
// result. The evidence is suitable for inclusion in an evidence bundle.
func GenerateReplayEvidence(result *ReplayResult) *ReplayEvidence {
	if result == nil {
		return nil
	}

	// Build a canonical representation of the replay result for hashing.
	canonical := fmt.Sprintf(
		"job=%s|original=%s|replay=%s|match=%t|ts=%s",
		result.JobID, result.OriginalOutput, result.ReplayOutput,
		result.Match, result.Timestamp,
	)
	sum := sha256.Sum256([]byte(canonical))

	return &ReplayEvidence{
		ReplayHash:         hex.EncodeToString(sum[:]),
		InputHash:          "", // Set by caller if input verification was performed.
		OriginalOutputHash: result.OriginalOutput,
		ReplayOutputHash:   result.ReplayOutput,
		Timestamp:          result.Timestamp,
		Match:              result.Match,
	}
}

// ---------------------------------------------------------------------------
// Replay from audit records
// ---------------------------------------------------------------------------

// ReplayFromAuditTrail replays a computation using only information from
// the audit trail. This is a lighter-weight replay that verifies the audit
// record chain rather than re-executing the computation.
func (re *ReplayEngine) ReplayFromAuditTrail(ctx context.Context, jobID string) (*ReplayResult, error) {
	if re.source == nil {
		return nil, fmt.Errorf("audit/replay: LogSource is required")
	}

	// Find all audit records for this job.
	records := re.source.GetRecords()
	var jobRecords []keeper.AuditRecord
	for _, r := range records {
		if r.Details["job_id"] == jobID {
			jobRecords = append(jobRecords, r)
		}
	}

	if len(jobRecords) == 0 {
		return nil, fmt.Errorf("audit/replay: no audit records found for job %s", jobID)
	}

	// Verify the chain integrity of the job's records.
	result := &ReplayResult{
		JobID:     jobID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Find the completion record.
	for _, r := range jobRecords {
		if r.Action == "job_completed" {
			result.OriginalOutput = r.Details["output_hash"]
			break
		}
	}

	// Verify each record's hash.
	allValid := true
	for _, r := range jobRecords {
		computed := ComputeRecordHash(r)
		if computed != r.RecordHash {
			allValid = false
			result.Differences = append(result.Differences, Difference{
				Field:         fmt.Sprintf("record_hash_seq_%d", r.Sequence),
				OriginalValue: r.RecordHash,
				ReplayValue:   computed,
				Description:   fmt.Sprintf("audit record %d hash mismatch", r.Sequence),
			})
		}
	}

	result.Match = allValid
	result.Evidence = GenerateReplayEvidence(result)

	return result, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hashBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
