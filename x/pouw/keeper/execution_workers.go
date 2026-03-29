package keeper

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// ExecutionLane identifies the isolated execution lane a job should use.
type ExecutionLane string

const (
	ExecutionLaneFastSmallModel       ExecutionLane = "fast-small-model"
	ExecutionLaneMediumEnterprise     ExecutionLane = "medium-enterprise-scoring"
	ExecutionLaneHeavyProofLargeModel ExecutionLane = "heavy-proof-large-model"
)

// ExecutionWorkerCapability models an attested execution worker that is
// separate from the settlement validator set.
type ExecutionWorkerCapability struct {
	ID                string
	Lane              ExecutionLane
	TeePlatforms      []string
	ZKMLSystems       []string
	MaxConcurrentJobs int
	CurrentJobs       int
	IsOnline          bool
	Attested          bool
}

// CanServe returns true when the worker is attested, online, has capacity, and
// has the required proof-system capabilities for the job.
func (w *ExecutionWorkerCapability) CanServe(job *types.ComputeJob, lane ExecutionLane) bool {
	if w == nil || job == nil {
		return false
	}
	if !w.IsOnline || !w.Attested {
		return false
	}
	if w.MaxConcurrentJobs <= 0 || w.CurrentJobs >= w.MaxConcurrentJobs {
		return false
	}
	if w.Lane != lane {
		return false
	}
	switch job.ProofType {
	case types.ProofTypeTEE:
		return len(w.TeePlatforms) > 0
	case types.ProofTypeZKML:
		return len(w.ZKMLSystems) > 0
	case types.ProofTypeHybrid:
		return len(w.TeePlatforms) > 0 && len(w.ZKMLSystems) > 0
	default:
		return false
	}
}

// ParseExecutionLane validates and parses a lane string.
func ParseExecutionLane(raw string) (ExecutionLane, error) {
	switch ExecutionLane(strings.TrimSpace(raw)) {
	case ExecutionLaneFastSmallModel:
		return ExecutionLaneFastSmallModel, nil
	case ExecutionLaneMediumEnterprise:
		return ExecutionLaneMediumEnterprise, nil
	case ExecutionLaneHeavyProofLargeModel:
		return ExecutionLaneHeavyProofLargeModel, nil
	default:
		return "", fmt.Errorf("unknown execution lane %q", raw)
	}
}

// ResolveExecutionLane derives the execution lane for a job.
// Explicit metadata wins; otherwise purpose and workload hints decide.
func ResolveExecutionLane(job *types.ComputeJob) (ExecutionLane, error) {
	if job == nil {
		return "", fmt.Errorf("job must not be nil")
	}

	for _, key := range []string{
		schedulerMetaExecutionLane,
		"execution_lane",
		"workload.pack_lane",
		"workload_lane",
	} {
		if job.Metadata == nil {
			break
		}
		if raw := strings.TrimSpace(job.Metadata[key]); raw != "" {
			return ParseExecutionLane(raw)
		}
	}

	text := strings.ToLower(strings.TrimSpace(job.Purpose) + " " + joinJobMetadata(job))
	if containsAny(text,
		"recursive",
		"heavy-proof",
		"large-model",
		"proof-heavy",
		"batch-proof",
		"genomics",
		"radiology",
		"foundation-model",
	) {
		return ExecutionLaneHeavyProofLargeModel, nil
	}

	if containsAny(text,
		"credit",
		"scoring",
		"score",
		"risk",
		"fraud",
		"underwriting",
		"compliance",
		"classification",
		"claims",
		"decisioning",
	) {
		return ExecutionLaneMediumEnterprise, nil
	}

	return ExecutionLaneFastSmallModel, nil
}

func joinJobMetadata(job *types.ComputeJob) string {
	if job == nil || len(job.Metadata) == 0 {
		return ""
	}
	keys := make([]string, 0, len(job.Metadata))
	for key := range job.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+job.Metadata[key])
	}
	return strings.Join(parts, " ")
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

type executionWorkerPool struct {
	workers map[string]*ExecutionWorkerCapability
}

func newExecutionWorkerPool(workers map[string]*ExecutionWorkerCapability) *executionWorkerPool {
	return &executionWorkerPool{workers: workers}
}

func (p *executionWorkerPool) availableCount() int {
	if p == nil {
		return 0
	}
	count := 0
	for _, worker := range p.workers {
		if worker != nil && worker.IsOnline && worker.Attested && worker.CurrentJobs < worker.MaxConcurrentJobs {
			count++
		}
	}
	return count
}

func (p *executionWorkerPool) assign(job *types.ComputeJob, lane ExecutionLane, required int) []string {
	if p == nil || job == nil || required <= 0 {
		return nil
	}

	candidates := make([]*ExecutionWorkerCapability, 0, len(p.workers))
	for _, worker := range p.workers {
		if worker != nil && worker.CanServe(job, lane) {
			candidates = append(candidates, worker)
		}
	}
	if len(candidates) < required {
		return nil
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CurrentJobs != candidates[j].CurrentJobs {
			return candidates[i].CurrentJobs < candidates[j].CurrentJobs
		}
		return candidates[i].ID < candidates[j].ID
	})

	assigned := make([]string, 0, required)
	for _, worker := range candidates[:required] {
		worker.CurrentJobs++
		assigned = append(assigned, worker.ID)
	}
	return assigned
}
