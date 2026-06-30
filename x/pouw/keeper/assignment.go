package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// assignmentBeaconSource marks a job assigned by the in-consensus deterministic
// assigner (as opposed to an external DKG/drand threshold beacon).
const assignmentBeaconSource = "block-deterministic"

// AssignPendingJobs deterministically assigns every unassigned pending job to the
// eligible validator pool. It runs in EndBlock, so every validator computes the
// SAME assignment from the SAME on-chain state — no wall clock, no map-iteration
// order, no in-memory scheduler state. Assignments are written to each job's
// on-chain Metadata (scheduler.assigned_to), which ExtendVote reads (via
// GetJobsForValidator) to decide which jobs a validator must verify. This is the
// wire between job submission and the verification → Digital Seal pipeline.
func (k Keeper) AssignPendingJobs(ctx context.Context) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	eligible := k.eligibleValidators(ctx)
	if len(eligible) == 0 {
		return
	}

	for _, job := range k.GetPendingJobs(ctx) {
		if job == nil {
			continue
		}
		// Already assigned — assignment is written once and is stable.
		if len(getMetaStringSlice(job.Metadata, schedulerMetaAssignedTo)) > 0 {
			continue
		}

		assigned := selectAssignedValidators(job.Id, eligible)
		if len(assigned) == 0 {
			continue
		}

		raw, err := json.Marshal(assigned)
		if err != nil {
			sdkCtx.Logger().Error("assign job: marshal validators", "job_id", job.Id, "error", err)
			continue
		}
		if job.Metadata == nil {
			job.Metadata = make(map[string]string)
		}
		job.Metadata[schedulerMetaAssignedTo] = string(raw)
		job.Metadata[schedulerMetaBeaconSource] = assignmentBeaconSource

		// Move the job PENDING → PROCESSING on assignment. This makes the eventual
		// seal step's PROCESSING → COMPLETED transition valid (PENDING → COMPLETED
		// is rejected by the state machine). UpdateJob keeps PROCESSING jobs in the
		// pending set, so assigned validators keep verifying it until it is sealed.
		// TransitionTo stamps UpdatedAt from the wall clock; override with block
		// time so this EndBlock state write is deterministic across validators.
		if err := job.MarkProcessing(); err != nil {
			sdkCtx.Logger().Error("assign job: mark processing", "job_id", job.Id, "error", err)
			continue
		}
		job.UpdatedAt = timestamppb.New(sdkCtx.BlockTime())

		if err := k.UpdateJob(ctx, job); err != nil {
			sdkCtx.Logger().Error("assign job: update", "job_id", job.Id, "error", err)
			continue
		}

		sdkCtx.EventManager().EmitEvent(sdk.NewEvent(
			"job_assigned",
			sdk.NewAttribute("job_id", job.Id),
			sdk.NewAttribute("validators", string(raw)),
			sdk.NewAttribute("count", fmt.Sprintf("%d", len(assigned))),
		))
	}
}

// AssignedJobsForValidator returns the pending jobs whose on-chain assignment
// (scheduler.assigned_to) includes the given validator account address. This is
// the read side of AssignPendingJobs and is what ExtendVote uses to decide which
// jobs a validator must verify. It reads only committed on-chain state, so every
// validator resolves its own assignments identically.
func (k Keeper) AssignedJobsForValidator(ctx context.Context, validatorAddr string) []*types.ComputeJob {
	var jobs []*types.ComputeJob
	for _, job := range k.GetPendingJobs(ctx) {
		if job == nil {
			continue
		}
		for _, addr := range getMetaStringSlice(job.Metadata, schedulerMetaAssignedTo) {
			if addr == validatorAddr {
				jobs = append(jobs, job)
				break
			}
		}
	}
	return jobs
}

// eligibleValidators returns the sorted set of validator account addresses that
// are eligible for PoUW assignment: they have registered a compute capability and
// meet the minimum bonded stake. The result is sorted so every validator builds
// an identical pool.
func (k Keeper) eligibleValidators(ctx context.Context) []string {
	caps, err := k.GetAllValidatorCapabilities(ctx)
	if err != nil {
		return nil
	}
	eligible := make([]string, 0, len(caps))
	for _, c := range caps {
		if c == nil || c.Address == "" {
			continue
		}
		if !k.hasMinimumValidatorStake(ctx, c.Address) {
			continue
		}
		eligible = append(eligible, c.Address)
	}
	sort.Strings(eligible)
	return eligible
}

// selectAssignedValidators picks the validators for a job. The current policy
// assigns the entire eligible pool, which guarantees the >=67% Digital Seal
// quorum can be reached whenever honest validators agree. Selection is a pure
// function of the (sorted) pool, so it is identical across validators. A future
// policy can sample a deterministic subset via rendezvous hashing keyed on jobID
// without changing the assignment contract.
func selectAssignedValidators(_ string, eligible []string) []string {
	out := make([]string, len(eligible))
	copy(out, eligible)
	return out
}
