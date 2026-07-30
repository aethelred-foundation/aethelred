package keeper

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

// activeValidatorForScheduling is derived entirely from committed staking and
// PoUW capability state. No process-local profile or network input may affect
// this set.
type activeValidatorForScheduling struct {
	address string
	power   int64
	cap     *types.ValidatorCapability
}

// GetOpenJobs returns the authoritative PendingJobs index, including both
// Pending and Processing jobs. Unlike GetPendingJobs, it returns collection
// errors instead of silently turning a state read failure into an empty queue.
func (k Keeper) GetOpenJobs(ctx sdk.Context) ([]*types.ComputeJob, error) {
	jobs := make([]*types.ComputeJob, 0)
	err := k.PendingJobs.Walk(ctx, nil, func(id string, job types.ComputeJob) (bool, error) {
		if id == "" || job.Id != id {
			return true, fmt.Errorf("pending job index mismatch: key=%q job_id=%q", id, job.Id)
		}
		if job.Status != types.JobStatusPending && job.Status != types.JobStatusProcessing {
			return true, fmt.Errorf("terminal job %s remains in pending index with status %s", id, job.Status)
		}
		jobCopy := job
		jobs = append(jobs, &jobCopy)
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk open jobs: %w", err)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Id < jobs[j].Id })
	return jobs, nil
}

// AssignedValidators returns the persisted, canonical assignment for a job.
// Processing jobs must always have a non-empty, duplicate-free assignment.
func AssignedValidators(job *types.ComputeJob) ([]string, error) {
	if job == nil {
		return nil, fmt.Errorf("job is nil")
	}
	if job.Metadata == nil {
		if job.Status == types.JobStatusProcessing {
			return nil, fmt.Errorf("processing job %s has no scheduling metadata", job.Id)
		}
		return nil, nil
	}
	raw := job.Metadata[schedulerMetaAssignedTo]
	if raw == "" {
		if job.Status == types.JobStatusProcessing {
			return nil, fmt.Errorf("processing job %s has no validator assignment", job.Id)
		}
		return nil, nil
	}

	var assigned []string
	if err := json.Unmarshal([]byte(raw), &assigned); err != nil {
		return nil, fmt.Errorf("decode assignment for job %s: %w", job.Id, err)
	}
	if len(assigned) == 0 {
		return nil, fmt.Errorf("job %s has an empty validator assignment", job.Id)
	}
	sort.Strings(assigned)
	for i, address := range assigned {
		if _, err := sdk.AccAddressFromBech32(address); err != nil {
			return nil, fmt.Errorf("job %s has invalid assigned validator %q: %w", job.Id, address, err)
		}
		if i > 0 && assigned[i-1] == address {
			return nil, fmt.Errorf("job %s assigns validator %s more than once", job.Id, address)
		}
	}
	return assigned, nil
}

// IsValidatorAssigned checks the chain-backed assignment rather than the
// process-local scheduler cache.
func IsValidatorAssigned(job *types.ComputeJob, validatorAddress string) (bool, error) {
	assigned, err := AssignedValidators(job)
	if err != nil {
		return false, err
	}
	index := sort.SearchStrings(assigned, validatorAddress)
	return index < len(assigned) && assigned[index] == validatorAddress, nil
}

// GetAssignedProcessingJobs returns a stable job-ID-sorted view suitable for
// ExtendVote. It remains correct immediately after restart or snapshot restore,
// before the in-memory scheduler cache has been rebuilt.
func (k Keeper) GetAssignedProcessingJobs(
	ctx sdk.Context,
	validatorAddress string,
) ([]*types.ComputeJob, error) {
	if _, err := sdk.AccAddressFromBech32(validatorAddress); err != nil {
		return nil, fmt.Errorf("invalid validator account address: %w", err)
	}

	openJobs, err := k.GetOpenJobs(ctx)
	if err != nil {
		return nil, err
	}
	jobs := make([]*types.ComputeJob, 0)
	for _, job := range openJobs {
		if job.Status != types.JobStatusProcessing {
			continue
		}
		assigned, err := IsValidatorAssigned(job, validatorAddress)
		if err != nil {
			return nil, err
		}
		if assigned {
			jobs = append(jobs, job)
		}
	}
	return jobs, nil
}

// ScheduleChainBacked assigns pending jobs using only committed state.
//
// The initial production policy deliberately assigns every active, bonded,
// proof-capable validator with capacity. Aggregation currently measures quorum
// against the full commit voting power, so selecting a smaller address-count
// committee can make a valid job mathematically unable to reach finality.
// A smaller committee requires a separate, explicit consensus upgrade with an
// authenticated on-chain randomness source and committee-power denominator.
func (s *JobScheduler) ScheduleChainBacked(ctx sdk.Context) ([]*types.ComputeJob, error) {
	if s == nil || s.keeper == nil {
		return nil, fmt.Errorf("chain-backed scheduler keeper is not configured")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cacheCtx, write := ctx.CacheContext()
	params, err := s.keeper.GetParams(cacheCtx)
	if err != nil {
		return nil, fmt.Errorf("load scheduler params: %w", err)
	}
	if params == nil ||
		params.MinValidators <= 0 ||
		params.MaxJobsPerBlock <= 0 ||
		params.ConsensusThreshold < 67 ||
		params.ConsensusThreshold > 100 {
		return nil, fmt.Errorf("invalid on-chain scheduler params")
	}

	openJobs, err := s.keeper.GetOpenJobs(cacheCtx)
	if err != nil {
		return nil, err
	}
	active, totalPower, err := s.activeValidatorsFromChain(cacheCtx)
	if err != nil {
		return nil, err
	}

	currentJobs := make(map[string]int64, len(active))
	for _, job := range openJobs {
		if job.Status != types.JobStatusProcessing {
			continue
		}
		assigned, err := AssignedValidators(job)
		if err != nil {
			return nil, err
		}
		for _, address := range assigned {
			if currentJobs[address] == math.MaxInt64 {
				return nil, fmt.Errorf("validator %s assignment count overflow", address)
			}
			currentJobs[address]++
		}
	}

	pending := make([]*types.ComputeJob, 0)
	for _, job := range openJobs {
		if job.Status == types.JobStatusPending {
			pending = append(pending, job)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if pending[i].Priority != pending[j].Priority {
			return pending[i].Priority > pending[j].Priority
		}
		if pending[i].BlockHeight != pending[j].BlockHeight {
			return pending[i].BlockHeight < pending[j].BlockHeight
		}
		return pending[i].Id < pending[j].Id
	})

	maxJobs := params.MaxJobsPerBlock
	selected := make([]*types.ComputeJob, 0)
	for _, job := range pending {
		if int64(len(selected)) >= maxJobs {
			break
		}
		// The module EndBlock timeout pass runs after this pre-update
		// assignment snapshot. Never activate a job that it will terminally
		// expire later in the same block.
		if cacheCtx.BlockHeight() > job.BlockHeight &&
			cacheCtx.BlockHeight()-job.BlockHeight > params.JobTimeoutBlocks {
			continue
		}

		assigned := make([]string, 0, len(active))
		var assignedPower int64
		for _, validator := range active {
			if !validatorSupportsProof(validator.cap, job.ProofType) {
				continue
			}
			if validator.cap.MaxConcurrentJobs <= 0 ||
				currentJobs[validator.address] >= validator.cap.MaxConcurrentJobs {
				continue
			}
			if assignedPower > math.MaxInt64-validator.power {
				return nil, fmt.Errorf("assigned voting power overflow for job %s", job.Id)
			}
			assigned = append(assigned, validator.address)
			assignedPower += validator.power
		}

		requiredPower := requiredThresholdCount(totalPower, int(params.ConsensusThreshold))
		if int64(len(assigned)) < params.MinValidators || assignedPower < requiredPower {
			continue
		}

		if err := job.MarkProcessingAt(cacheCtx.BlockTime()); err != nil {
			return nil, fmt.Errorf("mark job %s processing: %w", job.Id, err)
		}
		if job.Metadata == nil {
			job.Metadata = make(map[string]string)
		}
		assignmentJSON, err := json.Marshal(assigned)
		if err != nil {
			return nil, fmt.Errorf("encode assignment for job %s: %w", job.Id, err)
		}
		job.Metadata[schedulerMetaAssignedTo] = string(assignmentJSON)
		job.Metadata[schedulerMetaSubmittedBlock] = strconv.FormatInt(job.BlockHeight, 10)
		job.Metadata[schedulerMetaLastAttemptBlock] = strconv.FormatInt(cacheCtx.BlockHeight(), 10)
		delete(job.Metadata, schedulerMetaVRFVersion)
		delete(job.Metadata, schedulerMetaVRFEntropy)
		delete(job.Metadata, schedulerMetaVRFAssignments)
		delete(job.Metadata, schedulerMetaBeaconSource)
		delete(job.Metadata, schedulerMetaBeaconVersion)
		delete(job.Metadata, schedulerMetaBeaconRound)
		delete(job.Metadata, schedulerMetaBeaconRandomness)
		delete(job.Metadata, schedulerMetaBeaconSigHash)

		if err := s.keeper.UpdateJob(cacheCtx, job); err != nil {
			return nil, fmt.Errorf("persist assignment for job %s: %w", job.Id, err)
		}
		for _, address := range assigned {
			currentJobs[address]++
		}
		selected = append(selected, job)
		cacheCtx.EventManager().EmitEvent(
			sdk.NewEvent(
				"job_assigned",
				sdk.NewAttribute("job_id", job.Id),
				sdk.NewAttribute("validator_count", strconv.Itoa(len(assigned))),
				sdk.NewAttribute("assigned_power", strconv.FormatInt(assignedPower, 10)),
			),
		)
	}

	// Build the process-local hot cache from the exact state that is about to
	// commit. No cache mutation occurs before every state write succeeds.
	reconciledJobs, err := s.keeper.GetOpenJobs(cacheCtx)
	if err != nil {
		return nil, err
	}
	newQueue, newIndex, err := schedulerJobsFromChain(reconciledJobs)
	if err != nil {
		return nil, err
	}
	newCapabilities := make(map[string]*types.ValidatorCapability, len(active))
	for _, validator := range active {
		capCopy := *validator.cap
		capCopy.CurrentJobs = currentJobs[validator.address]
		newCapabilities[validator.address] = &capCopy
	}

	write()
	s.jobQueue = newQueue
	s.jobIndex = newIndex
	s.validatorCapabilities = newCapabilities
	return selected, nil
}

func (s *JobScheduler) activeValidatorsFromChain(
	ctx sdk.Context,
) ([]activeValidatorForScheduling, int64, error) {
	if s.keeper.stakingKeeper == nil {
		return nil, 0, fmt.Errorf("staking keeper is not configured")
	}
	powerKeeper, ok := s.keeper.stakingKeeper.(stakingPowerKeeper)
	if !ok {
		return nil, 0, fmt.Errorf("staking keeper cannot read the committed validator power snapshot")
	}
	validators, err := s.keeper.stakingKeeper.GetAllValidators(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("load staking validators: %w", err)
	}
	capabilities, err := s.keeper.GetAllValidatorCapabilities(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("load validator capabilities: %w", err)
	}
	capabilityByAddress := make(map[string]*types.ValidatorCapability, len(capabilities))
	for _, capability := range capabilities {
		if capability == nil || capability.Address == "" {
			return nil, 0, fmt.Errorf("validator capability has no address")
		}
		if _, duplicate := capabilityByAddress[capability.Address]; duplicate {
			return nil, 0, fmt.Errorf("duplicate validator capability for %s", capability.Address)
		}
		capCopy := *capability
		capabilityByAddress[capability.Address] = &capCopy
	}

	active := make([]activeValidatorForScheduling, 0)
	var totalPower int64
	for _, validator := range validators {
		operator, err := sdk.ValAddressFromBech32(validator.GetOperator())
		if err != nil {
			return nil, 0, fmt.Errorf("decode validator operator: %w", err)
		}
		// LastValidatorPower is the validator set committed before staking's
		// current EndBlock update. Scheduling runs before ModuleManager.EndBlock,
		// so this is exactly the H+1 set that consumes these assignments.
		power, err := powerKeeper.GetLastValidatorPower(ctx, operator)
		if err != nil || power <= 0 {
			continue
		}
		if totalPower > math.MaxInt64-power {
			return nil, 0, fmt.Errorf("total bonded voting power overflow")
		}
		totalPower += power

		accountAddress := sdk.AccAddress(operator).String()
		capability := capabilityByAddress[accountAddress]
		if capability == nil || !capability.IsOnline {
			continue
		}
		if !s.keeper.hasMinimumValidatorStake(ctx, accountAddress) {
			continue
		}
		active = append(active, activeValidatorForScheduling{
			address: accountAddress,
			power:   power,
			cap:     capability,
		})
	}
	sort.Slice(active, func(i, j int) bool { return active[i].address < active[j].address })
	return active, totalPower, nil
}

func validatorSupportsProof(capability *types.ValidatorCapability, proofType types.ProofType) bool {
	if capability == nil {
		return false
	}
	switch proofType {
	case types.ProofTypeTEE:
		return len(capability.TeePlatforms) > 0
	case types.ProofTypeZKML:
		return len(capability.ZkmlSystems) > 0
	case types.ProofTypeHybrid:
		return len(capability.TeePlatforms) > 0 && len(capability.ZkmlSystems) > 0
	default:
		return false
	}
}

func schedulerJobsFromChain(
	jobs []*types.ComputeJob,
) (*JobPriorityQueue, map[string]*ScheduledJob, error) {
	queue := &JobPriorityQueue{}
	index := make(map[string]*ScheduledJob, len(jobs))
	for _, job := range jobs {
		if job == nil {
			return nil, nil, fmt.Errorf("open job is nil")
		}
		assigned, err := AssignedValidators(job)
		if err != nil {
			return nil, nil, err
		}
		lane, err := ResolveExecutionLane(job)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve execution lane for job %s: %w", job.Id, err)
		}
		scheduled := &ScheduledJob{
			Job:               job,
			EffectivePriority: job.Priority,
			SubmittedBlock:    getMetaInt(job.Metadata, schedulerMetaSubmittedBlock, job.BlockHeight),
			RetryCount:        getMetaIntAsInt(job.Metadata, schedulerMetaRetryCount, 0),
			LastAttemptBlock:  getMetaInt(job.Metadata, schedulerMetaLastAttemptBlock, 0),
			AssignedTo:        assigned,
			ExecutionLane:     lane,
			AssignedWorkers:   getMetaStringSlice(job.Metadata, schedulerMetaAssignedWorkers),
		}
		*queue = append(*queue, scheduled)
		index[job.Id] = scheduled
	}
	sort.Slice(*queue, func(i, j int) bool {
		left := (*queue)[i]
		right := (*queue)[j]
		if left.EffectivePriority != right.EffectivePriority {
			return left.EffectivePriority > right.EffectivePriority
		}
		if left.SubmittedBlock != right.SubmittedBlock {
			return left.SubmittedBlock < right.SubmittedBlock
		}
		return left.Job.Id < right.Job.Id
	})
	for i, scheduled := range *queue {
		scheduled.index = i
	}
	return queue, index, nil
}
