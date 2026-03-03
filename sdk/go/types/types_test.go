package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJobStatusConstants(t *testing.T) {
	t.Parallel()

	statuses := []JobStatus{
		JobStatusUnspecified, JobStatusPending, JobStatusAssigned,
		JobStatusComputing, JobStatusVerifying, JobStatusCompleted,
		JobStatusFailed, JobStatusCancelled, JobStatusExpired,
	}
	if len(statuses) != 9 {
		t.Fatalf("expected 9 job statuses, got %d", len(statuses))
	}
	if JobStatusPending != "JOB_STATUS_PENDING" {
		t.Fatalf("JobStatusPending = %s, want JOB_STATUS_PENDING", JobStatusPending)
	}
}

func TestSealStatusConstants(t *testing.T) {
	t.Parallel()

	if SealStatusActive != "SEAL_STATUS_ACTIVE" {
		t.Fatalf("SealStatusActive = %s", SealStatusActive)
	}
}

func TestProofTypeConstants(t *testing.T) {
	t.Parallel()

	if ProofTypeTEE != "PROOF_TYPE_TEE" {
		t.Fatalf("ProofTypeTEE = %s", ProofTypeTEE)
	}
	if ProofTypeZKML != "PROOF_TYPE_ZKML" {
		t.Fatalf("ProofTypeZKML = %s", ProofTypeZKML)
	}
}

func TestTEEPlatformConstants(t *testing.T) {
	t.Parallel()

	platforms := []TEEPlatform{
		TEEPlatformUnspecified, TEEPlatformIntelSGX,
		TEEPlatformAMDSEV, TEEPlatformAWSNitro,
		TEEPlatformARMTrustZone,
	}
	if len(platforms) != 5 {
		t.Fatalf("expected 5 TEE platforms, got %d", len(platforms))
	}
}

func TestComputeJobJSON(t *testing.T) {
	t.Parallel()

	now := time.Now()
	job := ComputeJob{
		ID:        "job_1",
		Creator:   "aeth1creator",
		ModelHash: "abc123",
		InputHash: "def456",
		Status:    JobStatusPending,
		ProofType: ProofTypeTEE,
		Priority:  1,
		CreatedAt: now,
	}

	data, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ComputeJob
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ID != "job_1" {
		t.Fatalf("decoded ID = %s, want job_1", decoded.ID)
	}
	if decoded.Status != JobStatusPending {
		t.Fatalf("decoded Status = %s, want %s", decoded.Status, JobStatusPending)
	}
}

func TestDigitalSealJSON(t *testing.T) {
	t.Parallel()

	seal := DigitalSeal{
		ID:        "seal_1",
		JobID:     "job_1",
		ModelHash: "abc",
		Status:    SealStatusActive,
		Requester: "aeth1req",
	}

	data, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}

	var decoded DigitalSeal
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Status != SealStatusActive {
		t.Fatalf("decoded Status = %s", decoded.Status)
	}
}

func TestErrorSentinels(t *testing.T) {
	t.Parallel()

	if ErrRateLimited == nil || ErrNotFound == nil || ErrUnauthorized == nil || ErrTimeout == nil {
		t.Fatal("sentinel errors must not be nil")
	}
	if ErrRateLimited.Error() != "rate limit exceeded" {
		t.Fatalf("ErrRateLimited = %s", ErrRateLimited)
	}
}

func TestPageRequestJSON(t *testing.T) {
	t.Parallel()

	req := PageRequest{Limit: 50, Offset: 10, Reverse: true}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var decoded PageRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Limit != 50 || decoded.Offset != 10 || !decoded.Reverse {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestValidatorStatsJSON(t *testing.T) {
	t.Parallel()

	stats := ValidatorStats{
		Address:         "aeth1val",
		JobsCompleted:   100,
		ReputationScore: 0.95,
	}
	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ValidatorStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.JobsCompleted != 100 {
		t.Fatalf("decoded JobsCompleted = %d", decoded.JobsCompleted)
	}
}
