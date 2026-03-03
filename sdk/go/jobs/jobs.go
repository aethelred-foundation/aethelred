// Package jobs provides job-related operations.
package jobs

import (
	"context"
	"time"

	"github.com/aethelred/sdk-go/types"
)

// Client interface for HTTP operations.
type Client interface {
	Get(ctx context.Context, path string, result interface{}) error
	Post(ctx context.Context, path string, body, result interface{}) error
}

const basePath = "/aethelred/pouw/v1"

// Module provides job operations.
type Module struct {
	client Client
}

// NewModule creates a new jobs module.
func NewModule(client Client) *Module {
	return &Module{client: client}
}

// SubmitRequest represents a job submission request.
type SubmitRequest struct {
	ModelHash     string            `json:"model_hash"`
	InputHash     string            `json:"input_hash"`
	ProofType     types.ProofType   `json:"proof_type,omitempty"`
	Priority      uint32            `json:"priority,omitempty"`
	MaxGas        string            `json:"max_gas,omitempty"`
	TimeoutBlocks uint32            `json:"timeout_blocks,omitempty"`
	CallbackURL   string            `json:"callback_url,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// SubmitResponse represents a job submission response.
type SubmitResponse struct {
	JobID           string `json:"job_id"`
	TxHash          string `json:"tx_hash"`
	EstimatedBlocks uint32 `json:"estimated_blocks"`
}

// Submit submits a new job.
func (m *Module) Submit(ctx context.Context, req SubmitRequest) (*SubmitResponse, error) {
	var resp SubmitResponse
	if err := m.client.Post(ctx, basePath+"/jobs", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Get retrieves a job by ID.
func (m *Module) Get(ctx context.Context, jobID string) (*types.ComputeJob, error) {
	var resp struct{ Job types.ComputeJob }
	if err := m.client.Get(ctx, basePath+"/jobs/"+jobID, &resp); err != nil {
		return nil, err
	}
	return &resp.Job, nil
}

// List lists jobs.
func (m *Module) List(ctx context.Context, pagination *types.PageRequest) ([]types.ComputeJob, error) {
	var resp struct{ Jobs []types.ComputeJob }
	if err := m.client.Get(ctx, basePath+"/jobs", &resp); err != nil {
		return nil, err
	}
	return resp.Jobs, nil
}

// Cancel cancels a job.
func (m *Module) Cancel(ctx context.Context, jobID string) error {
	return m.client.Post(ctx, basePath+"/jobs/"+jobID+"/cancel", nil, nil)
}

// WaitForCompletion waits for a job to complete.
func (m *Module) WaitForCompletion(ctx context.Context, jobID string, pollInterval, timeout time.Duration) (*types.ComputeJob, error) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		job, err := m.Get(ctx, jobID)
		if err != nil {
			return nil, err
		}
		
		switch job.Status {
		case types.JobStatusCompleted, types.JobStatusFailed, types.JobStatusCancelled:
			return job, nil
		}
		
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
	
	return nil, types.ErrTimeout
}
