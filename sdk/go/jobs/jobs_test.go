package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aethelred/sdk-go/types"
	"github.com/stretchr/testify/require"
)

type stubClient struct {
	getFn  func(ctx context.Context, path string, result interface{}) error
	postFn func(ctx context.Context, path string, body, result interface{}) error
}

func (s *stubClient) Get(ctx context.Context, path string, result interface{}) error {
	return s.getFn(ctx, path, result)
}

func (s *stubClient) Post(ctx context.Context, path string, body, result interface{}) error {
	return s.postFn(ctx, path, body, result)
}

func assignJSONResult(result interface{}, payload interface{}) error {
	if result == nil {
		return nil
	}
	bz, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(bz, result)
}

func testJob(status types.JobStatus) types.ComputeJob {
	return types.ComputeJob{
		ID:            "job-1",
		Creator:       "aethelred1creator",
		ModelHash:     "0xmodel",
		InputHash:     "0xinput",
		Status:        status,
		ProofType:     types.ProofTypeTEE,
		Priority:      1,
		MaxGas:        "100000",
		TimeoutBlocks: 100,
		CreatedAt:     time.Unix(1700000000, 0),
		Metadata:      map[string]string{},
	}
}

func TestModuleSubmit_UsesExpectedEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotReq SubmitRequest

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			t.Fatalf("unexpected Get call: %s", path)
			return nil
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			gotPath = path
			gotReq = body.(SubmitRequest)
			return assignJSONResult(result, SubmitResponse{
				JobID:           "job-1",
				TxHash:          "0xtx",
				EstimatedBlocks: 3,
			})
		},
	})

	resp, err := m.Submit(context.Background(), SubmitRequest{
		ModelHash: "0xmodel",
		InputHash: "0xinput",
	})
	require.NoError(t, err)
	require.Equal(t, basePath+"/jobs", gotPath)
	require.Equal(t, "0xmodel", gotReq.ModelHash)
	require.Equal(t, "job-1", resp.JobID)
}

func TestWaitForCompletion_ReturnsTerminalJob(t *testing.T) {
	t.Parallel()

	callCount := 0
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			callCount++
			require.Equal(t, basePath+"/jobs/job-1", path)
			if callCount == 1 {
				return assignJSONResult(result, struct {
					Job types.ComputeJob `json:"Job"`
				}{Job: testJob(types.JobStatusPending)})
			}
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"Job"`
			}{Job: testJob(types.JobStatusCompleted)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			t.Fatalf("unexpected Post call: %s", path)
			return nil
		},
	})

	job, err := m.WaitForCompletion(context.Background(), "job-1", 0, 200*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusCompleted, job.Status)
	require.Equal(t, 2, callCount)
}

func TestWaitForCompletion_Timeout(t *testing.T) {
	t.Parallel()

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"Job"`
			}{Job: testJob(types.JobStatusPending)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			t.Fatalf("unexpected Post call: %s", path)
			return nil
		},
	})

	job, err := m.WaitForCompletion(context.Background(), "job-1", 1*time.Millisecond, 2*time.Millisecond)
	require.Nil(t, job)
	require.ErrorIs(t, err, types.ErrTimeout)
}

func TestGet_UnwrapsJob(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			gotPath = path
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"job"`
			}{Job: testJob(types.JobStatusAssigned)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			t.Fatalf("unexpected Post call: %s", path)
			return nil
		},
	})

	job, err := m.Get(context.Background(), "job-abc")
	require.NoError(t, err)
	require.Equal(t, basePath+"/jobs/job-abc", gotPath)
	require.Equal(t, types.JobStatusAssigned, job.Status)
}

func TestList_UsesJobsEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			gotPath = path
			return assignJSONResult(result, struct {
				Jobs []types.ComputeJob `json:"jobs"`
			}{Jobs: []types.ComputeJob{testJob(types.JobStatusPending)}})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			t.Fatalf("unexpected Post call: %s", path)
			return nil
		},
	})

	jobs, err := m.List(context.Background(), &types.PageRequest{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, basePath+"/jobs", gotPath)
	require.Len(t, jobs, 1)
}

func TestCancel_PostsToCancelEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			t.Fatalf("unexpected Get call: %s", path)
			return nil
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			gotPath = path
			require.Nil(t, body)
			require.Nil(t, result)
			return nil
		},
	})

	err := m.Cancel(context.Background(), "job-1")
	require.NoError(t, err)
	require.Equal(t, basePath+"/jobs/job-1/cancel", gotPath)
}

func TestSubmit_PropagatesClientError(t *testing.T) {
	t.Parallel()

	wantErr := context.DeadlineExceeded
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return nil },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return wantErr },
	})

	resp, err := m.Submit(context.Background(), SubmitRequest{ModelHash: "x", InputHash: "y"})
	require.Nil(t, resp)
	require.ErrorIs(t, err, wantErr)
}

func TestWaitForCompletion_ReturnsFailedTerminalJob(t *testing.T) {
	t.Parallel()

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"job"`
			}{Job: testJob(types.JobStatusFailed)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	job, err := m.WaitForCompletion(context.Background(), "job-fail", 0, 100*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusFailed, job.Status)
}

func TestWaitForCompletion_ReturnsCancelledTerminalJob(t *testing.T) {
	t.Parallel()

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"job"`
			}{Job: testJob(types.JobStatusCancelled)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	job, err := m.WaitForCompletion(context.Background(), "job-cancel", 0, 100*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, types.JobStatusCancelled, job.Status)
}

func TestWaitForCompletion_PropagatesGetError(t *testing.T) {
	t.Parallel()

	wantErr := types.ErrUnauthorized
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return wantErr },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	job, err := m.WaitForCompletion(context.Background(), "job-err", 0, 100*time.Millisecond)
	require.Nil(t, job)
	require.ErrorIs(t, err, wantErr)
}

func TestWaitForCompletion_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			return assignJSONResult(result, struct {
				Job types.ComputeJob `json:"job"`
			}{Job: testJob(types.JobStatusPending)})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	job, err := m.WaitForCompletion(ctx, "job-ctx", time.Hour, time.Hour)
	require.Nil(t, job)
	require.ErrorIs(t, err, context.Canceled)
}

func TestWaitForCompletion_TableDrivenEdgeCases(t *testing.T) {
	t.Parallel()

	type scenario struct {
		name         string
		statuses      []types.JobStatus
		getErrAtCall  int
		getErr        error
		cancelContext bool
		pollInterval  time.Duration
		timeout       time.Duration
		wantStatus    *types.JobStatus
		wantErr       error
	}

	completed := types.JobStatusCompleted
	failed := types.JobStatusFailed
	cancelled := types.JobStatusCancelled

	cases := []scenario{
		{
			name:        "pending_assigned_verifying_completed",
			statuses:     []types.JobStatus{types.JobStatusPending, types.JobStatusAssigned, types.JobStatusVerifying, types.JobStatusCompleted},
			pollInterval: 0,
			timeout:      200 * time.Millisecond,
			wantStatus:   &completed,
		},
		{
			name:        "immediate_failed_terminal",
			statuses:     []types.JobStatus{types.JobStatusFailed},
			pollInterval: 0,
			timeout:      100 * time.Millisecond,
			wantStatus:   &failed,
		},
		{
			name:        "immediate_cancelled_terminal",
			statuses:     []types.JobStatus{types.JobStatusCancelled},
			pollInterval: 0,
			timeout:      100 * time.Millisecond,
			wantStatus:   &cancelled,
		},
		{
			name:        "rpc_error_on_second_poll",
			statuses:     []types.JobStatus{types.JobStatusPending},
			getErrAtCall: 2,
			getErr:       types.ErrUnauthorized,
			pollInterval: 0,
			timeout:      100 * time.Millisecond,
			wantErr:      types.ErrUnauthorized,
		},
		{
			name:        "timeout_with_non_terminal_status",
			statuses:     []types.JobStatus{types.JobStatusPending},
			pollInterval: 1 * time.Millisecond,
			timeout:      2 * time.Millisecond,
			wantErr:      types.ErrTimeout,
		},
		{
			name:         "context_cancelled_before_poll_sleep_returns_context_error",
			statuses:      []types.JobStatus{types.JobStatusPending},
			cancelContext: true,
			pollInterval:  10 * time.Millisecond,
			timeout:       100 * time.Millisecond,
			wantErr:       context.Canceled,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			callCount := 0
			ctx := context.Background()
			var cancel context.CancelFunc = func() {}
			if tc.cancelContext {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()

			m := NewModule(&stubClient{
				getFn: func(ctx context.Context, path string, result interface{}) error {
					callCount++
					if tc.getErrAtCall > 0 && callCount == tc.getErrAtCall {
						return tc.getErr
					}

					status := tc.statuses[len(tc.statuses)-1]
					if callCount-1 < len(tc.statuses) {
						status = tc.statuses[callCount-1]
					}

					if tc.cancelContext && callCount == 1 {
						cancel()
					}

					return assignJSONResult(result, struct {
						Job types.ComputeJob `json:"job"`
					}{Job: testJob(status)})
				},
				postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
			})

			job, err := m.WaitForCompletion(ctx, "job-edge", tc.pollInterval, tc.timeout)
			if tc.wantErr != nil {
				require.Nil(t, job)
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, job)
			require.Equal(t, *tc.wantStatus, job.Status)
		})
	}
}
