package seals

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

func assign(result interface{}, payload interface{}) error {
	if result == nil {
		return nil
	}
	bz, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(bz, result)
}

func sampleSeal() types.DigitalSeal {
	return types.DigitalSeal{
		ID:               "seal-1",
		JobID:            "job-1",
		ModelHash:        "0xmodel",
		InputCommitment:  "0xinput",
		OutputCommitment: "0xoutput",
		ModelCommitment:  "0xmodelcommit",
		Status:           types.SealStatusActive,
		Requester:        "aethelred1requester",
		Validators:       []types.ValidatorAttestation{},
		CreatedAt:        time.Unix(1700000000, 0),
	}
}

func TestVerify_UsesExpectedEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			gotPath = path
			return assign(result, VerifyResponse{
				Valid:               true,
				Seal:                &types.DigitalSeal{ID: "seal-1"},
				VerificationDetails: map[string]bool{"signature": true},
			})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			t.Fatalf("unexpected Post call: %s", path)
			return nil
		},
	})

	resp, err := m.Verify(context.Background(), "seal-1")
	require.NoError(t, err)
	require.Equal(t, basePath+"/seals/seal-1/verify", gotPath)
	require.True(t, resp.Valid)
	require.Equal(t, "seal-1", resp.Seal.ID)
}

func TestRevoke_PostsReasonPayload(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]string

	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			t.Fatalf("unexpected Get call: %s", path)
			return nil
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			gotPath = path
			gotBody = body.(map[string]string)
			return nil
		},
	})

	err := m.Revoke(context.Background(), "seal-1", "audit_test")
	require.NoError(t, err)
	require.Equal(t, basePath+"/seals/seal-1/revoke", gotPath)
	require.Equal(t, "audit_test", gotBody["reason"])
}

func TestCreate_PostsCreateRequest(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotReq CreateRequest
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			t.Fatalf("unexpected Get call: %s", path)
			return nil
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			gotPath = path
			gotReq = body.(CreateRequest)
			return assign(result, CreateResponse{SealID: "seal-1", TxHash: "0xtx"})
		},
	})

	resp, err := m.Create(context.Background(), CreateRequest{
		JobID:           "job-1",
		ExpiresInBlocks: 10,
	})
	require.NoError(t, err)
	require.Equal(t, basePath+"/seals", gotPath)
	require.Equal(t, "job-1", gotReq.JobID)
	require.Equal(t, "seal-1", resp.SealID)
}

func TestGet_UnwrapsSeal(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			gotPath = path
			return assign(result, struct {
				Seal types.DigitalSeal `json:"seal"`
			}{Seal: sampleSeal()})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	seal, err := m.Get(context.Background(), "seal-1")
	require.NoError(t, err)
	require.Equal(t, basePath+"/seals/seal-1", gotPath)
	require.Equal(t, "seal-1", seal.ID)
}

func TestList_UsesSealsEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error {
			gotPath = path
			return assign(result, struct {
				Seals []types.DigitalSeal `json:"seals"`
			}{Seals: []types.DigitalSeal{sampleSeal()}})
		},
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	seals, err := m.List(context.Background(), &types.PageRequest{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, basePath+"/seals", gotPath)
	require.Len(t, seals, 1)
}

func TestCreate_PropagatesClientError(t *testing.T) {
	t.Parallel()

	wantErr := types.ErrUnauthorized
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return nil },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return wantErr },
	})

	resp, err := m.Create(context.Background(), CreateRequest{JobID: "job-1"})
	require.Nil(t, resp)
	require.ErrorIs(t, err, wantErr)
}

func TestGet_PropagatesClientError(t *testing.T) {
	t.Parallel()

	wantErr := types.ErrNotFound
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return wantErr },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	seal, err := m.Get(context.Background(), "missing")
	require.Nil(t, seal)
	require.ErrorIs(t, err, wantErr)
}

func TestVerify_PropagatesClientError(t *testing.T) {
	t.Parallel()

	wantErr := types.ErrTimeout
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return wantErr },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	resp, err := m.Verify(context.Background(), "seal-1")
	require.Nil(t, resp)
	require.ErrorIs(t, err, wantErr)
}

func TestList_PropagatesClientError(t *testing.T) {
	t.Parallel()

	wantErr := types.ErrUnauthorized
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return wantErr },
		postFn: func(ctx context.Context, path string, body, result interface{}) error { return nil },
	})

	resp, err := m.List(context.Background(), nil)
	require.Nil(t, resp)
	require.ErrorIs(t, err, wantErr)
}

func TestCreate_IncludesRegulatoryInfoPayload(t *testing.T) {
	t.Parallel()

	var gotReq CreateRequest
	m := NewModule(&stubClient{
		getFn: func(ctx context.Context, path string, result interface{}) error { return nil },
		postFn: func(ctx context.Context, path string, body, result interface{}) error {
			gotReq = body.(CreateRequest)
			return assign(result, CreateResponse{SealID: "seal-2", TxHash: "0xtx2"})
		},
	})

	_, err := m.Create(context.Background(), CreateRequest{
		JobID: "job-2",
		RegulatoryInfo: &types.RegulatoryInfo{
			Jurisdiction:         "UAE",
			ComplianceFrameworks: []string{"ADGM"},
			DataClassification:   "confidential",
			RetentionPeriod:      "7y",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, gotReq.RegulatoryInfo)
	require.Equal(t, "UAE", gotReq.RegulatoryInfo.Jurisdiction)
}
