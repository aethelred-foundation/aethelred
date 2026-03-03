package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aethelred/sdk-go/types"
)

type mockClient struct {
	getResp  interface{}
	postResp interface{}
	getErr   error
	postErr  error
	lastPath string
}

func (m *mockClient) Get(_ context.Context, path string, result interface{}) error {
	m.lastPath = path
	if m.getErr != nil {
		return m.getErr
	}
	data, _ := json.Marshal(m.getResp)
	return json.Unmarshal(data, result)
}

func (m *mockClient) Post(_ context.Context, path string, body, result interface{}) error {
	m.lastPath = path
	if m.postErr != nil {
		return m.postErr
	}
	if result == nil {
		return nil
	}
	data, _ := json.Marshal(m.postResp)
	return json.Unmarshal(data, result)
}

func TestNewModule(t *testing.T) {
	t.Parallel()
	m := NewModule(&mockClient{})
	if m == nil {
		t.Fatal("NewModule returned nil")
	}
}

func TestGetStats(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getResp: types.ValidatorStats{
		Address: "aethel1val", JobsCompleted: 100, ReputationScore: 0.95,
	}}
	m := NewModule(mc)

	stats, err := m.GetStats(context.Background(), "aethel1val")
	if err != nil {
		t.Fatal(err)
	}
	if stats.JobsCompleted != 100 {
		t.Fatalf("JobsCompleted = %d", stats.JobsCompleted)
	}
	if mc.lastPath != "/aethelred/pouw/v1/validators/aethel1val/stats" {
		t.Fatalf("path = %s", mc.lastPath)
	}
}

func TestList(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getResp: map[string]interface{}{
		"Validators": []types.ValidatorStats{
			{Address: "v1"}, {Address: "v2"}, {Address: "v3"},
		},
	}}
	m := NewModule(mc)

	vals, err := m.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 3 {
		t.Fatalf("len = %d, want 3", len(vals))
	}
}

func TestRegisterCapability(t *testing.T) {
	t.Parallel()

	mc := &mockClient{}
	m := NewModule(mc)

	err := m.RegisterCapability(context.Background(), "aethel1val", types.HardwareCapability{
		TEEPlatforms:   []types.TEEPlatform{types.TEEPlatformIntelSGX},
		MaxModelSizeMB: 4096,
		GPUMemoryGB:    80,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mc.lastPath != "/aethelred/pouw/v1/validators/aethel1val/capability" {
		t.Fatalf("path = %s", mc.lastPath)
	}
}

func TestGetStatsError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getErr: fmt.Errorf("not found")}
	m := NewModule(mc)

	_, err := m.GetStats(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}
