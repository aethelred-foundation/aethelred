package models

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

func TestRegister(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postResp: RegisterResponse{
		ModelHash: "abc123", TxHash: "tx_1",
	}}
	m := NewModule(mc)

	resp, err := m.Register(context.Background(), RegisterRequest{
		ModelHash: "abc123",
		Name:      "test-model",
		Category:  types.UtilityCategoryMedical,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ModelHash != "abc123" {
		t.Fatalf("ModelHash = %s", resp.ModelHash)
	}
	if mc.lastPath != "/aethelred/pouw/v1/models" {
		t.Fatalf("path = %s", mc.lastPath)
	}
}

func TestGet(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getResp: map[string]interface{}{
		"Model": types.RegisteredModel{ModelHash: "abc", Name: "my-model"},
	}}
	m := NewModule(mc)

	model, err := m.Get(context.Background(), "abc")
	if err != nil {
		t.Fatal(err)
	}
	if model.Name != "my-model" {
		t.Fatalf("Name = %s", model.Name)
	}
}

func TestList(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getResp: map[string]interface{}{
		"Models": []types.RegisteredModel{{Name: "m1"}, {Name: "m2"}},
	}}
	m := NewModule(mc)

	models, err := m.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 {
		t.Fatalf("len = %d, want 2", len(models))
	}
}

func TestRegisterError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postErr: fmt.Errorf("server error")}
	m := NewModule(mc)

	_, err := m.Register(context.Background(), RegisterRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{getErr: fmt.Errorf("not found")}
	m := NewModule(mc)

	_, err := m.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}
