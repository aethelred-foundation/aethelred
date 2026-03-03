// Package models provides model registry operations.
package models

import (
	"context"

	"github.com/aethelred/sdk-go/types"
)

type Client interface {
	Get(ctx context.Context, path string, result interface{}) error
	Post(ctx context.Context, path string, body, result interface{}) error
}

const basePath = "/aethelred/pouw/v1"

type Module struct {
	client Client
}

func NewModule(client Client) *Module {
	return &Module{client: client}
}

type RegisterRequest struct {
	ModelHash    string              `json:"model_hash"`
	Name         string              `json:"name"`
	Architecture string              `json:"architecture,omitempty"`
	Version      string              `json:"version,omitempty"`
	Category     types.UtilityCategory `json:"category,omitempty"`
	StorageURI   string              `json:"storage_uri,omitempty"`
}

type RegisterResponse struct {
	ModelHash string `json:"model_hash"`
	TxHash    string `json:"tx_hash"`
}

func (m *Module) Register(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	var resp RegisterResponse
	if err := m.client.Post(ctx, basePath+"/models", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *Module) Get(ctx context.Context, modelHash string) (*types.RegisteredModel, error) {
	var resp struct{ Model types.RegisteredModel }
	if err := m.client.Get(ctx, basePath+"/models/"+modelHash, &resp); err != nil {
		return nil, err
	}
	return &resp.Model, nil
}

func (m *Module) List(ctx context.Context, pagination *types.PageRequest) ([]types.RegisteredModel, error) {
	var resp struct{ Models []types.RegisteredModel }
	if err := m.client.Get(ctx, basePath+"/models", &resp); err != nil {
		return nil, err
	}
	return resp.Models, nil
}
