// Package validators provides validator operations.
package validators

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

func (m *Module) GetStats(ctx context.Context, address string) (*types.ValidatorStats, error) {
	var resp types.ValidatorStats
	if err := m.client.Get(ctx, basePath+"/validators/"+address+"/stats", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *Module) List(ctx context.Context, pagination *types.PageRequest) ([]types.ValidatorStats, error) {
	var resp struct{ Validators []types.ValidatorStats }
	if err := m.client.Get(ctx, basePath+"/validators", &resp); err != nil {
		return nil, err
	}
	return resp.Validators, nil
}

func (m *Module) RegisterCapability(ctx context.Context, address string, capability types.HardwareCapability) error {
	return m.client.Post(ctx, basePath+"/validators/"+address+"/capability", map[string]interface{}{"hardware_capabilities": capability}, nil)
}
