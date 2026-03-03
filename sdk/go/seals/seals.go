// Package seals provides seal-related operations.
package seals

import (
	"context"

	"github.com/aethelred/sdk-go/types"
)

type Client interface {
	Get(ctx context.Context, path string, result interface{}) error
	Post(ctx context.Context, path string, body, result interface{}) error
}

const basePath = "/aethelred/seal/v1"

type Module struct {
	client Client
}

func NewModule(client Client) *Module {
	return &Module{client: client}
}

type CreateRequest struct {
	JobID           string               `json:"job_id"`
	RegulatoryInfo  *types.RegulatoryInfo `json:"regulatory_info,omitempty"`
	ExpiresInBlocks uint64               `json:"expires_in_blocks,omitempty"`
}

type CreateResponse struct {
	SealID string `json:"seal_id"`
	TxHash string `json:"tx_hash"`
}

type VerifyResponse struct {
	Valid               bool            `json:"valid"`
	Seal                *types.DigitalSeal `json:"seal,omitempty"`
	VerificationDetails map[string]bool `json:"verification_details"`
	Errors              []string        `json:"errors"`
}

func (m *Module) Create(ctx context.Context, req CreateRequest) (*CreateResponse, error) {
	var resp CreateResponse
	if err := m.client.Post(ctx, basePath+"/seals", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *Module) Get(ctx context.Context, sealID string) (*types.DigitalSeal, error) {
	var resp struct{ Seal types.DigitalSeal }
	if err := m.client.Get(ctx, basePath+"/seals/"+sealID, &resp); err != nil {
		return nil, err
	}
	return &resp.Seal, nil
}

func (m *Module) List(ctx context.Context, pagination *types.PageRequest) ([]types.DigitalSeal, error) {
	var resp struct{ Seals []types.DigitalSeal }
	if err := m.client.Get(ctx, basePath+"/seals", &resp); err != nil {
		return nil, err
	}
	return resp.Seals, nil
}

func (m *Module) Verify(ctx context.Context, sealID string) (*VerifyResponse, error) {
	var resp VerifyResponse
	if err := m.client.Get(ctx, basePath+"/seals/"+sealID+"/verify", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *Module) Revoke(ctx context.Context, sealID, reason string) error {
	return m.client.Post(ctx, basePath+"/seals/"+sealID+"/revoke", map[string]string{"reason": reason}, nil)
}
