package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/structpb"
)

type queryServer struct {
	types.UnimplementedQueryServer
	Keeper
}

// NewQueryServerImpl returns an implementation of the QueryServer interface
func NewQueryServerImpl(keeper Keeper) types.QueryServer {
	return &queryServer{Keeper: keeper}
}

var _ types.QueryServer = queryServer{}

func (q queryServer) Seal(ctx context.Context, req *types.QuerySealRequest) (*types.QuerySealResponse, error) {
	if req.SealId == "" {
		return nil, fmt.Errorf("seal_id is required")
	}

	seal, err := q.Keeper.GetSeal(ctx, req.SealId)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealResponse{
		Seal: seal,
	}, nil
}

func (q queryServer) Seals(ctx context.Context, req *types.QuerySealsRequest) (*types.QuerySealsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	offset := int(req.Offset)
	if offset < 0 {
		offset = 0
	}

	seals, err := q.Keeper.ListSeals(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	total, err := q.Keeper.GetSealCount(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealsResponse{
		Seals: seals,
		Total: total,
	}, nil
}

func (q queryServer) SealsByModel(ctx context.Context, req *types.QuerySealsByModelRequest) (*types.QuerySealsByModelResponse, error) {
	if len(req.ModelHash) == 0 {
		return nil, fmt.Errorf("model_hash is required")
	}

	seals, err := q.Keeper.ListSealsByModel(ctx, req.ModelHash)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealsByModelResponse{
		Seals: seals,
	}, nil
}

func (q queryServer) SealsByRequester(ctx context.Context, req *types.QuerySealsByRequesterRequest) (*types.QuerySealsByRequesterResponse, error) {
	if req.Requester == "" {
		return nil, fmt.Errorf("requester is required")
	}

	seals, err := q.Keeper.ListSealsByRequester(ctx, req.Requester)
	if err != nil {
		return nil, err
	}

	return &types.QuerySealsByRequesterResponse{
		Seals: seals,
	}, nil
}

func (q queryServer) VerifySeal(ctx context.Context, req *types.QueryVerifySealRequest) (*types.QueryVerifySealResponse, error) {
	if req.SealId == "" {
		return nil, fmt.Errorf("seal_id is required")
	}

	seal, err := q.Keeper.GetSeal(ctx, req.SealId)
	if err != nil {
		return &types.QueryVerifySealResponse{
			Valid:            false,
			VerificationType: "none",
			Status:           "not_found",
		}, nil
	}

	valid, err := q.Keeper.VerifySeal(ctx, req.SealId)
	if err != nil {
		return nil, err
	}

	return &types.QueryVerifySealResponse{
		Valid:            valid,
		VerificationType: seal.GetVerificationType(),
		Status:           seal.Status.String(),
	}, nil
}

func (q queryServer) ExportSeal(ctx context.Context, req *types.QueryExportSealRequest) (*types.QueryExportSealResponse, error) {
	if req.SealId == "" {
		return nil, fmt.Errorf("seal_id is required")
	}

	format, err := parseQueryExportFormat(req.Format)
	if err != nil {
		return nil, err
	}

	valid, err := q.Keeper.VerifySeal(ctx, req.SealId)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("seal %s is not active or verified; export refused", req.SealId)
	}

	options := DefaultExportOptions()
	options.Format = format
	// Query exports are read-only evidence objects. The endpoint gates exports
	// with Keeper.VerifySeal above and leaves full verifier-backed export
	// signing/verification to configured internal callers.
	options.VerifyBeforeExport = false

	exporter := NewSealExporter(q.Keeper.logger, &q.Keeper, nil)
	exported, err := exporter.Export(ctx, req.SealId, options)
	if err != nil {
		return nil, err
	}

	exportStruct, err := jsonObjectStruct(exported)
	if err != nil {
		return nil, fmt.Errorf("failed to encode seal export: %w", err)
	}

	return &types.QueryExportSealResponse{
		Export: exportStruct,
	}, nil
}

func (q queryServer) EnterpriseEvidenceBundle(ctx context.Context, req *types.QueryEnterpriseEvidenceBundleRequest) (*types.QueryEnterpriseEvidenceBundleResponse, error) {
	if req.JobId == "" {
		return nil, fmt.Errorf("job_id is required")
	}

	bundle, err := ExportEnterpriseEvidenceBundle(ctx, &q.Keeper, req.JobId)
	if err != nil {
		return nil, err
	}

	bundleStruct, err := jsonObjectStruct(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to encode enterprise evidence bundle: %w", err)
	}

	return &types.QueryEnterpriseEvidenceBundleResponse{
		EvidenceBundle: bundleStruct,
	}, nil
}

func (q queryServer) Params(ctx context.Context, req *types.QueryParamsRequest) (*types.QueryParamsResponse, error) {
	params, err := q.Keeper.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	return &types.QueryParamsResponse{
		Params: params,
	}, nil
}

func parseQueryExportFormat(format string) (ExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", string(ExportFormatJSON):
		return ExportFormatJSON, nil
	case string(ExportFormatCompact):
		return ExportFormatCompact, nil
	case string(ExportFormatPortable):
		return ExportFormatPortable, nil
	case string(ExportFormatAudit):
		return ExportFormatAudit, nil
	default:
		return "", fmt.Errorf("unsupported export format %q; supported formats: json, compact, portable, audit", format)
	}
}

func jsonObjectStruct(value interface{}) (*structpb.Struct, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}

	return structpb.NewStruct(object)
}
