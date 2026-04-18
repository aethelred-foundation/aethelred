package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	cosmossdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/confidential"
	"github.com/aethelred/aethelred/pkg/enterprise/billing"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	financeintegration "github.com/aethelred/aethelred/pkg/integrations/finance"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	sealsdk "github.com/aethelred/aethelred/pkg/seal/sdk"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

const (
	financeTreasuryReleaseCollectionRoute = "/api/v1/finance/treasury/releases"
	financeTreasuryReleaseExportRoute     = "/api/v1/finance/treasury/releases/export"
	financeTreasuryReleaseItemPrefix      = "/api/v1/finance/treasury/releases/"
	financeTreasurySettlementQuoteRoute   = "/api/v1/finance/treasury/settlement-quote"
	financeTrustPackRoute                 = "/api/v1/finance/trust-pack"
	financeTrustPackExportRoute           = "/api/v1/finance/trust-pack/export"
)

type financeAPIErrorResponse struct {
	Error string `json:"error"`
}

type financeTreasuryReleaseInitiateRequest struct {
	Identity      json.RawMessage                       `json:"identity"`
	PolicyReceipt *policy.SignedPolicyReceipt           `json:"policy_receipt,omitempty"`
	Operation     *financeintegration.TreasuryOperation `json:"operation"`
	Resource      string                                `json:"resource,omitempty"`
	Jurisdiction  string                                `json:"jurisdiction,omitempty"`
	ReasonCode    string                                `json:"reason_code,omitempty"`
	Tool          string                                `json:"tool,omitempty"`
	Originator    financeintegration.ScreeningEntity    `json:"originator,omitempty"`
	Beneficiary   financeintegration.ScreeningEntity    `json:"beneficiary,omitempty"`
	Metadata      map[string]string                     `json:"metadata,omitempty"`
}

type financeTreasuryReleaseApproveRequest struct {
	Approver      string                      `json:"approver"`
	Comment       string                      `json:"comment,omitempty"`
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
}

type financeTreasuryReleaseResponse struct {
	Result *financeintegration.TreasuryReleaseResult `json:"result,omitempty"`
	Error  string                                    `json:"error,omitempty"`
}

type financeTreasuryReleaseListResponse struct {
	Items []financeintegration.TreasuryReleaseSummary `json:"items,omitempty"`
}

type financeTreasurySettlementQuoteResponse struct {
	Quote *financeintegration.TreasurySettlementQuote `json:"quote,omitempty"`
	Error string                                      `json:"error,omitempty"`
}

type financeTrustPackResponse struct {
	Pack *financeintegration.FinanceTrustPack `json:"pack,omitempty"`
}

type financeTreasuryReleaseSettlementResponse struct {
	WorkflowID          string                                           `json:"workflow_id"`
	Status              financeintegration.TreasuryReleaseWorkflowStatus `json:"status"`
	Ready               bool                                             `json:"ready"`
	ApprovalStatus      *financeintegration.ApprovalStatus               `json:"approval_status,omitempty"`
	ConfidentialExecution *confidential.VerificationSummary              `json:"confidential_execution,omitempty"`
	Settlement          *evidence.ValueSettlementEvidence                `json:"settlement,omitempty"`
	SettlementReceipt   *policy.SignedPolicyReceipt                      `json:"settlement_receipt,omitempty"`
	ExecutionSealID     string                                           `json:"execution_seal_id,omitempty"`
	ControlLedgerID     string                                           `json:"control_ledger_id,omitempty"`
	PortablePackageHash string                                           `json:"portable_package_hash,omitempty"`
}

type financeTreasuryReleaseSettlementArtifactsResponse struct {
	WorkflowID               string                                           `json:"workflow_id"`
	Status                   financeintegration.TreasuryReleaseWorkflowStatus `json:"status"`
	ConfidentialExecution    *confidential.VerificationSummary                `json:"confidential_execution,omitempty"`
	ExecutionAttestations    []evidence.Attestation                           `json:"execution_attestations,omitempty"`
	Settlement               *evidence.ValueSettlementEvidence                `json:"settlement,omitempty"`
	SettlementReceipt        *policy.SignedPolicyReceipt                      `json:"settlement_receipt,omitempty"`
	ExecutionSeal            *evidence.Seal                                   `json:"execution_seal,omitempty"`
	ControlLedgerID          string                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash string                                           `json:"control_ledger_content_hash,omitempty"`
	ControlSummary           *evidence.ControlLedgerSummary                   `json:"control_summary,omitempty"`
	PortablePackageHash      string                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned    bool                                             `json:"portable_package_signed"`
	PortablePackageAnchored  bool                                             `json:"portable_package_anchored"`
}

type appFinanceTreasuryReleaseSealer struct {
	app         *AethelredApp
	requestedBy string
}

func (s *appFinanceTreasuryReleaseSealer) CreateSeal(_ context.Context, req sealsdk.SealRequest) (*sealsdk.SealResponse, error) {
	if s == nil || s.app == nil {
		return nil, fmt.Errorf("finance treasury release sealer is unavailable")
	}
	ctx := safeAuditKeeperContext(s.app)
	if ctx == nil {
		return nil, fmt.Errorf("finance treasury release sealer has no keeper context")
	}
	sdkCtx, ok := ctx.(cosmossdk.Context)
	if !ok {
		return nil, fmt.Errorf("finance treasury release sealer could not unwrap sdk context")
	}
	if sdkCtx.BlockHeight() <= 0 {
		sdkCtx = sdkCtx.WithBlockHeight(1)
		ctx = sdkCtx
	}

	requestedBy := strings.TrimSpace(s.requestedBy)
	if requestedBy == "" {
		requestedBy = authtypes.NewModuleAddress(pouwtypes.ModuleName).String()
	}
	seal := sealtypes.NewDigitalSeal(req.ModelHash, req.InputHash, req.OutputHash, sdkCtx.BlockHeight(), requestedBy, req.Purpose)
	if req.ZKProof != nil {
		seal.SetZKProof(req.ZKProof)
	}
	for _, attestation := range req.TEEAttestations {
		seal.AddAttestation(attestation)
	}
	if seal.IsVerified() {
		seal.Activate()
	}
	if err := s.app.SealKeeper.CreateSeal(ctx, seal); err != nil {
		return nil, err
	}
	return &sealsdk.SealResponse{
		SealID:         seal.Id,
		Status:         seal.Status,
		Attestations:   append([]*sealtypes.TEEAttestation(nil), seal.TeeAttestations...),
		Proof:          seal.ZkProof,
		Timestamp:      seal.Timestamp.AsTime().UTC(),
		RegulatoryInfo: seal.RegulatoryInfo,
		BlockHeight:    seal.BlockHeight,
		RequestedBy:    seal.RequestedBy,
		Purpose:        seal.Purpose,
		ValidatorSet:   append([]string(nil), seal.ValidatorSet...),
	}, nil
}

func (app *AethelredApp) initFinanceInfrastructure(appOpts servertypes.AppOptions) {
	controlLedgerDir := resolveFinanceControlLedgerDir(appOpts)
	ledgerStore, err := evidence.NewFileControlLedgerStore(controlLedgerDir)
	if err != nil {
		app.Logger().Error("Finance API initialization failed while creating the control-ledger store",
			"error", err,
			"control_ledger_dir", controlLedgerDir,
		)
		return
	}
	workflowStoreDir := resolveFinanceWorkflowStoreDir(appOpts)
	workflowStore, err := financeintegration.NewFileTreasuryReleaseStore(workflowStoreDir)
	if err != nil {
		app.Logger().Error("Finance API initialization failed while creating the workflow store",
			"error", err,
			"workflow_store_dir", workflowStoreDir,
		)
		return
	}

	policySignerKey, policySigner, signerMode, signerMessage, err := resolveFinancePolicySigner(appOpts)
	if err != nil {
		app.Logger().Error("Finance API initialization failed while resolving the finance policy signer", "error", err)
		return
	}
	requestedBy := firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.signer_address")), cast.ToString(appOpts.Get("finance.signer_address")), app.PouwKeeper.GetAuthority(), authtypes.NewModuleAddress(pouwtypes.ModuleName).String())
	confidentialKeys := map[string]*ecdsa.PublicKey{
		policySigner: &policySignerKey.PublicKey,
	}
	confidentialPolicy := resolveConfidentialExecutionPolicy(appOpts, "aethelred.finance", "finance", app.teeClient != nil, confidentialKeys)

	workflow, err := financeintegration.NewTreasuryReleaseWorkflow(financeintegration.TreasuryReleaseWorkflowConfig{
		Controller:      financeintegration.NewTreasuryController(resolveFinanceApprovalPolicy(appOpts)),
		Sanctions:       financeintegration.NewSanctionsService(resolveFinanceSanctionsConfig(appOpts)),
		AuditTrail:      financeintegration.NewFinancialAuditTrail(),
		PolicySignerKey: policySignerKey,
		PolicySigner:    policySigner,
		Sealer: &appFinanceTreasuryReleaseSealer{
			app:         app,
			requestedBy: requestedBy,
		},
		LedgerStore:            ledgerStore,
		WorkflowStore:          workflowStore,
		SettlementRail:         resolveFinanceSettlementRail(appOpts),
		Framework:              "SOX Treasury Release",
		ConfidentialAttestor:   newWorkflowTEEAttestor(app, "treasury_release", policySigner, policySignerKey),
		ConfidentialPolicy:     confidentialPolicy,
		PackageSignerFunc: func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return pkg.SignEd25519(privateKey, signer)
		},
		PackageAnchorer: func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
			anchor := anchorPortableControlLedgerPackage(app, pkg)
			if anchor == nil {
				return nil
			}
			pkg.AuditAnchor = anchor
			return nil
		},
	})
	if err != nil {
		app.Logger().Error("Finance API initialization failed while constructing the treasury release workflow", "error", err)
		return
	}

	app.financeTreasuryReleaseWorkflow = workflow
	financeAuth, authMode, authMessage := resolveFinanceTreasuryReleaseAuthorizer(app, appOpts)
	app.financeTreasuryReleaseAuth = financeAuth
	app.financeControlLedgerDir = controlLedgerDir
	if signerMode == "ephemeral" {
		app.Logger().Warn("Finance API initialized with an ephemeral policy signer",
			"control_ledger_dir", controlLedgerDir,
			"workflow_store_dir", workflowStoreDir,
			"policy_signer", policySigner,
			"policy_signer_mode", signerMode,
			"policy_signer_message", signerMessage,
			"write_auth_mode", authMode,
			"write_auth_message", authMessage,
		)
		return
	}
	app.Logger().Info("Finance API initialized",
		"control_ledger_dir", controlLedgerDir,
		"workflow_store_dir", workflowStoreDir,
		"policy_signer", policySigner,
		"policy_signer_mode", signerMode,
		"policy_signer_message", signerMessage,
		"write_auth_mode", authMode,
		"write_auth_message", authMessage,
	)
}

// FinanceTreasurySettlementQuoteHandler previews settlement admissibility
// without mutating workflow state.
func (app *AethelredApp) FinanceTreasurySettlementQuoteHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}

		var req financeTreasuryReleaseInitiateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, "invalid treasury settlement quote request: "+err.Error())
			return
		}
		authCtx, err := app.authorizeFinanceTreasuryReleaseInitiate(r, &req)
		if err != nil {
			writeFinanceAPIError(w, financeAuthorizationStatus(err, http.StatusForbidden), err.Error())
			return
		}
		identity, err := decodeFinanceAgentIdentity(req.Identity)
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Metadata = financeRequestMetadataWithAuthContext(req.Metadata, authCtx)
		quote, err := app.financeTreasuryReleaseWorkflow.PreviewSettlement(r.Context(), financeintegration.TreasuryReleaseRequest{
			Identity:     identity,
			Operation:    req.Operation,
			Resource:     req.Resource,
			Jurisdiction: req.Jurisdiction,
			ReasonCode:   req.ReasonCode,
			Tool:         req.Tool,
			Originator:   req.Originator,
			Beneficiary:  req.Beneficiary,
			Metadata:     req.Metadata,
		})
		if err != nil {
			writeFinanceAPIError(w, financeErrorStatus(err, http.StatusBadRequest), err.Error())
			return
		}
		writeFinanceJSON(w, http.StatusOK, financeTreasurySettlementQuoteResponse{Quote: quote})
	})
}

// FinanceTreasuryReleaseCollectionHandler returns operator summaries over
// persisted treasury releases.
func (app *AethelredApp) FinanceTreasuryReleaseCollectionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}
		filter, err := financeReleaseListFilterFromRequest(r)
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.financeTreasuryReleaseWorkflow.ListReleases(r.Context(), filter)
		if err != nil {
			writeFinanceAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeFinanceJSON(w, http.StatusOK, financeTreasuryReleaseListResponse{Items: items})
	})
}

// FinanceTrustPackHandler returns the buyer-facing finance trust-pack summary.
func (app *AethelredApp) FinanceTrustPackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}
		pack, err := app.financeTreasuryReleaseWorkflow.BuildTrustPack(r.Context(), financeintegration.FinanceTrustPackOptions{
			OperatorSurfaces: financeTrustPackOperatorSurfaces(),
		})
		if err != nil {
			writeFinanceAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeFinanceJSON(w, http.StatusOK, financeTrustPackResponse{Pack: pack})
	})
}

// FinanceTreasuryReleaseInitiateHandler starts the treasury release workflow.
func (app *AethelredApp) FinanceTreasuryReleaseInitiateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}

		var req financeTreasuryReleaseInitiateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, "invalid treasury release request: "+err.Error())
			return
		}
		authCtx, err := app.authorizeFinanceTreasuryReleaseInitiate(r, &req)
		if err != nil {
			writeFinanceAPIError(w, financeAuthorizationStatus(err, http.StatusForbidden), err.Error())
			return
		}
		identity, err := decodeFinanceAgentIdentity(req.Identity)
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Metadata = financeRequestMetadataWithAuthContext(req.Metadata, authCtx)

		result, err := app.financeTreasuryReleaseWorkflow.InitiateRelease(r.Context(), financeintegration.TreasuryReleaseRequest{
			Identity:     identity,
			Operation:    req.Operation,
			Resource:     req.Resource,
			Jurisdiction: req.Jurisdiction,
			ReasonCode:   req.ReasonCode,
			Tool:         req.Tool,
			Originator:   req.Originator,
			Beneficiary:  req.Beneficiary,
			Metadata:     req.Metadata,
		})

		switch {
		case err == nil:
			status := http.StatusCreated
			if result != nil && result.Status == financeintegration.ReleaseStatusPendingApproval {
				status = http.StatusAccepted
			}
			writeFinanceJSON(w, status, financeTreasuryReleaseResponse{Result: result})
		case result != nil:
			status := financeErrorStatus(err, http.StatusForbidden)
			writeFinanceJSON(w, status, financeTreasuryReleaseResponse{Result: result, Error: err.Error()})
		default:
			writeFinanceAPIError(w, financeErrorStatus(err, http.StatusBadRequest), err.Error())
		}
	})
}

// FinanceTreasuryReleaseGetHandler returns the current workflow state.
func (app *AethelredApp) FinanceTreasuryReleaseGetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}

		workflowID, err := parseFinanceWorkflowID(r.URL.Path, "")
		if strings.HasSuffix(r.URL.Path, "/settlement/artifacts") {
			workflowID, err = parseFinanceWorkflowID(r.URL.Path, "/settlement/artifacts")
			if err != nil {
				writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.financeTreasuryReleaseWorkflow.GetRelease(r.Context(), workflowID)
			if err != nil {
				writeFinanceAPIError(w, financeErrorStatus(err, http.StatusNotFound), err.Error())
				return
			}
			writeFinanceJSON(w, http.StatusOK, financeSettlementArtifactsProjection(result))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/settlement") {
			workflowID, err = parseFinanceWorkflowID(r.URL.Path, "/settlement")
			if err != nil {
				writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.financeTreasuryReleaseWorkflow.GetRelease(r.Context(), workflowID)
			if err != nil {
				writeFinanceAPIError(w, financeErrorStatus(err, http.StatusNotFound), err.Error())
				return
			}
			writeFinanceJSON(w, http.StatusOK, financeSettlementProjection(result))
			return
		}
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		result, err := app.financeTreasuryReleaseWorkflow.GetRelease(r.Context(), workflowID)
		if err != nil {
			writeFinanceAPIError(w, financeErrorStatus(err, http.StatusNotFound), err.Error())
			return
		}
		writeFinanceJSON(w, http.StatusOK, financeTreasuryReleaseResponse{Result: result})
	})
}

// FinanceTreasuryReleaseApproveHandler records an approval for a pending workflow.
func (app *AethelredApp) FinanceTreasuryReleaseApproveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeFinanceAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.financeTreasuryReleaseWorkflow == nil {
			writeFinanceAPIError(w, http.StatusServiceUnavailable, "finance treasury release workflow is unavailable")
			return
		}

		workflowID, err := parseFinanceWorkflowID(r.URL.Path, "/approve")
		if err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		var req financeTreasuryReleaseApproveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeFinanceAPIError(w, http.StatusBadRequest, "invalid treasury approval request: "+err.Error())
			return
		}
		authCtx, err := app.authorizeFinanceTreasuryReleaseApprove(r, workflowID, &req)
		if err != nil {
			writeFinanceAPIError(w, financeAuthorizationStatus(err, http.StatusForbidden), err.Error())
			return
		}
		approver := strings.TrimSpace(req.Approver)
		if approver == "" && authCtx != nil && authCtx.ActorDID != "" {
			approver = authCtx.ActorDID
		}
		comment := financeApprovalCommentWithAuthContext(req.Comment, authCtx)
		result, err := app.financeTreasuryReleaseWorkflow.ApproveReleaseWithAuthorization(r.Context(), workflowID, financeintegration.TreasuryReleaseApprovalRequest{
			Approver:      approver,
			Comment:       comment,
			ActorIdentity: authCtx.ActorIdentity,
			PolicyReceipt: authCtx.PolicyReceipt,
			Metadata:      financeApprovalMetadataWithAuthContext(nil, authCtx),
		})
		if err != nil {
			writeFinanceAPIError(w, financeErrorStatus(err, http.StatusConflict), err.Error())
			return
		}
		writeFinanceJSON(w, http.StatusOK, financeTreasuryReleaseResponse{Result: result})
	})
}

func resolveFinanceControlLedgerDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.control_ledger_dir")),
		cast.ToString(appOpts.Get("finance.control_ledger_dir")),
		os.Getenv("AETHELRED_FINANCE_CONTROL_LEDGER_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "finance", "control-ledgers"))
	}
	return filepath.Join(homePath, "data", "finance", "control-ledgers")
}

func resolveFinanceWorkflowStoreDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.workflow_store_dir")),
		cast.ToString(appOpts.Get("finance.workflow_store_dir")),
		os.Getenv("AETHELRED_FINANCE_WORKFLOW_STORE_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "finance", "workflows"))
	}
	return filepath.Join(homePath, "data", "finance", "workflows")
}

func resolveFinanceApprovalPolicy(appOpts servertypes.AppOptions) financeintegration.ApprovalPolicy {
	policy := financeintegration.ApprovalPolicy{
		SingleThreshold:       cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.approval.single_threshold")), cast.ToString(appOpts.Get("finance.approval.single_threshold")))),
		DualThreshold:         cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.approval.dual_threshold")), cast.ToString(appOpts.Get("finance.approval.dual_threshold")))),
		CommitteeThreshold:    cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.approval.committee_threshold")), cast.ToString(appOpts.Get("finance.approval.committee_threshold")))),
		RequiredCommitteeSize: cast.ToInt(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.approval.committee_size")), cast.ToString(appOpts.Get("finance.approval.committee_size")))),
	}
	if policy.SingleThreshold == 0 {
		policy.SingleThreshold = 10000
	}
	if policy.DualThreshold == 0 {
		policy.DualThreshold = 50000
	}
	if policy.CommitteeThreshold == 0 {
		policy.CommitteeThreshold = 500000
	}
	if policy.RequiredCommitteeSize == 0 {
		policy.RequiredCommitteeSize = 3
	}
	return policy
}

func resolveFinanceSanctionsConfig(appOpts servertypes.AppOptions) financeintegration.SanctionsConfig {
	config := financeintegration.SanctionsConfig{
		BlockOnMatch:   true,
		MatchThreshold: cast.ToInt(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.sanctions.match_threshold")), cast.ToString(appOpts.Get("finance.sanctions.match_threshold")))),
	}
	if raw := firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.sanctions.block_on_match")), cast.ToString(appOpts.Get("finance.sanctions.block_on_match")), os.Getenv("AETHELRED_FINANCE_SANCTIONS_BLOCK_ON_MATCH")); raw != "" {
		config.BlockOnMatch = cast.ToBool(raw)
	}
	return config
}

func resolveFinanceSettlementRail(appOpts servertypes.AppOptions) financeintegration.TreasurySettlementRail {
	config := financeintegration.PolicyBoundSettlementConfig{
		ProviderID:            firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.provider_id")), cast.ToString(appOpts.Get("finance.settlement.provider_id")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_PROVIDER_ID")),
		ProviderStatus:        firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.provider_status")), cast.ToString(appOpts.Get("finance.settlement.provider_status")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_PROVIDER_STATUS"), "active"),
		CorridorID:            firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.corridor_id")), cast.ToString(appOpts.Get("finance.settlement.corridor_id")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_CORRIDOR_ID")),
		Network:               firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.network")), cast.ToString(appOpts.Get("finance.settlement.network")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_NETWORK")),
		Method:                firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.method")), cast.ToString(appOpts.Get("finance.settlement.method")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_METHOD")),
		CustomerID:            firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.customer_id")), cast.ToString(appOpts.Get("finance.settlement.customer_id")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_CUSTOMER_ID")),
		FiatCurrency:          firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.fiat_currency")), cast.ToString(appOpts.Get("finance.settlement.fiat_currency")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_FIAT_CURRENCY")),
		TokenDenomination:     firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.token_denomination")), cast.ToString(appOpts.Get("finance.settlement.token_denomination")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_TOKEN_DENOMINATION")),
		ExchangeRate:          cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.exchange_rate")), cast.ToString(appOpts.Get("finance.settlement.exchange_rate")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_EXCHANGE_RATE"))),
		MaxFiatAmount:         cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.max_amount")), cast.ToString(appOpts.Get("finance.settlement.max_amount")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_MAX_AMOUNT"))),
		AllowedCounterparties: parseFinanceCSVValues(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.allowed_counterparties")), cast.ToString(appOpts.Get("finance.settlement.allowed_counterparties")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_ALLOWED_COUNTERPARTIES"))),
		AllowedJurisdictions:  parseFinanceCSVValues(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.allowed_jurisdictions")), cast.ToString(appOpts.Get("finance.settlement.allowed_jurisdictions")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_ALLOWED_JURISDICTIONS"))),
		AllowedCurrencies:     parseFinanceCSVValues(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.allowed_currencies")), cast.ToString(appOpts.Get("finance.settlement.allowed_currencies")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_ALLOWED_CURRENCIES"))),
		RequiredReasonCodes:   parseFinanceCSVValues(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.required_reason_codes")), cast.ToString(appOpts.Get("finance.settlement.required_reason_codes")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_REQUIRED_REASON_CODES"))),
	}

	budgetLimit := cast.ToFloat64(firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.budget_limit")), cast.ToString(appOpts.Get("finance.settlement.budget_limit")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_BUDGET_LIMIT")))
	if budgetLimit > 0 && strings.TrimSpace(config.CustomerID) != "" {
		spendController := billing.NewSpendController()
		budget, err := spendController.SetBudget(context.Background(), billing.Budget{
			CustomerID: config.CustomerID,
			Limit:      budgetLimit,
			Currency:   firstNonEmpty(cast.ToString(appOpts.Get("aethelred.finance.settlement.budget_currency")), cast.ToString(appOpts.Get("finance.settlement.budget_currency")), os.Getenv("AETHELRED_FINANCE_SETTLEMENT_BUDGET_CURRENCY"), config.FiatCurrency, "USD"),
			Period:     billing.Monthly,
			AlertThresholds: []billing.AlertThreshold{
				{Percent: 80, Action: billing.Notify},
				{Percent: 100, Action: billing.Block},
			},
		})
		if err == nil && budget != nil {
			config.SpendController = spendController
			config.BudgetID = budget.ID
		}
	}

	return financeintegration.NewPolicyBoundSettlementRail(config)
}

func resolveFinancePolicySigner(appOpts servertypes.AppOptions) (*ecdsa.PrivateKey, string, string, string, error) {
	signer := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.policy_signer")),
		cast.ToString(appOpts.Get("finance.policy_signer")),
		os.Getenv("AETHELRED_FINANCE_POLICY_SIGNER"),
	)
	if strings.TrimSpace(signer) == "" {
		signer = "did:aethelred:policy-gateway-finance"
	}

	keyHex := strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.finance.policy_signer_key")),
		cast.ToString(appOpts.Get("finance.policy_signer_key")),
		os.Getenv("AETHELRED_FINANCE_POLICY_SIGNER_KEY"),
	))
	if keyHex == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", "", "", err
		}
		return key, signer, "ephemeral", "generated an ephemeral finance policy signer because no configured signer key was provided", nil
	}

	key, err := parseFinanceECDSAPrivateKeyHex(keyHex)
	if err != nil {
		return nil, "", "", "", err
	}
	return key, signer, "configured", "loaded finance policy signer from configuration", nil
}

func parseFinanceECDSAPrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "0x"))
	keyBytes, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid finance policy signer key encoding: %w", err)
	}
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("finance policy signer key is empty")
	}

	curve := elliptic.P256()
	d := new(big.Int).SetBytes(keyBytes)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, fmt.Errorf("finance policy signer key is out of range for P-256")
	}
	x, y := curve.ScalarBaseMult(keyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("finance policy signer key could not derive a public key")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func parseFinanceWorkflowID(path, suffix string) (string, error) {
	if !strings.HasPrefix(path, financeTreasuryReleaseItemPrefix) {
		return "", fmt.Errorf("invalid treasury release path")
	}
	remainder := strings.TrimPrefix(path, financeTreasuryReleaseItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", fmt.Errorf("invalid treasury release action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	remainder = strings.Trim(remainder, "/")
	if remainder == "" || strings.Contains(remainder, "/") {
		return "", fmt.Errorf("invalid treasury release workflow ID")
	}
	return remainder, nil
}

func decodeFinanceAgentIdentity(raw json.RawMessage) (*agent.AgentIdentity, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("identity is required")
	}
	var identity agent.AgentIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		return nil, fmt.Errorf("invalid identity payload: %w", err)
	}
	return &identity, nil
}

func financeErrorStatus(err error, fallback int) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, audit.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, audit.ErrWriteDisabled):
		return http.StatusServiceUnavailable
	case errors.Is(err, financeintegration.ErrReleaseNotFound):
		return http.StatusNotFound
	case errors.Is(err, financeintegration.ErrSanctionsMatch),
		errors.Is(err, financeintegration.ErrPolicyDenied),
		errors.Is(err, financeintegration.ErrSettlementDenied),
		errors.Is(err, financeintegration.ErrSettlementJurisdictionDenied),
		errors.Is(err, financeintegration.ErrSettlementCurrencyDenied),
		errors.Is(err, financeintegration.ErrSettlementReasonRequired):
		return http.StatusForbidden
	case errors.Is(err, financeintegration.ErrSettlementProviderUnavailable), errors.Is(err, financeintegration.ErrSettlementRailUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, financeintegration.ErrSettlementAmountExceeded):
		return http.StatusConflict
	case errors.Is(err, financeintegration.ErrReleaseRejected), errors.Is(err, financeintegration.ErrInsufficientApproval):
		return http.StatusConflict
	case errors.Is(err, financeintegration.ErrSelfApproval):
		return http.StatusForbidden
	default:
		return fallback
	}
}

func writeFinanceAPIError(w http.ResponseWriter, status int, message string) {
	writeFinanceJSON(w, status, financeAPIErrorResponse{Error: message})
}

func writeFinanceJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseFinanceCSVValues(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func financeSettlementProjection(result *financeintegration.TreasuryReleaseResult) financeTreasuryReleaseSettlementResponse {
	if result == nil {
		return financeTreasuryReleaseSettlementResponse{}
	}
	resp := financeTreasuryReleaseSettlementResponse{
		WorkflowID:            result.WorkflowID,
		Status:                result.Status,
		Ready:                 result.Settlement != nil && result.SettlementReceipt != nil && result.ExecutionSeal != nil,
		ApprovalStatus:        result.ApprovalStatus,
		ConfidentialExecution: result.ConfidentialExecution,
		Settlement:            result.Settlement,
		SettlementReceipt:     result.SettlementReceipt,
	}
	if result.ExecutionSeal != nil {
		resp.ExecutionSealID = result.ExecutionSeal.SealID
	}
	if result.ControlLedger != nil && result.ControlLedger.Bundle != nil {
		resp.ControlLedgerID = result.ControlLedger.Bundle.ID
	}
	if result.PortablePackage != nil {
		resp.PortablePackageHash = result.PortablePackage.PackageHash
	}
	return resp
}

func financeSettlementArtifactsProjection(result *financeintegration.TreasuryReleaseResult) financeTreasuryReleaseSettlementArtifactsResponse {
	if result == nil {
		return financeTreasuryReleaseSettlementArtifactsResponse{}
	}
	resp := financeTreasuryReleaseSettlementArtifactsResponse{
		WorkflowID:            result.WorkflowID,
		Status:                result.Status,
		ConfidentialExecution: result.ConfidentialExecution,
		ExecutionAttestations: append([]evidence.Attestation(nil), result.ExecutionAttestations...),
		Settlement:            result.Settlement,
		SettlementReceipt:     result.SettlementReceipt,
		ExecutionSeal:         result.ExecutionSeal,
	}
	if result.ControlLedger != nil {
		resp.ControlSummary = &result.ControlLedger.Summary
		if result.ControlLedger.Bundle != nil {
			resp.ControlLedgerID = result.ControlLedger.Bundle.ID
			resp.ControlLedgerContentHash = result.ControlLedger.Bundle.ContentHash
		}
	}
	if result.PortablePackage != nil {
		resp.PortablePackageHash = result.PortablePackage.PackageHash
		resp.PortablePackageSigned = result.PortablePackage.Signature != nil
		resp.PortablePackageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	return resp
}
