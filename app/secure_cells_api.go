package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	cosmossdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
	sealsdk "github.com/aethelred/aethelred/pkg/seal/sdk"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

const (
	secureCellsCollectionRoute = "/api/v1/secure-cells"
	secureCellsItemPrefix      = "/api/v1/secure-cells/"
)

type secureCellAPIErrorResponse struct {
	Error string `json:"error"`
}

type secureCellCreateRequest struct {
	Identity      json.RawMessage                                `json:"identity"`
	PolicyReceipt *policy.SignedPolicyReceipt                    `json:"policy_receipt,omitempty"`
	Name          string                                         `json:"name"`
	Purpose       string                                         `json:"purpose"`
	Resource      string                                         `json:"resource,omitempty"`
	Jurisdiction  string                                         `json:"jurisdiction,omitempty"`
	Participants  []securecellsintegration.SecureCellParticipant `json:"participants,omitempty"`
	Policy        securecellsintegration.SecureCellPolicy        `json:"policy"`
	Metadata      map[string]string                              `json:"metadata,omitempty"`
}

type secureCellAdmitMemberRequest struct {
	ActorIdentity json.RawMessage                              `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                  `json:"policy_receipt,omitempty"`
	Participant   securecellsintegration.SecureCellParticipant `json:"participant"`
	Reason        string                                       `json:"reason,omitempty"`
	Metadata      map[string]string                            `json:"metadata,omitempty"`
}

type secureCellMemberMutationRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDID      string                      `json:"participant_did,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time                  `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellLifecycleRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	EffectiveAt   *time.Time                  `json:"effective_at,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellBulkMemberMutationRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDIDs     []string                    `json:"participant_dids,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time                  `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellResponse struct {
	Result *securecellsintegration.SecureCellResult `json:"result,omitempty"`
	Error  string                                   `json:"error,omitempty"`
}

type secureCellArtifactsResponse struct {
	CellID                   string                                              `json:"cell_id"`
	Status                   securecellsintegration.SecureCellStatus             `json:"status"`
	Participants             []securecellsintegration.SecureCellParticipantState `json:"participants,omitempty"`
	Transitions              []securecellsintegration.SecureCellTransition       `json:"transitions,omitempty"`
	CreationReceipt          *policy.SignedPolicyReceipt                         `json:"creation_receipt,omitempty"`
	ActivationReceipt        *policy.SignedPolicyReceipt                         `json:"activation_receipt,omitempty"`
	ExecutionSeal            *evidence.Seal                                      `json:"execution_seal,omitempty"`
	ControlLedgerID          string                                              `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash string                                              `json:"control_ledger_content_hash,omitempty"`
	ControlSummary           *evidence.ControlLedgerSummary                      `json:"control_summary,omitempty"`
	PortablePackageHash      string                                              `json:"portable_package_hash,omitempty"`
	PortablePackageSigned    bool                                                `json:"portable_package_signed"`
	PortablePackageAnchored  bool                                                `json:"portable_package_anchored"`
}

type secureCellListResponse struct {
	Items []securecellsintegration.SecureCellSummary `json:"items"`
}

type secureCellQuarantineExpiryListResponse struct {
	Items []securecellsintegration.SecureCellQuarantineExpiry `json:"items"`
}

type secureCellBulkMutationResponse struct {
	Result *securecellsintegration.SecureCellBulkMemberTransitionResult `json:"result,omitempty"`
}

type secureCellEventListResponse struct {
	Items []secureCellAuditEventRecord `json:"items"`
}

type secureCellWebhookDeliveryListResponse struct {
	Items []secureCellWebhookDeliveryRecord `json:"items"`
}

type appSecureCellSealer struct {
	app         *AethelredApp
	requestedBy string
}

func (s *appSecureCellSealer) CreateSeal(_ context.Context, req sealsdk.SealRequest) (*sealsdk.SealResponse, error) {
	if s == nil || s.app == nil {
		return nil, fmt.Errorf("secure cells sealer is unavailable")
	}
	ctx := safeAuditKeeperContext(s.app)
	if ctx == nil {
		return nil, fmt.Errorf("secure cells sealer has no keeper context")
	}
	sdkCtx, ok := ctx.(cosmossdk.Context)
	if !ok {
		return nil, fmt.Errorf("secure cells sealer could not unwrap sdk context")
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

func (app *AethelredApp) initSecureCellsInfrastructure(appOpts servertypes.AppOptions) {
	controlLedgerDir := resolveSecureCellControlLedgerDir(appOpts)
	ledgerStore, err := evidence.NewFileControlLedgerStore(controlLedgerDir)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while creating the control-ledger store",
			"error", err,
			"control_ledger_dir", controlLedgerDir,
		)
		return
	}

	policySignerKey, policySigner, signerMode, signerMessage, err := resolveSecureCellPolicySigner(appOpts)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while resolving the secure-cell policy signer", "error", err)
		return
	}

	webhookConfig := resolveSecureCellWebhookConfig(appOpts)
	secureCellRuntime := newSecureCellLifecycleRuntime(app, webhookConfig)
	service, err := securecellsintegration.NewService(securecellsintegration.ServiceConfig{
		PolicySignerKey:     policySignerKey,
		PolicySigner:        policySigner,
		CredentialIssuerKey: policySignerKey,
		CredentialIssuer:    policySigner,
		Sealer: &appSecureCellSealer{
			app:         app,
			requestedBy: firstNonEmpty(cast.ToString(appOpts.Get("aethelred.secure_cells.signer_address")), cast.ToString(appOpts.Get("secure_cells.signer_address")), app.PouwKeeper.GetAuthority(), authtypes.NewModuleAddress(pouwtypes.ModuleName).String()),
		},
		LedgerStore: ledgerStore,
		Framework:   "Secure Cells v1",
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
		EventPublisher: secureCellRuntime.Publish,
	})
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while constructing the lifecycle runtime-backed service", "error", err)
		return
	}

	app.secureCellService = service
	secureCellAuth, authMode, authMessage := resolveSecureCellAuthorizer(app, appOpts)
	app.secureCellAuth = secureCellAuth
	app.secureCellControlLedgerDir = controlLedgerDir
	app.secureCellRuntime = secureCellRuntime
	app.secureCellExpirySweeper = newSecureCellExpirySweeper(app, service, resolveSecureCellExpirySweepInterval(appOpts))
	if signerMode == "ephemeral" {
		app.Logger().Warn("Secure Cells API initialized with an ephemeral policy signer",
			"control_ledger_dir", controlLedgerDir,
			"policy_signer", policySigner,
			"policy_signer_mode", signerMode,
			"policy_signer_message", signerMessage,
			"write_auth_mode", authMode,
			"write_auth_message", authMessage,
			"webhook_endpoints", len(webhookConfig.Endpoints),
			"expiry_sweep_interval", resolveSecureCellExpirySweepInterval(appOpts),
		)
		return
	}
	app.Logger().Info("Secure Cells API initialized",
		"control_ledger_dir", controlLedgerDir,
		"policy_signer", policySigner,
		"policy_signer_mode", signerMode,
		"policy_signer_message", signerMessage,
		"write_auth_mode", authMode,
		"write_auth_message", authMessage,
		"webhook_endpoints", len(webhookConfig.Endpoints),
		"expiry_sweep_interval", resolveSecureCellExpirySweepInterval(appOpts),
	)
}

func (app *AethelredApp) SecureCellsCreateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		var req secureCellCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell request: "+err.Error())
			return
		}

		authCtx, err := app.authorizeSecureCellCreate(r, &req)
		if err != nil {
			writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
			return
		}

		identity, err := decodeFinanceAgentIdentity(req.Identity)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
		result, err := app.secureCellService.CreateCell(r.Context(), securecellsintegration.SecureCellRequest{
			OwnerIdentity: identity,
			Name:          req.Name,
			Purpose:       req.Purpose,
			Resource:      req.Resource,
			Jurisdiction:  req.Jurisdiction,
			Participants:  req.Participants,
			Policy:        req.Policy,
			Metadata:      req.Metadata,
		})
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
			return
		}
		if result != nil && result.Status == securecellsintegration.SecureCellStatusRejected {
			writeSecureCellJSON(w, http.StatusForbidden, secureCellResponse{Result: result, Error: result.RejectionReason})
			return
		}
		writeSecureCellJSON(w, http.StatusCreated, secureCellResponse{Result: result})
	})
}

func (app *AethelredApp) SecureCellsCollectionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}
		filter, err := parseSecureCellListFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.secureCellService.ListCells(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellListResponse{Items: items})
	})
}

func (app *AethelredApp) SecureCellsExpiringQuarantinesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}
		before, err := parseSecureCellOptionalTime(r.URL.Query().Get("before"))
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.secureCellService.ListExpiringQuarantines(r.Context(), derefSecureCellTime(before))
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellQuarantineExpiryListResponse{Items: items})
	})
}

func (app *AethelredApp) SecureCellsGetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		if r.URL.Path == secureCellsItemPrefix+"events" || r.URL.Path == secureCellsCollectionRoute+"/events" {
			filter := secureCellAuditEventFilter{
				CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
				ParticipantDID: strings.TrimSpace(r.URL.Query().Get("participant_did")),
				Action:         strings.TrimSpace(r.URL.Query().Get("action")),
				Actor:          strings.TrimSpace(r.URL.Query().Get("actor")),
				SinceSequence:  cast.ToUint64(strings.TrimSpace(r.URL.Query().Get("since_sequence"))),
				Limit:          cast.ToInt(strings.TrimSpace(r.URL.Query().Get("limit"))),
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellEventListResponse{Items: listSecureCellAuditEvents(app, filter)})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/webhook-deliveries" {
			if app.secureCellRuntime == nil {
				writeSecureCellJSON(w, http.StatusOK, secureCellWebhookDeliveryListResponse{Items: nil})
				return
			}
			filter := secureCellWebhookDeliveryFilter{
				CellID:   strings.TrimSpace(r.URL.Query().Get("cell_id")),
				EventID:  strings.TrimSpace(r.URL.Query().Get("event_id")),
				Endpoint: strings.TrimSpace(r.URL.Query().Get("endpoint")),
				Status:   secureCellWebhookDeliveryStatus(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))),
				Limit:    cast.ToInt(strings.TrimSpace(r.URL.Query().Get("limit"))),
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellWebhookDeliveryListResponse{Items: app.secureCellRuntime.ListDeliveries(filter)})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/artifacts") {
			cellID, err := parseSecureCellID(r.URL.Path, "/artifacts")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellArtifactsProjection(result))
			return
		}

		cellID, err := parseSecureCellID(r.URL.Path, "")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := app.secureCellService.GetCell(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
	})
}

func (app *AethelredApp) SecureCellsMutateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/members"):
			cellID, err := parseSecureCellID(r.URL.Path, "/members")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellAdmitMemberRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell admission request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellAdmit(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AdmitMember(r.Context(), cellID, securecellsintegration.SecureCellAdmissionRequest{
				Participant: req.Participant,
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/members/bulk/quarantine"), strings.HasSuffix(r.URL.Path, "/members/bulk/release"), strings.HasSuffix(r.URL.Path, "/members/bulk/revoke"):
			cellID, action, err := parseSecureCellBulkMemberActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellBulkMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell bulk mutation request: "+err.Error())
				return
			}
			authProbe := &secureCellMemberMutationRequest{
				ActorIdentity:       req.ActorIdentity,
				PolicyReceipt:       req.PolicyReceipt,
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "quarantine":
				authCtx, err = app.authorizeSecureCellQuarantine(r, cellID, authProbe)
			case "release":
				authCtx, err = app.authorizeSecureCellRelease(r, cellID, authProbe)
			case "revoke":
				authCtx, err = app.authorizeSecureCellRevoke(r, cellID, authProbe)
			default:
				err = fmt.Errorf("unsupported secure cell bulk action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			bulk := securecellsintegration.SecureCellBulkMemberTransitionRequest{
				ParticipantDIDs:     req.ParticipantDIDs,
				ActorDID:            safeSecureCellActorDID(authCtx),
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var result *securecellsintegration.SecureCellBulkMemberTransitionResult
			switch action {
			case "quarantine":
				result, err = app.secureCellService.BulkQuarantineMembers(r.Context(), cellID, bulk)
			case "release":
				result, err = app.secureCellService.BulkReleaseMembers(r.Context(), cellID, bulk)
			case "revoke":
				result, err = app.secureCellService.BulkRevokeMembers(r.Context(), cellID, bulk)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellBulkMutationResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/quarantine/expire"):
			cellID, err := parseSecureCellID(r.URL.Path, "/quarantine/expire")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell lifecycle request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellExpire(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ExpireQuarantinedMembers(r.Context(), cellID, derefSecureCellTime(req.EffectiveAt), securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/pause"), strings.HasSuffix(r.URL.Path, "/resume"), strings.HasSuffix(r.URL.Path, "/terminate"):
			cellID, action, err := parseSecureCellLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "pause":
				authCtx, err = app.authorizeSecureCellPause(r, cellID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellResume(r, cellID, &req)
			case "terminate":
				authCtx, err = app.authorizeSecureCellTerminate(r, cellID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "pause":
				result, err = app.secureCellService.PauseCell(r.Context(), cellID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeCell(r.Context(), cellID, lifecycle)
			case "terminate":
				result, err = app.secureCellService.TerminateCell(r.Context(), cellID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/quarantine"), strings.HasSuffix(r.URL.Path, "/revoke"), strings.HasSuffix(r.URL.Path, "/release"):
			cellID, participantDID, action, err := parseSecureCellMemberActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell member mutation request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.ParticipantDID) == "" {
				req.ParticipantDID = participantDID
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "release":
				authCtx, err = app.authorizeSecureCellRelease(r, cellID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellQuarantine(r, cellID, &req)
			case "revoke":
				authCtx, err = app.authorizeSecureCellRevoke(r, cellID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell member action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			mutation := securecellsintegration.SecureCellMemberTransitionRequest{
				ParticipantDID:      req.ParticipantDID,
				ActorDID:            safeSecureCellActorDID(authCtx),
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "release":
				result, err = app.secureCellService.ReleaseMember(r.Context(), cellID, mutation)
			case "quarantine":
				result, err = app.secureCellService.QuarantineMember(r.Context(), cellID, mutation)
			case "revoke":
				result, err = app.secureCellService.RevokeMember(r.Context(), cellID, mutation)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		default:
			writeSecureCellAPIError(w, http.StatusBadRequest, "unsupported secure cell mutation path")
			return
		}
	})
}

func secureCellArtifactsProjection(result *securecellsintegration.SecureCellResult) secureCellArtifactsResponse {
	projection := secureCellArtifactsResponse{}
	if result == nil {
		return projection
	}
	projection.CellID = result.CellID
	projection.Status = result.Status
	projection.Participants = append([]securecellsintegration.SecureCellParticipantState(nil), result.Participants...)
	projection.Transitions = append([]securecellsintegration.SecureCellTransition(nil), result.Transitions...)
	projection.CreationReceipt = result.CreationReceipt
	projection.ActivationReceipt = result.ActivationReceipt
	projection.ExecutionSeal = result.ExecutionSeal
	if result.ControlLedger != nil && result.ControlLedger.Bundle != nil {
		projection.ControlLedgerID = result.ControlLedger.Bundle.ID
		projection.ControlLedgerContentHash = result.ControlLedger.Bundle.ContentHash
		summary := result.ControlLedger.Summary
		projection.ControlSummary = &summary
	}
	if result.PortablePackage != nil {
		projection.PortablePackageHash = result.PortablePackage.PackageHash
		projection.PortablePackageSigned = result.PortablePackage.Signature != nil
		projection.PortablePackageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	return projection
}

func derefSecureCellTime(in *time.Time) time.Time {
	if in == nil {
		return time.Time{}
	}
	return in.UTC()
}

func parseSecureCellListFilter(r *http.Request) (securecellsintegration.SecureCellListFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellListFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	statuses, err := parseSecureCellStatuses(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	return securecellsintegration.SecureCellListFilter{
		Statuses:       statuses,
		Jurisdiction:   strings.TrimSpace(query.Get("jurisdiction")),
		ParticipantDID: strings.TrimSpace(query.Get("participant_did")),
		UpdatedAfter:   updatedAfter,
		UpdatedBefore:  updatedBefore,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellStatuses(raw string) ([]securecellsintegration.SecureCellStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]securecellsintegration.SecureCellStatus, 0, len(parts))
	for _, part := range parts {
		status, err := parseSecureCellStatus(part)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func parseSecureCellStatus(raw string) (securecellsintegration.SecureCellStatus, error) {
	switch securecellsintegration.SecureCellStatus(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellStatusActive,
		securecellsintegration.SecureCellStatusPaused,
		securecellsintegration.SecureCellStatusQuarantined,
		securecellsintegration.SecureCellStatusRevoked,
		securecellsintegration.SecureCellStatusTerminated,
		securecellsintegration.SecureCellStatusRejected:
		return securecellsintegration.SecureCellStatus(strings.ToLower(strings.TrimSpace(raw))), nil
	default:
		return "", fmt.Errorf("invalid secure cell status %q", raw)
	}
}

func parseSecureCellOptionalTime(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var parsed time.Time
	var err error
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err = time.Parse(layout, raw)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed, nil
		}
	}
	return nil, fmt.Errorf("invalid timestamp %q: %w", raw, err)
}

func resolveSecureCellControlLedgerDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.control_ledger_dir")),
		cast.ToString(appOpts.Get("secure_cells.control_ledger_dir")),
		os.Getenv("AETHELRED_SECURE_CELLS_CONTROL_LEDGER_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "secure-cells", "control-ledgers"))
	}
	return filepath.Join(homePath, "data", "secure-cells", "control-ledgers")
}

func resolveSecureCellPolicySigner(appOpts servertypes.AppOptions) (*ecdsa.PrivateKey, string, string, string, error) {
	signer := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.policy_signer")),
		cast.ToString(appOpts.Get("secure_cells.policy_signer")),
		os.Getenv("AETHELRED_SECURE_CELLS_POLICY_SIGNER"),
	)
	if strings.TrimSpace(signer) == "" {
		signer = "did:aethelred:policy-gateway-secure-cells"
	}

	keyHex := strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.policy_signer_key")),
		cast.ToString(appOpts.Get("secure_cells.policy_signer_key")),
		os.Getenv("AETHELRED_SECURE_CELLS_POLICY_SIGNER_KEY"),
	))
	if keyHex == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", "", "", err
		}
		return key, signer, "ephemeral", "generated an ephemeral secure-cell policy signer because no configured signer key was provided", nil
	}

	key, err := parseFinanceECDSAPrivateKeyHex(keyHex)
	if err != nil {
		return nil, "", "", "", err
	}
	return key, signer, "configured", "loaded secure-cell policy signer from configuration", nil
}

func parseSecureCellID(path, suffix string) (string, error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", fmt.Errorf("invalid secure cell path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", fmt.Errorf("invalid secure cell action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	remainder = strings.Trim(remainder, "/")
	if remainder == "" || strings.Contains(remainder, "/") {
		return "", fmt.Errorf("invalid secure cell ID")
	}
	return remainder, nil
}

func parseSecureCellMemberActionPath(path string) (cellID string, participantDID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "members" {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	cellID = strings.TrimSpace(parts[0])
	participantDID = strings.TrimSpace(parts[2])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || participantDID == "" || action == "" {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	return cellID, participantDID, action, nil
}

func parseSecureCellBulkMemberActionPath(path string) (cellID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "members" || parts[2] != "bulk" {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	cellID = strings.TrimSpace(parts[0])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || action == "" {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	return cellID, action, nil
}

func parseSecureCellLifecycleActionPath(path string) (cellID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	action = strings.TrimSpace(parts[1])
	if cellID == "" || action == "" {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	return cellID, action, nil
}

func secureCellErrorStatus(err error, fallback int) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, audit.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, audit.ErrWriteDisabled):
		return http.StatusServiceUnavailable
	case errors.Is(err, securecellsintegration.ErrCellNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrParticipantNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrParticipantExists):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrCellImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrPolicyDenied):
		return http.StatusForbidden
	default:
		return fallback
	}
}

func safeSecureCellActorDID(authCtx *secureCellAuthContext) string {
	if authCtx == nil {
		return ""
	}
	return strings.TrimSpace(authCtx.ActorDID)
}

func writeSecureCellAPIError(w http.ResponseWriter, status int, message string) {
	writeSecureCellJSON(w, status, secureCellAPIErrorResponse{Error: message})
}

func writeSecureCellJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
