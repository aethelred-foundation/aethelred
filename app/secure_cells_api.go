package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/aethelred/aethelred/pkg/confidential"
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

type secureCellFederationInviteRequest struct {
	ActorIdentity    json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt    *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	SponsorOfRecord  string                      `json:"sponsor_of_record,omitempty"`
	OrganizationName string                      `json:"organization_name,omitempty"`
	Jurisdiction     string                      `json:"jurisdiction,omitempty"`
	ExpectedDID      string                      `json:"expected_did,omitempty"`
	Role             string                      `json:"role,omitempty"`
	SessionScopeIDs  []string                    `json:"session_scope_ids,omitempty"`
	DataClasses      []string                    `json:"data_classes,omitempty"`
	ComputeZones     []string                    `json:"compute_zones,omitempty"`
	Resource         string                      `json:"resource,omitempty"`
	Reason           string                      `json:"reason,omitempty"`
	Metadata         map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationAcceptRequest struct {
	ActorIdentity json.RawMessage                              `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                  `json:"policy_receipt,omitempty"`
	InvitationID  string                                       `json:"invitation_id,omitempty"`
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
	ActorIdentity     json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt     *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason            string                      `json:"reason,omitempty"`
	Comment           string                      `json:"comment,omitempty"`
	RelatedOutputIDs  []string                    `json:"related_output_ids,omitempty"`
	ApprovalThreshold *int                        `json:"approval_threshold,omitempty"`
	ApprovalVote      string                      `json:"approval_vote,omitempty"`
	VoteChoice        string                      `json:"vote_choice,omitempty"`
	VoteRole          string                      `json:"vote_role,omitempty"`
	DelegatedToDID    string                      `json:"delegated_to_did,omitempty"`
	EscalationReason  string                      `json:"escalation_reason,omitempty"`
	OutcomeBundleID   string                      `json:"outcome_bundle_id,omitempty"`
	OutcomeBundleName string                      `json:"outcome_bundle_name,omitempty"`
	OutcomeBundleType string                      `json:"outcome_bundle_type,omitempty"`
	DeadlineAt        *time.Time                  `json:"deadline_at,omitempty"`
	PolicyTemplate    string                      `json:"policy_template,omitempty"`
	AutoEscalation    *bool                       `json:"auto_escalation,omitempty"`
	EffectiveAt       *time.Time                  `json:"effective_at,omitempty"`
	Metadata          map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionStartRequest struct {
	ActorIdentity   json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt   *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name            string                      `json:"name,omitempty"`
	Purpose         string                      `json:"purpose,omitempty"`
	ParticipantDIDs []string                    `json:"participant_dids,omitempty"`
	DataClasses     []string                    `json:"data_classes,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionThreadStartRequest struct {
	ActorIdentity   json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt   *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name            string                      `json:"name,omitempty"`
	Purpose         string                      `json:"purpose,omitempty"`
	ParticipantDIDs []string                    `json:"participant_dids,omitempty"`
	DataClasses     []string                    `json:"data_classes,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionShareRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ArtifactType   string                      `json:"artifact_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	SharedWith     []string                    `json:"shared_with,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionExchangeRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ExchangeType   string                      `json:"exchange_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	Recipients     []string                    `json:"recipients,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellThreadMessageRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ExchangeType   string                      `json:"exchange_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	Recipients     []string                    `json:"recipients,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellThreadDecisionRequest struct {
	ActorIdentity         json.RawMessage                                             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                 `json:"policy_receipt,omitempty"`
	Title                 string                                                      `json:"title,omitempty"`
	Summary               string                                                      `json:"summary,omitempty"`
	Classification        string                                                      `json:"classification,omitempty"`
	GovernanceTemplate    string                                                      `json:"governance_template,omitempty"`
	SLATemplate           string                                                      `json:"sla_template,omitempty"`
	SectorPolicyPack      string                                                      `json:"sector_policy_pack,omitempty"`
	ApprovalThreshold     *int                                                        `json:"approval_threshold,omitempty"`
	EligibleApproverDIDs  []string                                                    `json:"eligible_approver_dids,omitempty"`
	RequiredApproverRoles []string                                                    `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []securecellsintegration.SecureCellThreadDecisionVoteChoice `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                                                    `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                                                    `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                                                    `json:"reopen_roles,omitempty"`
	EscalationLadder      []securecellsintegration.SecureCellDecisionEscalationTier   `json:"escalation_ladder,omitempty"`
	AutoEscalateToDID     string                                                      `json:"auto_escalate_to_did,omitempty"`
	EscalationDueAt       *time.Time                                                  `json:"escalation_due_at,omitempty"`
	ResolutionDueAt       *time.Time                                                  `json:"resolution_due_at,omitempty"`
	RelatedExchangeIDs    []string                                                    `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs      []string                                                    `json:"related_output_ids,omitempty"`
	DeadlineAt            *time.Time                                                  `json:"deadline_at,omitempty"`
	PolicyTemplate        string                                                      `json:"policy_template,omitempty"`
	AutoEscalation        *bool                                                       `json:"auto_escalation,omitempty"`
	Reason                string                                                      `json:"reason,omitempty"`
	Metadata              map[string]string                                           `json:"metadata,omitempty"`
}

type secureCellSessionMemberMutationRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDID string                      `json:"participant_did,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
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
	CellID                   string                                                    `json:"cell_id"`
	Status                   securecellsintegration.SecureCellStatus                   `json:"status"`
	Participants             []securecellsintegration.SecureCellParticipantState       `json:"participants,omitempty"`
	FederationOrganizations  []securecellsintegration.SecureCellFederationOrganization `json:"federation_organizations,omitempty"`
	FederationInvitations    []securecellsintegration.SecureCellFederationInvitation   `json:"federation_invitations,omitempty"`
	Sessions                 []securecellsintegration.SecureCellSession                `json:"sessions,omitempty"`
	Threads                  []securecellsintegration.SecureCellSessionThread          `json:"threads,omitempty"`
	Decisions                []securecellsintegration.SecureCellThreadDecision         `json:"decisions,omitempty"`
	DecisionOutcomes         []securecellsintegration.SecureCellThreadDecisionOutcome  `json:"decision_outcomes,omitempty"`
	SharedOutputs            []securecellsintegration.SecureCellSharedOutput           `json:"shared_outputs,omitempty"`
	SessionExchanges         []securecellsintegration.SecureCellSessionExchange        `json:"session_exchanges,omitempty"`
	Transitions              []securecellsintegration.SecureCellTransition             `json:"transitions,omitempty"`
	CreationReceipt          *policy.SignedPolicyReceipt                               `json:"creation_receipt,omitempty"`
	ActivationReceipt        *policy.SignedPolicyReceipt                               `json:"activation_receipt,omitempty"`
	ConfidentialExecution    *confidential.VerificationSummary                         `json:"confidential_execution,omitempty"`
	ExecutionAttestations    []evidence.Attestation                                    `json:"execution_attestations,omitempty"`
	ExecutionSeal            *evidence.Seal                                            `json:"execution_seal,omitempty"`
	ControlLedgerID          string                                                    `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash string                                                    `json:"control_ledger_content_hash,omitempty"`
	ControlSummary           *evidence.ControlLedgerSummary                            `json:"control_summary,omitempty"`
	PortablePackageHash      string                                                    `json:"portable_package_hash,omitempty"`
	PortablePackageSigned    bool                                                      `json:"portable_package_signed"`
	PortablePackageAnchored  bool                                                      `json:"portable_package_anchored"`
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

type secureCellFederationResponse struct {
	CellID                  string                                                    `json:"cell_id"`
	Organizations           []securecellsintegration.SecureCellFederationOrganization `json:"organizations,omitempty"`
	Invitations             []securecellsintegration.SecureCellFederationInvitation   `json:"invitations,omitempty"`
	PortablePackageHash     string                                                    `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                      `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                      `json:"portable_package_anchored"`
}

type secureCellDecisionListResponse struct {
	Items []securecellsintegration.SecureCellThreadDecision `json:"items"`
}

type secureCellDecisionQueryResponse struct {
	Result *securecellsintegration.SecureCellThreadDecision `json:"result,omitempty"`
}

type secureCellDecisionDeliberationResponse struct {
	Result           *securecellsintegration.SecureCellThreadDecision         `json:"result,omitempty"`
	DecisionOutcomes []securecellsintegration.SecureCellThreadDecisionOutcome `json:"decision_outcomes,omitempty"`
	SharedOutputs    []securecellsintegration.SecureCellSharedOutput          `json:"shared_outputs,omitempty"`
	SessionExchanges []securecellsintegration.SecureCellSessionExchange       `json:"session_exchanges,omitempty"`
}

type secureCellDecisionOutcomeListResponse struct {
	Items []securecellsintegration.SecureCellThreadDecisionOutcome `json:"items"`
}

type secureCellEventListResponse struct {
	Items []secureCellAuditEventRecord `json:"items"`
}

type secureCellWebhookDeliveryListResponse struct {
	Items []secureCellWebhookDeliveryRecord `json:"items"`
}

type secureCellOverdueDecisionListResponse struct {
	Items []securecellsintegration.SecureCellOverdueDecision `json:"items"`
}

type secureCellDecisionAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellDecisionAutomationActionRecord `json:"items"`
}

type secureCellDecisionSLATemplateListResponse struct {
	Items []securecellsintegration.SecureCellDecisionSLATemplateSummary `json:"items"`
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
	workflowStoreDir := resolveSecureCellWorkflowStoreDir(appOpts)
	workflowStore, err := securecellsintegration.NewFileSecureCellStore(workflowStoreDir)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while creating the workflow store",
			"error", err,
			"workflow_store_dir", workflowStoreDir,
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
	requestedBy := firstNonEmpty(cast.ToString(appOpts.Get("aethelred.secure_cells.signer_address")), cast.ToString(appOpts.Get("secure_cells.signer_address")), app.PouwKeeper.GetAuthority(), authtypes.NewModuleAddress(pouwtypes.ModuleName).String())
	confidentialKeys := map[string]*ecdsa.PublicKey{
		policySigner: &policySignerKey.PublicKey,
	}
	confidentialPolicy := resolveConfidentialExecutionPolicy(appOpts, "aethelred.secure_cells", "secure_cells", false, confidentialKeys)
	service, err := securecellsintegration.NewService(securecellsintegration.ServiceConfig{
		PolicySignerKey:     policySignerKey,
		PolicySigner:        policySigner,
		CredentialIssuerKey: policySignerKey,
		CredentialIssuer:    policySigner,
		Sealer: &appSecureCellSealer{
			app:         app,
			requestedBy: requestedBy,
		},
		LedgerStore:          ledgerStore,
		WorkflowStore:        workflowStore,
		Framework:            "Secure Cells v1",
		ConfidentialAttestor: newWorkflowTEEAttestor(app, "secure_cell", policySigner, policySignerKey),
		ConfidentialPolicy:   confidentialPolicy,
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
	app.secureCellWorkflowStoreDir = workflowStoreDir
	app.secureCellRuntime = secureCellRuntime
	app.secureCellExpirySweeper = newSecureCellExpirySweeper(app, service, resolveSecureCellExpirySweepInterval(appOpts))
	if signerMode == "ephemeral" {
		app.Logger().Warn("Secure Cells API initialized with an ephemeral policy signer",
			"control_ledger_dir", controlLedgerDir,
			"workflow_store_dir", workflowStoreDir,
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
		"workflow_store_dir", workflowStoreDir,
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

		if r.URL.Path == secureCellsCollectionRoute+"/decision-sla-templates" {
			filter := parseSecureCellDecisionSLATemplateFilter(r)
			items, err := app.secureCellService.ListDecisionSLATemplates(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionSLATemplateListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decision-sla-templates/export" {
			filter := parseSecureCellDecisionSLATemplateFilter(r)
			items, err := app.secureCellService.ListDecisionSLATemplates(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellDecisionSLATemplateExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/overdue" {
			filter, err := parseSecureCellOverdueDecisionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueDecisions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueDecisionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/overdue/export" {
			filter, err := parseSecureCellOverdueDecisionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueDecisions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueDecisionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/automation-actions" {
			filter, err := parseSecureCellDecisionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListDecisionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/automation-actions/export" {
			filter, err := parseSecureCellDecisionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListDecisionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellDecisionAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsItemPrefix+"events" || r.URL.Path == secureCellsCollectionRoute+"/events" {
			filter := secureCellAuditEventFilter{
				CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
				ParticipantDID: strings.TrimSpace(r.URL.Query().Get("participant_did")),
				ThreadID:       strings.TrimSpace(r.URL.Query().Get("thread_id")),
				DecisionID:     strings.TrimSpace(r.URL.Query().Get("decision_id")),
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

		if strings.HasSuffix(r.URL.Path, "/status") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/status")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionQueryResponse{Result: decision})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/deliberation") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/deliberation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			response, ok := secureCellDecisionDeliberationProjection(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			writeSecureCellJSON(w, http.StatusOK, response)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/outcomes") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/outcomes")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			outcomes := secureCellDecisionOutcomesForDecision(result, decision)
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionOutcomeListResponse{Items: outcomes})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/federation") {
			cellID, err := parseSecureCellID(r.URL.Path, "/federation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationProjection(result))
			return
		}

		if strings.HasSuffix(r.URL.Path, "/decisions") && strings.Contains(r.URL.Path, "/threads/") {
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/decisions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionListResponse{Items: secureCellDecisionsForThread(result, sessionID, threadID)})
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
		case strings.HasSuffix(r.URL.Path, "/federation/invitations"):
			cellID, err := parseSecureCellID(r.URL.Path, "/federation/invitations")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationInviteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation invitation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationInvite(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CreateFederationInvitation(r.Context(), cellID, securecellsintegration.SecureCellFederationInviteRequest{
				ActorDID:         safeSecureCellActorDID(authCtx),
				SponsorOfRecord:  req.SponsorOfRecord,
				OrganizationName: req.OrganizationName,
				Jurisdiction:     req.Jurisdiction,
				ExpectedDID:      req.ExpectedDID,
				Role:             req.Role,
				SessionScopeIDs:  append([]string(nil), req.SessionScopeIDs...),
				DataClasses:      append([]string(nil), req.DataClasses...),
				ComputeZones:     append([]string(nil), req.ComputeZones...),
				Resource:         req.Resource,
				Reason:           req.Reason,
				Metadata:         req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/accept") && strings.Contains(r.URL.Path, "/federation/invitations/"):
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/accept")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationAcceptRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation acceptance request: "+err.Error())
				return
			}
			req.InvitationID = firstNonEmpty(req.InvitationID, invitationID)
			authCtx, err := app.authorizeSecureCellFederationAccept(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcceptFederationInvitation(r.Context(), cellID, securecellsintegration.SecureCellFederationAcceptRequest{
				InvitationID: req.InvitationID,
				ActorDID:     safeSecureCellActorDID(authCtx),
				Participant:  req.Participant,
				Reason:       req.Reason,
				Metadata:     req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/revoke") && strings.Contains(r.URL.Path, "/federation/invitations/"):
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/revoke")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation revoke request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationRevoke(r, cellID, invitationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RevokeFederationInvitation(r.Context(), cellID, invitationID, securecellsintegration.SecureCellLifecycleRequest{
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
		case strings.HasSuffix(r.URL.Path, "/outcome-bundles/fetch") && strings.Contains(r.URL.Path, "/decisions/"):
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionOutcomeBundleFetchPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision outcome bundle request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadDecisionOutcomeBundleFetch(r, cellID, sessionID, threadID, decisionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			req.Metadata = secureCellOutcomeBundleMetadata(req.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/vote") || strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/comments") || strings.HasSuffix(r.URL.Path, "/contain-outputs") || strings.HasSuffix(r.URL.Path, "/release-outputs") || strings.HasSuffix(r.URL.Path, "/delegate") || strings.HasSuffix(r.URL.Path, "/escalate") || strings.HasSuffix(r.URL.Path, "/outcome-bundles") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine") || strings.HasSuffix(r.URL.Path, "/close")) && strings.Contains(r.URL.Path, "/decisions/"):
			cellID, sessionID, threadID, decisionID, action, err := parseSecureCellSessionThreadDecisionLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "vote":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionVote(r, cellID, sessionID, threadID, decisionID, &req)
			case "approve":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionApprove(r, cellID, sessionID, threadID, decisionID, &req)
			case "comments":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionComment(r, cellID, sessionID, threadID, decisionID, &req)
			case "contain-outputs":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionContainOutputs(r, cellID, sessionID, threadID, decisionID, &req)
			case "release-outputs":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionReleaseOutputs(r, cellID, sessionID, threadID, decisionID, &req)
			case "delegate":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionDelegate(r, cellID, sessionID, threadID, decisionID, &req)
			case "escalate":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionEscalate(r, cellID, sessionID, threadID, decisionID, &req)
			case "outcome-bundles":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionOutcomeBundleCreate(r, cellID, sessionID, threadID, decisionID, &req)
			case "fetch":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionOutcomeBundleFetch(r, cellID, sessionID, threadID, decisionID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionResume(r, cellID, sessionID, threadID, decisionID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionQuarantine(r, cellID, sessionID, threadID, decisionID, &req)
			case "close":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionClose(r, cellID, sessionID, threadID, decisionID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell thread decision lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			req.Metadata = secureCellDecisionMutationMetadata(req.Metadata, decisionID, req.Comment, req.RelatedOutputIDs, req.ApprovalThreshold, firstNonEmpty(strings.TrimSpace(req.VoteChoice), strings.TrimSpace(req.ApprovalVote)))
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "vote":
				if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
					return
				}
				voteChoice := strings.TrimSpace(firstNonEmpty(req.VoteChoice, req.ApprovalVote))
				if voteChoice == "" {
					voteChoice = "approve"
				}
				if !secureCellDecisionVoteChoiceAllowed(voteChoice) {
					writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell decision vote choice")
					return
				}
				lifecycle.Metadata = secureCellDecisionVoteMetadata(lifecycle.Metadata, req.ApprovalThreshold, voteChoice, req.VoteRole, req.Comment)
				result, err = app.secureCellService.VoteThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle, securecellsintegration.SecureCellThreadDecisionVoteChoice(strings.ToLower(voteChoice)))
			case "approve":
				if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
					return
				}
				voteChoice := strings.TrimSpace(firstNonEmpty(req.VoteChoice, req.ApprovalVote))
				if voteChoice == "" {
					voteChoice = "approve"
				}
				if !strings.EqualFold(voteChoice, "approve") {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approve route only accepts approve votes")
					return
				}
				lifecycle.Metadata = secureCellDecisionVoteMetadata(lifecycle.Metadata, req.ApprovalThreshold, voteChoice, req.VoteRole, req.Comment)
				result, err = app.secureCellService.ApproveThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "comments":
				if strings.TrimSpace(req.Comment) == "" {
					writeSecureCellAPIError(w, http.StatusBadRequest, "decision comment is required")
					return
				}
				result, err = app.secureCellService.CommentThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionCommentRequest{
					ActorDID: safeSecureCellActorDID(authCtx),
					Comment:  req.Comment,
					Reason:   req.Reason,
					Metadata: req.Metadata,
				})
			case "contain-outputs":
				lifecycle.Metadata = secureCellDecisionOutputContainmentMetadata(lifecycle.Metadata, req.RelatedOutputIDs, req.Comment)
				result, err = app.secureCellService.ContainThreadDecisionOutputs(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "release-outputs":
				lifecycle.Metadata = secureCellDecisionOutputReleaseMetadata(lifecycle.Metadata, req.RelatedOutputIDs, req.Comment)
				result, err = app.secureCellService.ReleaseThreadDecisionOutputs(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "delegate":
				lifecycle.Metadata = secureCellDecisionDelegationMetadata(lifecycle.Metadata, decisionID, req.DelegatedToDID, req.Comment, req.Reason)
				result, err = app.secureCellService.DelegateThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionDelegationRequest{
					ActorDID:  safeSecureCellActorDID(authCtx),
					TargetDID: req.DelegatedToDID,
					Reason:    req.Reason,
					Metadata:  lifecycle.Metadata,
				})
			case "escalate":
				lifecycle.Metadata = secureCellDecisionEscalationMetadata(lifecycle.Metadata, decisionID, req.EscalationReason, req.Comment, req.Reason)
				result, err = app.secureCellService.EscalateThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionDelegationRequest{
					ActorDID:  safeSecureCellActorDID(authCtx),
					TargetDID: req.DelegatedToDID,
					Reason:    firstNonEmpty(req.EscalationReason, req.Reason),
					Metadata:  lifecycle.Metadata,
				})
			case "outcome-bundles":
				lifecycle.Metadata = secureCellOutcomeBundleMetadata(lifecycle.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
				result, err = app.secureCellService.PublishThreadDecisionOutcome(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionOutcomeRequest{
					ActorDID:         safeSecureCellActorDID(authCtx),
					Title:            req.OutcomeBundleName,
					Summary:          req.Comment,
					Classification:   "",
					OutcomeType:      req.OutcomeBundleType,
					RelatedOutputIDs: req.RelatedOutputIDs,
					Reason:           req.Reason,
					Metadata:         lifecycle.Metadata,
				})
			case "fetch":
				lifecycle.Metadata = secureCellOutcomeBundleMetadata(lifecycle.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
				result, err = app.secureCellService.GetCell(r.Context(), cellID)
			case "resume":
				result, err = app.secureCellService.ResumeThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "close":
				result, err = app.secureCellService.CloseThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/decisions") && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/decisions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellThreadDecisionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision request: "+err.Error())
				return
			}
			if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
				writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadDecisionCreate(r, cellID, sessionID, threadID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			result, err := app.secureCellService.CreateThreadDecision(r.Context(), cellID, securecellsintegration.SecureCellThreadDecisionRequest{
				SessionID:             sessionID,
				ThreadID:              threadID,
				ActorDID:              safeSecureCellActorDID(authCtx),
				Title:                 req.Title,
				Summary:               req.Summary,
				Classification:        req.Classification,
				GovernanceTemplate:    secureCellDecisionServiceGovernanceTemplate(req),
				SLATemplate:           secureCellDecisionServiceSLATemplate(req),
				SectorPolicyPack:      secureCellDecisionServiceSectorPolicyPack(req),
				ApprovalThreshold:     safeSecureCellOptionalInt(req.ApprovalThreshold),
				EligibleApproverDIDs:  req.EligibleApproverDIDs,
				RequiredApproverRoles: req.RequiredApproverRoles,
				AllowedVoteChoices:    append([]securecellsintegration.SecureCellThreadDecisionVoteChoice(nil), req.AllowedVoteChoices...),
				RejectorRoles:         append([]string(nil), req.RejectorRoles...),
				AbstainerRoles:        append([]string(nil), req.AbstainerRoles...),
				ReopenRoles:           append([]string(nil), req.ReopenRoles...),
				EscalationLadder:      append([]securecellsintegration.SecureCellDecisionEscalationTier(nil), req.EscalationLadder...),
				AutoEscalateToDID:     strings.TrimSpace(req.AutoEscalateToDID),
				EscalationDueAt:       safeSecureCellOptionalTime(req.EscalationDueAt),
				ResolutionDueAt:       secureCellDecisionResolutionDueAt(req),
				RelatedExchangeIDs:    req.RelatedExchangeIDs,
				RelatedOutputIDs:      req.RelatedOutputIDs,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/messages") && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/messages")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellThreadMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread message request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadMessage(r, cellID, sessionID, threadID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.PostThreadMessage(r.Context(), cellID, securecellsintegration.SecureCellThreadMessageRequest{
				SessionID:      sessionID,
				ThreadID:       threadID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Name:           req.Name,
				ExchangeType:   req.ExchangeType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				Recipients:     req.Recipients,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/close") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine")) && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, action, err := parseSecureCellSessionThreadLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "close":
				authCtx, err = app.authorizeSecureCellSessionThreadClose(r, cellID, sessionID, threadID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionThreadResume(r, cellID, sessionID, threadID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionThreadQuarantine(r, cellID, sessionID, threadID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell session thread lifecycle action")
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
			case "close":
				result, err = app.secureCellService.CloseThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/threads"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/threads")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionThreadStartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session thread start request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadStart(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.StartThread(r.Context(), cellID, securecellsintegration.SecureCellSessionThreadStartRequest{
				SessionID:       sessionID,
				ActorDID:        safeSecureCellActorDID(authCtx),
				Name:            req.Name,
				Purpose:         req.Purpose,
				ParticipantDIDs: req.ParticipantDIDs,
				DataClasses:     req.DataClasses,
				Reason:          req.Reason,
				Metadata:        req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/exchange")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionExchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session exchange request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionExchange(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RecordExchange(r.Context(), cellID, securecellsintegration.SecureCellSessionExchangeRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				SessionID:      sessionID,
				Name:           req.Name,
				ExchangeType:   req.ExchangeType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				Recipients:     req.Recipients,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/members") && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/members")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session member mutation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionMemberAdmit(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AddSessionMember(r.Context(), cellID, securecellsintegration.SecureCellSessionMemberTransitionRequest{
				ParticipantDID: req.ParticipantDID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/remove") && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, participantDID, err := parseSecureCellSessionMemberActionPath(r.URL.Path, "/remove")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session member removal request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.ParticipantDID) == "" {
				req.ParticipantDID = participantDID
			}
			authCtx, err := app.authorizeSecureCellSessionMemberRemove(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RemoveSessionMember(r.Context(), cellID, securecellsintegration.SecureCellSessionMemberTransitionRequest{
				ParticipantDID: req.ParticipantDID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/pause") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine")) && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, action, err := parseSecureCellSessionLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "pause":
				authCtx, err = app.authorizeSecureCellSessionPause(r, cellID, sessionID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionResume(r, cellID, sessionID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionQuarantine(r, cellID, sessionID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell session lifecycle action")
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
				result, err = app.secureCellService.PauseSession(r.Context(), cellID, sessionID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeSession(r.Context(), cellID, sessionID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineSession(r.Context(), cellID, sessionID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/sessions"):
			cellID, err := parseSecureCellID(r.URL.Path, "/sessions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionStartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session start request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionStart(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.StartSession(r.Context(), cellID, securecellsintegration.SecureCellSessionStartRequest{
				ActorDID:        safeSecureCellActorDID(authCtx),
				Name:            req.Name,
				Purpose:         req.Purpose,
				ParticipantDIDs: req.ParticipantDIDs,
				DataClasses:     req.DataClasses,
				Reason:          req.Reason,
				Metadata:        req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/share"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/share")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session share request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionShare(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ShareOutput(r.Context(), cellID, securecellsintegration.SecureCellSessionShareRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				SessionID:      sessionID,
				Name:           req.Name,
				ArtifactType:   req.ArtifactType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				SharedWith:     req.SharedWith,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/close"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/close")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session close request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionClose(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CloseSession(r.Context(), cellID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
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
	projection.FederationOrganizations = append([]securecellsintegration.SecureCellFederationOrganization(nil), result.FederationOrganizations...)
	projection.FederationInvitations = append([]securecellsintegration.SecureCellFederationInvitation(nil), result.FederationInvitations...)
	projection.Sessions = append([]securecellsintegration.SecureCellSession(nil), result.Sessions...)
	projection.Threads = append([]securecellsintegration.SecureCellSessionThread(nil), result.Threads...)
	projection.Decisions = append([]securecellsintegration.SecureCellThreadDecision(nil), result.Decisions...)
	projection.DecisionOutcomes = append([]securecellsintegration.SecureCellThreadDecisionOutcome(nil), result.DecisionOutcomes...)
	projection.SharedOutputs = append([]securecellsintegration.SecureCellSharedOutput(nil), result.SharedOutputs...)
	projection.SessionExchanges = append([]securecellsintegration.SecureCellSessionExchange(nil), result.SessionExchanges...)
	projection.Transitions = append([]securecellsintegration.SecureCellTransition(nil), result.Transitions...)
	projection.CreationReceipt = result.CreationReceipt
	projection.ActivationReceipt = result.ActivationReceipt
	projection.ConfidentialExecution = result.ConfidentialExecution
	projection.ExecutionAttestations = append([]evidence.Attestation(nil), result.ExecutionAttestations...)
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

func secureCellFederationProjection(result *securecellsintegration.SecureCellResult) secureCellFederationResponse {
	if result == nil {
		return secureCellFederationResponse{}
	}
	packageHash := ""
	packageSigned := false
	packageAnchored := false
	if result.PortablePackage != nil {
		packageHash = result.PortablePackage.PackageHash
		packageSigned = result.PortablePackage.Signature != nil
		packageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	return secureCellFederationResponse{
		CellID:                  result.CellID,
		Organizations:           append([]securecellsintegration.SecureCellFederationOrganization(nil), result.FederationOrganizations...),
		Invitations:             append([]securecellsintegration.SecureCellFederationInvitation(nil), result.FederationInvitations...),
		PortablePackageHash:     packageHash,
		PortablePackageSigned:   packageSigned,
		PortablePackageAnchored: packageAnchored,
	}
}

func secureCellDecisionVoteChoiceAllowed(raw string) bool {
	switch securecellsintegration.SecureCellThreadDecisionVoteChoice(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellThreadDecisionVoteChoiceApprove,
		securecellsintegration.SecureCellThreadDecisionVoteChoiceReject,
		securecellsintegration.SecureCellThreadDecisionVoteChoiceAbstain:
		return true
	default:
		return false
	}
}

func secureCellDecisionFromResult(result *securecellsintegration.SecureCellResult, sessionID string, threadID string, decisionID string) (*securecellsintegration.SecureCellThreadDecision, bool) {
	if result == nil {
		return nil, false
	}
	for _, decision := range result.Decisions {
		if strings.TrimSpace(decision.SessionID) != strings.TrimSpace(sessionID) {
			continue
		}
		if strings.TrimSpace(decision.ThreadID) != strings.TrimSpace(threadID) {
			continue
		}
		if strings.TrimSpace(decision.ID) != strings.TrimSpace(decisionID) {
			continue
		}
		clone := decision
		return &clone, true
	}
	return nil, false
}

func secureCellDecisionsForThread(result *securecellsintegration.SecureCellResult, sessionID string, threadID string) []securecellsintegration.SecureCellThreadDecision {
	if result == nil {
		return nil
	}
	items := make([]securecellsintegration.SecureCellThreadDecision, 0)
	for _, decision := range result.Decisions {
		if strings.TrimSpace(decision.SessionID) != strings.TrimSpace(sessionID) {
			continue
		}
		if strings.TrimSpace(decision.ThreadID) != strings.TrimSpace(threadID) {
			continue
		}
		items = append(items, decision)
	}
	return items
}

func secureCellDecisionDeliberationProjection(result *securecellsintegration.SecureCellResult, sessionID string, threadID string, decisionID string) (secureCellDecisionDeliberationResponse, bool) {
	decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
	if !ok {
		return secureCellDecisionDeliberationResponse{}, false
	}
	return secureCellDecisionDeliberationResponse{
		Result:           decision,
		DecisionOutcomes: secureCellDecisionOutcomesForDecision(result, decision),
		SharedOutputs:    secureCellSharedOutputsForDecision(result, decision),
		SessionExchanges: secureCellSessionExchangesForDecision(result, decision),
	}, true
}

func secureCellDecisionOutcomesForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellThreadDecisionOutcome {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellThreadDecisionOutcome, 0)
	for _, outcome := range result.DecisionOutcomes {
		if strings.TrimSpace(outcome.DecisionID) == decisionID {
			items = append(items, outcome)
		}
	}
	return items
}

func secureCellSharedOutputsForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellSharedOutput {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellSharedOutput, 0)
	for _, output := range result.SharedOutputs {
		if strings.TrimSpace(output.ContainmentDecisionID) == decisionID || containsString(decision.RelatedOutputIDs, output.ID) {
			items = append(items, output)
		}
	}
	return items
}

func secureCellSessionExchangesForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellSessionExchange {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellSessionExchange, 0)
	for _, exchange := range result.SessionExchanges {
		if strings.TrimSpace(exchange.ContainmentDecisionID) == decisionID || containsString(decision.RelatedExchangeIDs, exchange.ID) {
			items = append(items, exchange)
		}
	}
	return items
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

func parseSecureCellOverdueDecisionFilter(r *http.Request) (securecellsintegration.SecureCellOverdueDecisionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	statuses, err := parseSecureCellDecisionStatuses(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, err
	}
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueDecisionFilter{
		CellID:           strings.TrimSpace(query.Get("cell_id")),
		Jurisdiction:     strings.TrimSpace(query.Get("jurisdiction")),
		ParticipantDID:   strings.TrimSpace(query.Get("participant_did")),
		SLATemplate:      strings.TrimSpace(query.Get("sla_template")),
		SectorPolicyPack: strings.TrimSpace(query.Get("sector_policy_pack")),
		Statuses:         statuses,
		Before:           before,
		Limit:            cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellDecisionAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellDecisionAutomationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, err
	}
	return securecellsintegration.SecureCellDecisionAutomationActionFilter{
		CellID:           strings.TrimSpace(query.Get("cell_id")),
		SessionID:        strings.TrimSpace(query.Get("session_id")),
		ThreadID:         strings.TrimSpace(query.Get("thread_id")),
		DecisionID:       strings.TrimSpace(query.Get("decision_id")),
		SLATemplate:      strings.TrimSpace(query.Get("sla_template")),
		SectorPolicyPack: strings.TrimSpace(query.Get("sector_policy_pack")),
		Action:           strings.TrimSpace(query.Get("action")),
		Since:            since,
		Until:            until,
		Limit:            cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellDecisionSLATemplateFilter(r *http.Request) securecellsintegration.SecureCellDecisionSLATemplateFilter {
	if r == nil {
		return securecellsintegration.SecureCellDecisionSLATemplateFilter{}
	}
	query := r.URL.Query()
	return securecellsintegration.SecureCellDecisionSLATemplateFilter{
		Sector:             strings.TrimSpace(query.Get("sector")),
		SectorPolicyPack:   strings.TrimSpace(query.Get("sector_policy_pack")),
		GovernanceTemplate: strings.TrimSpace(query.Get("governance_template")),
		Limit:              cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}
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

func parseSecureCellDecisionStatuses(raw string) ([]securecellsintegration.SecureCellThreadDecisionStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]securecellsintegration.SecureCellThreadDecisionStatus, 0, len(parts))
	for _, part := range parts {
		status, err := parseSecureCellDecisionStatus(part)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func parseSecureCellDecisionStatus(raw string) (securecellsintegration.SecureCellThreadDecisionStatus, error) {
	switch securecellsintegration.SecureCellThreadDecisionStatus(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellThreadDecisionStatusOpen,
		securecellsintegration.SecureCellThreadDecisionStatusApproved,
		securecellsintegration.SecureCellThreadDecisionStatusQuorumFailed,
		securecellsintegration.SecureCellThreadDecisionStatusQuarantined,
		securecellsintegration.SecureCellThreadDecisionStatusClosed:
		return securecellsintegration.SecureCellThreadDecisionStatus(strings.ToLower(strings.TrimSpace(raw))), nil
	default:
		return "", fmt.Errorf("invalid secure cell decision status %q", raw)
	}
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

func resolveSecureCellWorkflowStoreDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.workflow_store_dir")),
		cast.ToString(appOpts.Get("secure_cells.workflow_store_dir")),
		os.Getenv("AETHELRED_SECURE_CELLS_WORKFLOW_STORE_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "secure-cells", "workflows"))
	}
	return filepath.Join(homePath, "data", "secure-cells", "workflows")
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

func parseSecureCellFederationInvitationActionPath(path string, suffix string) (cellID string, invitationID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation invitation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "invitations" {
		return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
	}
	cellID = strings.TrimSpace(parts[0])
	invitationID = strings.TrimSpace(parts[3])
	if cellID == "" || invitationID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
	}
	return cellID, invitationID, nil
}

func parseSecureCellSessionActionPath(path string, suffix string) (cellID string, sessionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell session path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell session action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 3 || parts[1] != "sessions" {
		return "", "", fmt.Errorf("invalid secure cell session action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	if cellID == "" || sessionID == "" {
		return "", "", fmt.Errorf("invalid secure cell session action path")
	}
	return cellID, sessionID, nil
}

func parseSecureCellSessionLifecycleActionPath(path string) (cellID string, sessionID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "sessions" {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || sessionID == "" || action == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	return cellID, sessionID, action, nil
}

func parseSecureCellSessionMemberActionPath(path string, suffix string) (cellID string, sessionID string, participantDID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session member path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell session member action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 5 || parts[1] != "sessions" || parts[3] != "members" {
		return "", "", "", fmt.Errorf("invalid secure cell session member action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	participantDID = strings.TrimSpace(parts[4])
	if cellID == "" || sessionID == "" || participantDID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session member action path")
	}
	return cellID, sessionID, participantDID, nil
}

func parseSecureCellSessionThreadActionPath(path string, suffix string) (cellID string, sessionID string, threadID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session thread path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 5 || parts[1] != "sessions" || parts[3] != "threads" {
		return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	if cellID == "" || sessionID == "" || threadID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
	}
	return cellID, sessionID, threadID, nil
}

func parseSecureCellSessionThreadLifecycleActionPath(path string) (cellID string, sessionID string, threadID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 6 || parts[1] != "sessions" || parts[3] != "threads" {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	action = strings.TrimSpace(parts[5])
	if cellID == "" || sessionID == "" || threadID == "" || action == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	return cellID, sessionID, threadID, action, nil
}

func parseSecureCellSessionThreadDecisionLifecycleActionPath(path string) (cellID string, sessionID string, threadID string, decisionID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 8 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	action = strings.TrimSpace(parts[7])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" || action == "" {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	return cellID, sessionID, threadID, decisionID, action, nil
}

func parseSecureCellSessionThreadDecisionOutcomeBundleFetchPath(path string) (cellID string, sessionID string, threadID string, decisionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 9 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" || parts[8] != "fetch" || parts[7] != "outcome-bundles" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	return cellID, sessionID, threadID, decisionID, nil
}

func parseSecureCellSessionThreadDecisionLookupPath(path string, suffix string) (cellID string, sessionID string, threadID string, decisionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 7 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	return cellID, sessionID, threadID, decisionID, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func secureCellDecisionMutationMetadata(metadata map[string]string, decisionID, comment string, relatedOutputIDs []string, approvalThreshold *int, approvalVote string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if approvalThreshold != nil {
		out["approval_threshold"] = fmt.Sprintf("%d", *approvalThreshold)
	}
	if trimmed := strings.TrimSpace(approvalVote); trimmed != "" {
		out["approval_vote"] = trimmed
	}
	return out
}

func secureCellDecisionGovernanceMetadata(metadata map[string]string, deadlineAt *time.Time, policyTemplate string, autoEscalation *bool) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if deadlineAt != nil && !deadlineAt.IsZero() {
		out["decision_deadline_at"] = deadlineAt.UTC().Format(time.RFC3339Nano)
	}
	if trimmed := strings.TrimSpace(policyTemplate); trimmed != "" {
		out["decision_policy_template"] = trimmed
	}
	if autoEscalation != nil {
		out["decision_auto_escalation_enabled"] = fmt.Sprintf("%t", *autoEscalation)
	}
	return out
}

func secureCellDecisionApprovalMetadata(metadata map[string]string, threshold *int, vote string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if threshold != nil {
		out["approval_threshold"] = fmt.Sprintf("%d", *threshold)
	}
	if trimmed := strings.TrimSpace(vote); trimmed != "" {
		out["approval_vote"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["approval_comment"] = trimmed
	}
	return out
}

func secureCellDecisionVoteMetadata(metadata map[string]string, threshold *int, voteChoice string, voteRole string, comment string) map[string]string {
	out := secureCellDecisionApprovalMetadata(metadata, threshold, voteChoice, comment)
	if trimmed := strings.TrimSpace(voteChoice); trimmed != "" {
		out["decision_vote_choice"] = trimmed
		out["approval_vote"] = trimmed
	}
	if trimmed := strings.TrimSpace(voteRole); trimmed != "" {
		out["decision_vote_role"] = trimmed
	}
	return out
}

func secureCellDecisionDelegationMetadata(metadata map[string]string, decisionID, delegatedToDID, comment, reason string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(delegatedToDID); trimmed != "" {
		out["decision_delegated_to_did"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		out["decision_delegation_reason"] = trimmed
	}
	return out
}

func secureCellDecisionEscalationMetadata(metadata map[string]string, decisionID, escalationReason, comment, reason string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(escalationReason); trimmed != "" {
		out["decision_escalation_reason"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		out["decision_escalation_request_reason"] = trimmed
	}
	return out
}

func secureCellOutcomeBundleMetadata(metadata map[string]string, decisionID, outcomeBundleID, outcomeBundleName, outcomeBundleType, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleID); trimmed != "" {
		out["decision_outcome_bundle_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleName); trimmed != "" {
		out["decision_outcome_bundle_name"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleType); trimmed != "" {
		out["decision_outcome_bundle_type"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	return out
}

func secureCellDecisionOutputContainmentMetadata(metadata map[string]string, relatedOutputIDs []string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	out["containment_mode"] = "decision_outputs"
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["containment_comment"] = trimmed
	}
	return out
}

func secureCellDecisionOutputReleaseMetadata(metadata map[string]string, relatedOutputIDs []string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	out["release_mode"] = "decision_outputs"
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["release_comment"] = trimmed
	}
	return out
}

func secureCellDecisionCommentIntegrityHash(cellID, sessionID, threadID, decisionID, comment string, metadata map[string]string, actorDID string) string {
	payload, err := json.Marshal(struct {
		CellID     string            `json:"cell_id"`
		SessionID  string            `json:"session_id"`
		ThreadID   string            `json:"thread_id"`
		DecisionID string            `json:"decision_id"`
		Comment    string            `json:"comment"`
		ActorDID   string            `json:"actor_did"`
		Metadata   map[string]string `json:"metadata,omitempty"`
	}{
		CellID:     strings.TrimSpace(cellID),
		SessionID:  strings.TrimSpace(sessionID),
		ThreadID:   strings.TrimSpace(threadID),
		DecisionID: strings.TrimSpace(decisionID),
		Comment:    strings.TrimSpace(comment),
		ActorDID:   strings.TrimSpace(actorDID),
		Metadata:   cloneStringMap(metadata),
	})
	if err != nil {
		payload = []byte(strings.TrimSpace(cellID) + ":" + strings.TrimSpace(sessionID) + ":" + strings.TrimSpace(threadID) + ":" + strings.TrimSpace(decisionID) + ":" + strings.TrimSpace(comment) + ":" + strings.TrimSpace(actorDID))
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
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
	case errors.Is(err, securecellsintegration.ErrSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrSessionNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrSessionImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrSessionParticipantNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrSessionParticipantExists):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrThreadNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrThreadNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrThreadImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrDecisionNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrDecisionNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrDecisionImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationInvitationNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrFederationInvitationImmutable):
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

func safeSecureCellOptionalInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func safeSecureCellOptionalTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func secureCellDecisionResolutionDueAt(req secureCellThreadDecisionRequest) *time.Time {
	if normalized := safeSecureCellOptionalTime(req.ResolutionDueAt); normalized != nil {
		return normalized
	}
	return safeSecureCellOptionalTime(req.DeadlineAt)
}

func secureCellDecisionServiceGovernanceTemplate(req secureCellThreadDecisionRequest) string {
	if template := strings.TrimSpace(req.GovernanceTemplate); template != "" {
		return template
	}
	switch normalized := strings.ToLower(strings.TrimSpace(req.PolicyTemplate)); normalized {
	case "standard_review", "dual_control", "board_escalation":
		return normalized
	default:
		return ""
	}
}

func secureCellDecisionServiceSLATemplate(req secureCellThreadDecisionRequest) string {
	if template := strings.TrimSpace(req.SLATemplate); template != "" {
		return strings.ToLower(template)
	}
	return ""
}

func secureCellDecisionServiceSectorPolicyPack(req secureCellThreadDecisionRequest) string {
	if pack := strings.TrimSpace(req.SectorPolicyPack); pack != "" {
		return strings.ToLower(pack)
	}
	return ""
}

func writeSecureCellAPIError(w http.ResponseWriter, status int, message string) {
	writeSecureCellJSON(w, status, secureCellAPIErrorResponse{Error: message})
}

func writeSecureCellJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
