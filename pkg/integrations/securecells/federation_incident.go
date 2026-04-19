package securecells

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

const secureCellFederationIncidentBulletinSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentSeverity ranks one declared federation incident.
type SecureCellFederationIncidentSeverity string

const (
	SecureCellFederationIncidentSeverityInfo     SecureCellFederationIncidentSeverity = "info"
	SecureCellFederationIncidentSeverityWarning  SecureCellFederationIncidentSeverity = "warning"
	SecureCellFederationIncidentSeverityHigh     SecureCellFederationIncidentSeverity = "high"
	SecureCellFederationIncidentSeverityCritical SecureCellFederationIncidentSeverity = "critical"
)

// SecureCellFederationIncidentCategory groups federation incidents into
// operator-facing response domains.
type SecureCellFederationIncidentCategory string

const (
	SecureCellFederationIncidentCategoryIdentityCompromise          SecureCellFederationIncidentCategory = "identity_compromise"
	SecureCellFederationIncidentCategoryCredentialCompromise        SecureCellFederationIncidentCategory = "credential_compromise"
	SecureCellFederationIncidentCategoryConfidentialComputeFailure  SecureCellFederationIncidentCategory = "confidential_compute_failure"
	SecureCellFederationIncidentCategoryDataExposure                SecureCellFederationIncidentCategory = "data_exposure"
	SecureCellFederationIncidentCategoryUnauthorizedExchange        SecureCellFederationIncidentCategory = "unauthorized_exchange"
	SecureCellFederationIncidentCategoryPolicyBreach               SecureCellFederationIncidentCategory = "policy_breach"
	SecureCellFederationIncidentCategoryMalwareOrTamper            SecureCellFederationIncidentCategory = "malware_or_tamper"
	SecureCellFederationIncidentCategoryCounterpartyOutage         SecureCellFederationIncidentCategory = "counterparty_outage"
)

// SecureCellFederationIncidentStatus tracks one local or imported incident.
type SecureCellFederationIncidentStatus string

const (
	SecureCellFederationIncidentStatusOpen     SecureCellFederationIncidentStatus = "open"
	SecureCellFederationIncidentStatusResolved SecureCellFederationIncidentStatus = "resolved"
)

// SecureCellFederationIncident records one evidence-bearing federation
// incident declared by the local organization inside a secure cell.
type SecureCellFederationIncident struct {
	ID                        string                             `json:"id"`
	OrganizationID            string                             `json:"organization_id"`
	SponsorOfRecord           string                             `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                             `json:"organization_name,omitempty"`
	Status                    SecureCellFederationIncidentStatus `json:"status"`
	Severity                  SecureCellFederationIncidentSeverity `json:"severity"`
	Category                  SecureCellFederationIncidentCategory `json:"category"`
	Summary                   string                             `json:"summary"`
	Description               string                             `json:"description,omitempty"`
	ContractIDs               []string                           `json:"contract_ids,omitempty"`
	SessionIDs                []string                           `json:"session_ids,omitempty"`
	ThreadIDs                 []string                           `json:"thread_ids,omitempty"`
	SharedOutputIDs           []string                           `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs        []string                           `json:"session_exchange_ids,omitempty"`
	AutoContainmentRequested  bool                               `json:"auto_containment_requested"`
	ReportedBy                string                             `json:"reported_by,omitempty"`
	ReportedAt                time.Time                          `json:"reported_at"`
	ExpiresAt                 *time.Time                         `json:"expires_at,omitempty"`
	ResolvedBy                string                             `json:"resolved_by,omitempty"`
	ResolvedAt                *time.Time                         `json:"resolved_at,omitempty"`
	ResolutionReason          string                             `json:"resolution_reason,omitempty"`
	Metadata                  map[string]string                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentPublishRequest publishes one local federation
// incident into the secure-cell evidence chain.
type SecureCellFederationIncidentPublishRequest struct {
	ActorDID                 string                              `json:"actor_did,omitempty"`
	Severity                 SecureCellFederationIncidentSeverity `json:"severity"`
	Category                 SecureCellFederationIncidentCategory `json:"category"`
	Summary                  string                              `json:"summary,omitempty"`
	Description              string                              `json:"description,omitempty"`
	ContractIDs              []string                            `json:"contract_ids,omitempty"`
	SessionIDs               []string                            `json:"session_ids,omitempty"`
	ThreadIDs                []string                            `json:"thread_ids,omitempty"`
	SharedOutputIDs          []string                            `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs       []string                            `json:"session_exchange_ids,omitempty"`
	AutoContainmentRequested bool                                `json:"auto_containment_requested,omitempty"`
	ExpiresAt                *time.Time                          `json:"expires_at,omitempty"`
	Reason                   string                              `json:"reason,omitempty"`
	Metadata                 map[string]string                   `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResolveRequest resolves one local federation
// incident after remediation or expiration.
type SecureCellFederationIncidentResolveRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentFilter narrows operator queries across local
// incident declarations.
type SecureCellFederationIncidentFilter struct {
	CellID         string                              `json:"cell_id,omitempty"`
	OrganizationID string                              `json:"organization_id,omitempty"`
	ContractID     string                              `json:"contract_id,omitempty"`
	Status         SecureCellFederationIncidentStatus  `json:"status,omitempty"`
	Severity       SecureCellFederationIncidentSeverity `json:"severity,omitempty"`
	Category       SecureCellFederationIncidentCategory `json:"category,omitempty"`
	Since          *time.Time                          `json:"since,omitempty"`
	Until          *time.Time                          `json:"until,omitempty"`
	Limit          int                                 `json:"limit,omitempty"`
}

// SecureCellFederationIncidentSummary is the operator-facing projection of one
// local incident declaration.
type SecureCellFederationIncidentSummary struct {
	CellID                    string                              `json:"cell_id"`
	CellName                  string                              `json:"cell_name,omitempty"`
	CellStatus                SecureCellStatus                    `json:"cell_status"`
	Jurisdiction              string                              `json:"jurisdiction,omitempty"`
	IncidentID                string                              `json:"incident_id"`
	OrganizationID            string                              `json:"organization_id"`
	SponsorOfRecord           string                              `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                              `json:"organization_name,omitempty"`
	Status                    SecureCellFederationIncidentStatus  `json:"status"`
	Severity                  SecureCellFederationIncidentSeverity `json:"severity"`
	Category                  SecureCellFederationIncidentCategory `json:"category"`
	Summary                   string                              `json:"summary"`
	Description               string                              `json:"description,omitempty"`
	ContractIDs               []string                            `json:"contract_ids,omitempty"`
	SessionIDs                []string                            `json:"session_ids,omitempty"`
	ThreadIDs                 []string                            `json:"thread_ids,omitempty"`
	SharedOutputIDs           []string                            `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs        []string                            `json:"session_exchange_ids,omitempty"`
	ContractCount             int                                 `json:"contract_count"`
	SessionCount              int                                 `json:"session_count"`
	ThreadCount               int                                 `json:"thread_count"`
	SharedOutputCount         int                                 `json:"shared_output_count"`
	SessionExchangeCount      int                                 `json:"session_exchange_count"`
	AutoContainmentRequested  bool                                `json:"auto_containment_requested"`
	ReportedBy                string                              `json:"reported_by,omitempty"`
	ReportedAt                time.Time                           `json:"reported_at"`
	ExpiresAt                 *time.Time                          `json:"expires_at,omitempty"`
	ResolvedBy                string                              `json:"resolved_by,omitempty"`
	ResolvedAt                *time.Time                          `json:"resolved_at,omitempty"`
	ResolutionReason          string                              `json:"resolution_reason,omitempty"`
}

// SecureCellFederationIncidentBulletinSignature captures the detached signer
// metadata for one portable federation incident bulletin.
type SecureCellFederationIncidentBulletinSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentBulletin is the signed portable incident bulletin
// an organization can share with a counterparty.
type SecureCellFederationIncidentBulletin struct {
	ID                      string                                      `json:"id"`
	Version                 string                                      `json:"version"`
	Name                    string                                      `json:"name"`
	GeneratedAt             time.Time                                   `json:"generated_at"`
	ExpiresAt               *time.Time                                  `json:"expires_at,omitempty"`
	CellID                  string                                      `json:"cell_id"`
	CellName                string                                      `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                            `json:"cell_status"`
	Jurisdiction            string                                      `json:"jurisdiction,omitempty"`
	Framework               string                                      `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary     `json:"organization"`
	Runtime                 SecureCellFederationOrganizationRuntime     `json:"runtime"`
	Contracts               []SecureCellFederationContractSummary       `json:"contracts,omitempty"`
	Incidents               []SecureCellFederationIncidentSummary       `json:"incidents,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface       `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                      `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                      `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                      `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                        `json:"portable_package_signed"`
	PortablePackageAnchored bool                                        `json:"portable_package_anchored"`
	ContentHash             string                                      `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentBulletinSignature `json:"signature,omitempty"`
	Metadata                map[string]string                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentBulletinOptions lets callers tune bulletin
// identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentBulletinOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentStatus tracks the verification and
// freshness posture of one imported counterparty incident bulletin.
type SecureCellFederationCounterpartyIncidentStatus string

const (
	SecureCellFederationCounterpartyIncidentStatusVerified SecureCellFederationCounterpartyIncidentStatus = "verified"
	SecureCellFederationCounterpartyIncidentStatusStale    SecureCellFederationCounterpartyIncidentStatus = "stale"
	SecureCellFederationCounterpartyIncidentStatusExpired  SecureCellFederationCounterpartyIncidentStatus = "expired"
	SecureCellFederationCounterpartyIncidentStatusInvalid  SecureCellFederationCounterpartyIncidentStatus = "invalid"
)

// SecureCellFederationCounterpartyIncidentSnapshot stores one imported
// counterparty incident bulletin inside the secure-cell runtime trace.
type SecureCellFederationCounterpartyIncidentSnapshot struct {
	SnapshotID          string                                        `json:"snapshot_id"`
	OrganizationID      string                                        `json:"organization_id"`
	ContractIDs         []string                                      `json:"contract_ids,omitempty"`
	Bulletin            SecureCellFederationIncidentBulletin          `json:"bulletin"`
	Status              SecureCellFederationCounterpartyIncidentStatus `json:"status"`
	Verified            bool                                          `json:"verified"`
	VerificationMessage string                                        `json:"verification_message,omitempty"`
	Signer              string                                        `json:"signer,omitempty"`
	ReceivedBy          string                                        `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                     `json:"received_at"`
	Metadata            map[string]string                             `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentFilter narrows operator queries over
// imported counterparty incident bulletins.
type SecureCellFederationCounterpartyIncidentFilter struct {
	CellID         string                                        `json:"cell_id,omitempty"`
	OrganizationID string                                        `json:"organization_id,omitempty"`
	ContractID     string                                        `json:"contract_id,omitempty"`
	Status         SecureCellFederationCounterpartyIncidentStatus `json:"status,omitempty"`
	Signer         string                                        `json:"signer,omitempty"`
	Limit          int                                           `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentSummary is the operator-facing
// summary of one imported counterparty bulletin.
type SecureCellFederationCounterpartyIncidentSummary struct {
	CellID                    string                                        `json:"cell_id"`
	CellName                  string                                        `json:"cell_name,omitempty"`
	CellStatus                SecureCellStatus                              `json:"cell_status"`
	Jurisdiction              string                                        `json:"jurisdiction,omitempty"`
	OrganizationID            string                                        `json:"organization_id"`
	SponsorOfRecord           string                                        `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                        `json:"organization_name,omitempty"`
	SnapshotID                string                                        `json:"snapshot_id"`
	BulletinID                string                                        `json:"bulletin_id,omitempty"`
	BulletinVersion           string                                        `json:"bulletin_version,omitempty"`
	BulletinName              string                                        `json:"bulletin_name,omitempty"`
	Status                    SecureCellFederationCounterpartyIncidentStatus `json:"status"`
	Verified                  bool                                          `json:"verified"`
	Signer                    string                                        `json:"signer,omitempty"`
	KeyID                     string                                        `json:"key_id,omitempty"`
	ContractIDs               []string                                      `json:"contract_ids,omitempty"`
	IncidentCount             int                                           `json:"incident_count"`
	OpenIncidentCount         int                                           `json:"open_incident_count"`
	CriticalIncidentCount     int                                           `json:"critical_incident_count"`
	HighIncidentCount         int                                           `json:"high_incident_count"`
	GeneratedAt               time.Time                                     `json:"generated_at,omitempty"`
	ExpiresAt                 *time.Time                                    `json:"expires_at,omitempty"`
	ReceivedAt                time.Time                                     `json:"received_at,omitempty"`
	ControlLedgerID           string                                        `json:"control_ledger_id,omitempty"`
	ControlLedgerHash         string                                        `json:"control_ledger_hash,omitempty"`
	PortablePackageHash       string                                        `json:"portable_package_hash,omitempty"`
	PortablePackageSigned     bool                                          `json:"portable_package_signed"`
	PortablePackageAnchored   bool                                          `json:"portable_package_anchored"`
	VerificationMessage       string                                        `json:"verification_message,omitempty"`
}

// SecureCellFederationIncidentBulletinIntakeRequest ingests one signed
// counterparty incident bulletin into the secure-cell evidence chain.
type SecureCellFederationIncidentBulletinIntakeRequest struct {
	ActorDID string                                      `json:"actor_did,omitempty"`
	Bulletin *SecureCellFederationIncidentBulletin       `json:"bulletin,omitempty"`
	Reason   string                                      `json:"reason,omitempty"`
	Metadata map[string]string                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentActionFilter narrows operator queries over
// incident-linked containment and lifecycle actions.
type SecureCellFederationIncidentActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentActionRecord projects one incident-linked
// lifecycle or automated containment action.
type SecureCellFederationIncidentActionRecord struct {
	CellID            string                              `json:"cell_id"`
	CellName          string                              `json:"cell_name,omitempty"`
	Jurisdiction      string                              `json:"jurisdiction,omitempty"`
	CellStatus        SecureCellStatus                    `json:"cell_status"`
	OrganizationID    string                              `json:"organization_id,omitempty"`
	SponsorOfRecord   string                              `json:"sponsor_of_record,omitempty"`
	IncidentID        string                              `json:"incident_id,omitempty"`
	IncidentStatus    SecureCellFederationIncidentStatus  `json:"incident_status,omitempty"`
	Severity          SecureCellFederationIncidentSeverity `json:"severity,omitempty"`
	Category          SecureCellFederationIncidentCategory `json:"category,omitempty"`
	ContractID        string                              `json:"contract_id,omitempty"`
	SessionID         string                              `json:"session_id,omitempty"`
	ThreadID          string                              `json:"thread_id,omitempty"`
	SharedOutputIDs   []string                            `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs []string                           `json:"session_exchange_ids,omitempty"`
	Action            string                              `json:"action"`
	Trigger           string                              `json:"trigger,omitempty"`
	Actor             string                              `json:"actor"`
	AutomatedActor    string                              `json:"automated_actor,omitempty"`
	Reason            string                              `json:"reason,omitempty"`
	TransitionID      string                              `json:"transition_id"`
	OccurredAt        time.Time                           `json:"occurred_at"`
	Metadata          map[string]string                   `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentSweepResult summarizes one automated incident
// containment pass across all secure cells.
type SecureCellFederationIncidentSweepResult struct {
	At                   time.Time                               `json:"at"`
	CellsScanned         int                                     `json:"cells_scanned"`
	BulletinsScanned     int                                     `json:"bulletins_scanned"`
	IncidentsDetected    int                                     `json:"incidents_detected"`
	ContractsSuspended   int                                     `json:"contracts_suspended"`
	SessionsQuarantined  int                                     `json:"sessions_quarantined"`
	ThreadsQuarantined   int                                     `json:"threads_quarantined"`
	ArtifactsContained   int                                     `json:"artifacts_contained"`
	CellIDs              []string                                `json:"cell_ids,omitempty"`
	Actions              []SecureCellFederationIncidentActionRecord `json:"actions,omitempty"`
}

type secureCellFederationIncidentTargetSet struct {
	contractIDs        []string
	sessionIDs         []string
	threadIDs          []string
	sharedOutputIDs    []string
	sessionExchangeIDs []string
}

// PublishFederationIncident declares one local federation incident and binds it
// into the secure-cell evidence chain.
func (s *Service) PublishFederationIncident(ctx context.Context, cellID string, organizationID string, req SecureCellFederationIncidentPublishRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident: incident summary is required")
	}
	if !secureCellFederationIncidentSeverityAllowed(req.Severity) {
		return nil, fmt.Errorf("securecells/federation-incident: unsupported severity %q", req.Severity)
	}
	if !secureCellFederationIncidentCategoryAllowed(req.Category) {
		return nil, fmt.Errorf("securecells/federation-incident: unsupported category %q", req.Category)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident: %w: actor %q is not permitted to publish incidents", ErrPolicyDenied, actorDID)
	}
	targets, err := secureCellNormalizeFederationIncidentTargets(run, strings.TrimSpace(organizationID), req.ContractIDs, req.SessionIDs, req.ThreadIDs, req.SharedOutputIDs, req.SessionExchangeIDs)
	if err != nil {
		return nil, err
	}
	stageMetadata := map[string]string{
		"federation_organization_id":    strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record":  strings.TrimSpace(summary.SponsorOfRecord),
		"federation_incident_severity":  string(req.Severity),
		"federation_incident_category":  string(req.Category),
		"federation_contract_ids":       strings.Join(targets.contractIDs, ","),
		"federation_session_ids":        strings.Join(targets.sessionIDs, ","),
		"federation_thread_ids":         strings.Join(targets.threadIDs, ","),
		"federation_shared_output_ids":  strings.Join(targets.sharedOutputIDs, ","),
		"federation_session_exchange_ids": strings.Join(targets.sessionExchangeIDs, ","),
		"federation_incident_summary":   strings.TrimSpace(req.Summary),
		"federation_incident_auto_containment": fmt.Sprintf("%t", req.AutoContainmentRequested),
		"transition_reason":             strings.TrimSpace(req.Reason),
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.IsZero() {
		stageMetadata["federation_incident_expires_at"] = req.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "publish_federation_incident", lastReceiptHash(run.result), stageMetadata, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident: %w", ErrPolicyDenied)
	}
	reportedAt := time.Now().UTC()
	incident := SecureCellFederationIncident{
		ID:                       secureCellFederationIncidentID(run.request, summary.OrganizationID, req.Severity, req.Category, req.Summary, reportedAt),
		OrganizationID:           strings.TrimSpace(summary.OrganizationID),
		SponsorOfRecord:          strings.TrimSpace(summary.SponsorOfRecord),
		OrganizationName:         strings.TrimSpace(summary.OrganizationName),
		Status:                   SecureCellFederationIncidentStatusOpen,
		Severity:                 req.Severity,
		Category:                 req.Category,
		Summary:                  strings.TrimSpace(req.Summary),
		Description:              strings.TrimSpace(req.Description),
		ContractIDs:              append([]string(nil), targets.contractIDs...),
		SessionIDs:               append([]string(nil), targets.sessionIDs...),
		ThreadIDs:                append([]string(nil), targets.threadIDs...),
		SharedOutputIDs:          append([]string(nil), targets.sharedOutputIDs...),
		SessionExchangeIDs:       append([]string(nil), targets.sessionExchangeIDs...),
		AutoContainmentRequested: req.AutoContainmentRequested,
		ReportedBy:               actorDID,
		ReportedAt:               reportedAt,
		ExpiresAt:                cloneTimePtr(req.ExpiresAt),
		Metadata:                 cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidents = append(run.result.FederationIncidents, incident)
	responseID := secureCellUpsertFederationIncidentResponseForLocalIncident(run, incident)
	run.result.UpdatedAt = reportedAt
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_published", incident.ID),
		Action:           "secure_cell.federation_incident_published",
		Actor:            actorDID,
		TargetType:       "federation_incident",
		TargetDID:        incident.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_id":           incident.ID,
			"federation_organization_id":       incident.OrganizationID,
			"federation_sponsor_of_record":     incident.SponsorOfRecord,
			"federation_incident_status":       string(incident.Status),
			"federation_incident_severity":     string(incident.Severity),
			"federation_incident_category":     string(incident.Category),
			"federation_contract_ids":          strings.Join(incident.ContractIDs, ","),
			"federation_session_ids":           strings.Join(incident.SessionIDs, ","),
			"federation_thread_ids":            strings.Join(incident.ThreadIDs, ","),
			"federation_shared_output_ids":     strings.Join(incident.SharedOutputIDs, ","),
			"federation_session_exchange_ids": strings.Join(incident.SessionExchangeIDs, ","),
			"federation_incident_summary":      incident.Summary,
			"federation_incident_auto_containment": fmt.Sprintf("%t", incident.AutoContainmentRequested),
			"federation_incident_response_id": responseID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ResolveFederationIncident resolves one local federation incident.
func (s *Service) ResolveFederationIncident(ctx context.Context, cellID string, organizationID string, incidentID string, req SecureCellFederationIncidentResolveRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	incidentIdx, incident := findSecureCellFederationIncident(run.result.FederationIncidents, incidentID)
	if incident == nil || !strings.EqualFold(strings.TrimSpace(incident.OrganizationID), strings.TrimSpace(organizationID)) {
		return nil, fmt.Errorf("securecells/federation-incident: %w: %q", ErrFederationOrganizationNotFound, organizationID)
	}
	if incident.Status != SecureCellFederationIncidentStatusOpen {
		return nil, fmt.Errorf("securecells/federation-incident: incident %q is %s", incidentID, incident.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident: %w: actor %q is not permitted to resolve incidents", ErrPolicyDenied, actorDID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "resolve_federation_incident", lastReceiptHash(run.result), map[string]string{
		"federation_incident_id":        incident.ID,
		"federation_organization_id":    incident.OrganizationID,
		"federation_sponsor_of_record":  incident.SponsorOfRecord,
		"federation_incident_status_before": string(incident.Status),
		"federation_incident_status_after":  string(SecureCellFederationIncidentStatusResolved),
		"federation_incident_severity":  string(incident.Severity),
		"federation_incident_category":  string(incident.Category),
		"transition_reason":             strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	run.result.FederationIncidents[incidentIdx].Status = SecureCellFederationIncidentStatusResolved
	run.result.FederationIncidents[incidentIdx].ResolvedBy = actorDID
	run.result.FederationIncidents[incidentIdx].ResolvedAt = cloneTimePtr(&now)
	run.result.FederationIncidents[incidentIdx].ResolutionReason = strings.TrimSpace(req.Reason)
	run.result.FederationIncidents[incidentIdx].Metadata = mergeStringMaps(run.result.FederationIncidents[incidentIdx].Metadata, req.Metadata)
	secureCellUpdateFederationIncidentResponseStatusForResolution(run.result, incident.ID, now, actorDID)
	run.result.UpdatedAt = now
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_resolved", incident.ID),
		Action:           "secure_cell.federation_incident_resolved",
		Actor:            actorDID,
		TargetType:       "federation_incident",
		TargetDID:        incident.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_id":            incident.ID,
			"federation_organization_id":        incident.OrganizationID,
			"federation_sponsor_of_record":      incident.SponsorOfRecord,
			"federation_incident_status":        string(SecureCellFederationIncidentStatusResolved),
			"federation_incident_severity":      string(incident.Severity),
			"federation_incident_category":      string(incident.Category),
			"federation_incident_response_ids":  strings.Join(secureCellFederationIncidentResponseIDsForIncident(run.result.FederationIncidentResponses, incident.ID), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationIncidents returns operator-facing local incident summaries.
func (s *Service) ListFederationIncidents(_ context.Context, filter SecureCellFederationIncidentFilter) ([]SecureCellFederationIncidentSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, incident := range run.result.FederationIncidents {
			summary := secureCellFederationIncidentSummaryFromRun(run, incident)
			if !matchesSecureCellFederationIncidentFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReportedAt.Equal(items[j].ReportedAt) {
			if secureCellFederationIncidentSeverityRank(items[i].Severity) == secureCellFederationIncidentSeverityRank(items[j].Severity) {
				return items[i].IncidentID < items[j].IncidentID
			}
			return secureCellFederationIncidentSeverityRank(items[i].Severity) > secureCellFederationIncidentSeverityRank(items[j].Severity)
		}
		return items[i].ReportedAt.After(items[j].ReportedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// BuildFederationIncidentBulletin builds the signed portable incident bulletin
// for one collaborating organization in one secure cell.
func (s *Service) BuildFederationIncidentBulletin(ctx context.Context, cellID string, organizationID string, options SecureCellFederationIncidentBulletinOptions) (*SecureCellFederationIncidentBulletin, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	summary, org, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	incidents, err := s.ListFederationIncidents(ctx, SecureCellFederationIncidentFilter{
		CellID:         cellID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bulletin := &SecureCellFederationIncidentBulletin{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-federation-incident-bulletin-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(strings.TrimSpace(organizationID))))),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), "Federation Incident Bulletin"),
		GeneratedAt:      now,
		ExpiresAt:        cloneTimePtr(&expiresAt),
		CellID:           strings.TrimSpace(run.result.CellID),
		CellName:         strings.TrimSpace(run.result.Name),
		CellStatus:       run.result.Status,
		Jurisdiction:     strings.TrimSpace(run.request.Jurisdiction),
		Framework:        firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:     summary,
		Runtime:          secureCellFederationRuntimeForOrganization(run, *org),
		Contracts:        secureCellFederationContractSummariesForOrganization(run, strings.TrimSpace(organizationID)),
		Incidents:        append([]SecureCellFederationIncidentSummary(nil), incidents...),
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:         cloneStringMap(options.Metadata),
	}
	if run.result.ControlLedger != nil && run.result.ControlLedger.Bundle != nil {
		bulletin.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		bulletin.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		bulletin.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		bulletin.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		bulletin.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	if s.config.FederationIncidentBulletinSigner != nil {
		if err := s.config.FederationIncidentBulletinSigner(ctx, bulletin); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident: external bulletin signing failed: %w", err)
		}
	} else if err := SignFederationIncidentBulletinEd25519(bulletin, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bulletin, nil
}

// VerifyFederationIncidentBulletin validates one signed incident bulletin.
func VerifyFederationIncidentBulletin(bulletin *SecureCellFederationIncidentBulletin) error {
	if bulletin == nil {
		return fmt.Errorf("securecells/federation-incident: bulletin is required")
	}
	digest := secureCellFederationIncidentBulletinDigest(bulletin)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bulletin.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bulletin.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident: content hash mismatch")
	}
	if bulletin.Signature == nil {
		return fmt.Errorf("securecells/federation-incident: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bulletin.Signature.Algorithm)); algorithm != secureCellFederationIncidentBulletinSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident: unsupported signature algorithm %q", bulletin.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bulletin.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bulletin.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident: signature verification failed")
	}
	return nil
}

// SignFederationIncidentBulletinEd25519 signs one incident bulletin.
func SignFederationIncidentBulletinEd25519(bulletin *SecureCellFederationIncidentBulletin, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bulletin == nil {
		return fmt.Errorf("securecells/federation-incident: bulletin is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident: ed25519 private key is required")
	}
	digest := secureCellFederationIncidentBulletinDigest(bulletin)
	signature := ed25519.Sign(privateKey, digest[:])
	sig := &SecureCellFederationIncidentBulletinSignature{
		Algorithm: secureCellFederationIncidentBulletinSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		SignedAt:  time.Now().UTC(),
		Signature: hex.EncodeToString(signature),
	}
	if includeVerificationKeys {
		publicKey := privateKey.Public().(ed25519.PublicKey)
		sig.PublicKey = hex.EncodeToString(publicKey)
		if sig.KeyID == "" {
			keyDigest := sha256.Sum256(publicKey)
			sig.KeyID = hex.EncodeToString(keyDigest[:8])
		}
	}
	bulletin.Signature = sig
	bulletin.ContentHash = hex.EncodeToString(digest[:])
	return nil
}

// IngestFederationIncidentBulletin imports one signed counterparty incident
// bulletin and binds it into the secure-cell evidence chain.
func (s *Service) IngestFederationIncidentBulletin(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentBulletinIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if intake.Bulletin == nil {
		return nil, fmt.Errorf("securecells/federation-incident: bulletin is required")
	}
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident: %w: actor %q is not permitted to ingest incident bulletins", ErrPolicyDenied, actorDID)
	}
	status := SecureCellFederationCounterpartyIncidentStatusVerified
	verificationMessage := "verified"
	if err := VerifyFederationIncidentBulletin(intake.Bulletin); err != nil {
		status = SecureCellFederationCounterpartyIncidentStatusInvalid
		verificationMessage = err.Error()
	}
	if status != SecureCellFederationCounterpartyIncidentStatusInvalid {
		if !strings.EqualFold(strings.TrimSpace(intake.Bulletin.Organization.OrganizationID), strings.TrimSpace(organizationID)) {
			status = SecureCellFederationCounterpartyIncidentStatusInvalid
			verificationMessage = fmt.Sprintf("organization mismatch: expected %q", strings.TrimSpace(organizationID))
		}
	}
	now := time.Now().UTC()
	if status == SecureCellFederationCounterpartyIncidentStatusVerified {
		if intake.Bulletin.ExpiresAt != nil && !intake.Bulletin.ExpiresAt.After(now) {
			status = SecureCellFederationCounterpartyIncidentStatusExpired
			verificationMessage = "incident bulletin expired"
		} else if now.Sub(intake.Bulletin.GeneratedAt.UTC()) > 24*time.Hour {
			status = SecureCellFederationCounterpartyIncidentStatusStale
			verificationMessage = "incident bulletin is stale"
		}
	}
	contractIDs := secureCellFederationContractIDsForOrganization(run, strings.TrimSpace(summary.OrganizationID))
	snapshot := SecureCellFederationCounterpartyIncidentSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(intake.Bulletin.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		ContractIDs:         append([]string(nil), contractIDs...),
		Bulletin:            secureCellCloneFederationIncidentBulletin(*intake.Bulletin),
		Status:              status,
		Verified:            status == SecureCellFederationCounterpartyIncidentStatusVerified || status == SecureCellFederationCounterpartyIncidentStatusStale,
		VerificationMessage: verificationMessage,
		Signer:              safeString(intake.Bulletin.Signature, func(sig *SecureCellFederationIncidentBulletinSignature) string { return strings.TrimSpace(sig.Signer) }),
		ReceivedBy:          actorDID,
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_bulletin", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":      snapshot.OrganizationID,
		"federation_sponsor_of_record":    summary.SponsorOfRecord,
		"federation_incident_bulletin_id": snapshot.Bulletin.ID,
		"federation_incident_bulletin_status": string(snapshot.Status),
		"federation_contract_ids":         strings.Join(snapshot.ContractIDs, ","),
		"federation_incident_count":       fmt.Sprintf("%d", len(snapshot.Bulletin.Incidents)),
		"transition_reason":               strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident: %w", ErrPolicyDenied)
	}
	run.result.FederationCounterpartyIncidents = append(run.result.FederationCounterpartyIncidents, snapshot)
	responseIDs := secureCellUpsertFederationIncidentResponsesForCounterpartySnapshot(run, snapshot)
	run.result.UpdatedAt = now
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_bulletin_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_bulletin_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_bulletin",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":          snapshot.OrganizationID,
			"federation_sponsor_of_record":        summary.SponsorOfRecord,
			"federation_incident_bulletin_id":     snapshot.Bulletin.ID,
			"federation_incident_bulletin_status": string(snapshot.Status),
			"federation_contract_ids":             strings.Join(snapshot.ContractIDs, ","),
			"federation_incident_count":           fmt.Sprintf("%d", len(snapshot.Bulletin.Incidents)),
			"federation_incident_response_ids":    strings.Join(responseIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationCounterpartyIncidents returns imported incident bulletins as
// operator-facing summaries.
func (s *Service) ListFederationCounterpartyIncidents(_ context.Context, filter SecureCellFederationCounterpartyIncidentFilter) ([]SecureCellFederationCounterpartyIncidentSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidents {
			summary := secureCellFederationCounterpartyIncidentSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			return items[i].SnapshotID > items[j].SnapshotID
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// ListFederationIncidentActions returns incident-linked lifecycle and
// automated containment actions.
func (s *Service) ListFederationIncidentActions(_ context.Context, filter SecureCellFederationIncidentActionFilter) ([]SecureCellFederationIncidentActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// SweepFederationIncidents applies automated contract and collaboration
// containment in response to imported counterparty incident bulletins.
func (s *Service) SweepFederationIncidents(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident: service is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.RLock()
	cellIDs := make([]string, 0, len(s.runs))
	for cellID := range s.runs {
		cellIDs = append(cellIDs, cellID)
	}
	s.mu.RUnlock()
	sort.Strings(cellIDs)

	report := &SecureCellFederationIncidentSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutatedCells := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		latest := secureCellLatestCounterpartyIncidentSnapshots(run.result.FederationCounterpartyIncidents)
		if len(latest) == 0 {
			continue
		}
		report.BulletinsScanned += len(latest)
		for _, snapshot := range latest {
			if snapshot.Status == SecureCellFederationCounterpartyIncidentStatusInvalid || snapshot.Status == SecureCellFederationCounterpartyIncidentStatusExpired {
				continue
			}
			for _, incident := range snapshot.Bulletin.Incidents {
				if !secureCellFederationBulletinIncidentActionable(incident, at) {
					continue
				}
				report.IncidentsDetected++
				metadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
					"federation_incident_mode":           "automated",
					"federation_incident_trigger":        "counterparty_bulletin",
					"federation_incident_id":             incident.IncidentID,
					"federation_incident_status":         string(incident.Status),
					"federation_incident_severity":       string(incident.Severity),
					"federation_incident_category":       string(incident.Category),
					"federation_incident_bulletin_id":    snapshot.Bulletin.ID,
					"federation_counterparty_snapshot_id": snapshot.SnapshotID,
					"federation_organization_id":         snapshot.OrganizationID,
					"federation_sponsor_of_record":       incident.SponsorOfRecord,
				})
				if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
					metadata["automated_actor"] = automatedActor
				}
				affectedContracts := uniqueTrimmedStrings(append(append([]string(nil), incident.ContractIDs...), snapshot.ContractIDs...))
				if len(affectedContracts) == 0 {
					affectedContracts = secureCellFederationContractIDsForOrganization(run, snapshot.OrganizationID)
				}
				for _, contractID := range affectedContracts {
					contractRun, err := s.getRun(cellID)
					if err != nil {
						return nil, err
					}
					_, contract := findSecureCellFederationContract(contractRun.result.FederationContracts, contractID)
					if contract == nil || contract.Status != SecureCellFederationContractStatusActive {
						continue
					}
					result, err := s.SuspendFederationContract(ctx, cellID, contractID, SecureCellLifecycleRequest{
						ActorDID: run.request.OwnerIdentity.AgentID(),
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "automated federation incident containment"),
						Metadata: mergeStringMaps(metadata, map[string]string{
							"federation_incident_action": "suspend_contract",
							"federation_contract_id":     contractID,
						}),
					})
					if err != nil {
						return nil, err
					}
					report.ContractsSuspended++
					mutatedCells[cellID] = struct{}{}
					record := secureCellFederationIncidentActionRecordFromResult(result, map[string]string{
						"federation_incident_id":       incident.IncidentID,
						"federation_contract_id":       contractID,
						"federation_incident_action":   "suspend_contract",
						"federation_organization_id":   snapshot.OrganizationID,
						"federation_sponsor_of_record": incident.SponsorOfRecord,
					})
					if record != nil {
						report.Actions = append(report.Actions, *record)
					}
				}
				affectedSessions := uniqueTrimmedStrings(append([]string(nil), incident.SessionIDs...))
				if len(affectedSessions) == 0 {
					for _, contractID := range affectedContracts {
						if _, contract := findSecureCellFederationContract(run.result.FederationContracts, contractID); contract != nil {
							affectedSessions = append(affectedSessions, contract.SessionScopeIDs...)
						}
					}
					affectedSessions = uniqueTrimmedStrings(affectedSessions)
				}
				for _, sessionID := range affectedSessions {
					sessionRun, err := s.getRun(cellID)
					if err != nil {
						return nil, err
					}
					_, session := findSecureCellSession(sessionRun.result.Sessions, sessionID)
					if session == nil || session.Status != SecureCellSessionStatusActive {
						continue
					}
					result, err := s.QuarantineSession(ctx, cellID, sessionID, SecureCellLifecycleRequest{
						ActorDID: run.request.OwnerIdentity.AgentID(),
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "automated federation incident session containment"),
						Metadata: mergeStringMaps(metadata, map[string]string{
							"federation_incident_action": "quarantine_session",
							"session_id":                 sessionID,
						}),
					})
					if err != nil {
						return nil, err
					}
					report.SessionsQuarantined++
					mutatedCells[cellID] = struct{}{}
					record := secureCellFederationIncidentActionRecordFromResult(result, map[string]string{
						"federation_incident_id":       incident.IncidentID,
						"session_id":                   sessionID,
						"federation_incident_action":   "quarantine_session",
						"federation_organization_id":   snapshot.OrganizationID,
						"federation_sponsor_of_record": incident.SponsorOfRecord,
					})
					if record != nil {
						report.Actions = append(report.Actions, *record)
					}
				}
				for _, threadID := range uniqueTrimmedStrings(incident.ThreadIDs) {
					threadRun, err := s.getRun(cellID)
					if err != nil {
						return nil, err
					}
					_, thread := findSecureCellThread(threadRun.result.Threads, threadID)
					if thread == nil || thread.Status != SecureCellThreadStatusActive {
						continue
					}
					_, session := findSecureCellSession(threadRun.result.Sessions, thread.SessionID)
					if session == nil || session.Status != SecureCellSessionStatusActive {
						continue
					}
					result, err := s.QuarantineThread(ctx, cellID, thread.SessionID, threadID, SecureCellLifecycleRequest{
						ActorDID: run.request.OwnerIdentity.AgentID(),
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "automated federation incident thread containment"),
						Metadata: mergeStringMaps(metadata, map[string]string{
							"federation_incident_action": "quarantine_thread",
							"thread_id":                  threadID,
						}),
					})
					if err != nil {
						return nil, err
					}
					report.ThreadsQuarantined++
					mutatedCells[cellID] = struct{}{}
					record := secureCellFederationIncidentActionRecordFromResult(result, map[string]string{
						"federation_incident_id":       incident.IncidentID,
						"thread_id":                    threadID,
						"federation_incident_action":   "quarantine_thread",
						"federation_organization_id":   snapshot.OrganizationID,
						"federation_sponsor_of_record": incident.SponsorOfRecord,
					})
					if record != nil {
						report.Actions = append(report.Actions, *record)
					}
				}
				contained, actionRecord, err := s.containFederationIncidentArtifacts(ctx, cellID, snapshot.OrganizationID, incident, SecureCellLifecycleRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), "automated federation incident artifact containment"),
					Metadata: mergeStringMaps(metadata, map[string]string{
						"federation_incident_action": "contain_artifacts",
					}),
				})
				if err != nil {
					return nil, err
				}
				if contained > 0 {
					report.ArtifactsContained += contained
					mutatedCells[cellID] = struct{}{}
					if actionRecord != nil {
						report.Actions = append(report.Actions, *actionRecord)
					}
				}
			}
		}
	}
	if len(mutatedCells) > 0 {
		report.CellIDs = make([]string, 0, len(mutatedCells))
		for cellID := range mutatedCells {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func (s *Service) containFederationIncidentArtifacts(ctx context.Context, cellID string, organizationID string, incident SecureCellFederationIncidentSummary, lifecycle SecureCellLifecycleRequest) (int, *SecureCellFederationIncidentActionRecord, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return 0, nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return 0, nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return 0, nil, fmt.Errorf("securecells/federation-incident: %w: actor %q is not permitted to contain artifacts", ErrPolicyDenied, actorDID)
	}
	outputIdxs := make([]int, 0)
	exchangeIdxs := make([]int, 0)
	for idx, output := range run.result.SharedOutputs {
		if output.ContainmentStatus == SecureCellArtifactContainmentStatusContained && strings.EqualFold(strings.TrimSpace(output.ContainmentSourceID), strings.TrimSpace(incident.IncidentID)) {
			continue
		}
		if secureCellFederationIncidentMatchesOutput(incident, organizationID, output) {
			outputIdxs = append(outputIdxs, idx)
		}
	}
	for idx, item := range run.result.SessionExchanges {
		if item.ContainmentStatus == SecureCellArtifactContainmentStatusContained && strings.EqualFold(strings.TrimSpace(item.ContainmentSourceID), strings.TrimSpace(incident.IncidentID)) {
			continue
		}
		if secureCellFederationIncidentMatchesExchange(incident, organizationID, item) {
			exchangeIdxs = append(exchangeIdxs, idx)
		}
	}
	if len(outputIdxs) == 0 && len(exchangeIdxs) == 0 {
		return 0, nil, nil
	}
	receipt, err := s.evaluateStage(ctx, run.request, "contain_federation_incident_artifacts", lastReceiptHash(run.result), map[string]string{
		"federation_incident_id":        incident.IncidentID,
		"federation_organization_id":    strings.TrimSpace(organizationID),
		"federation_incident_severity":  string(incident.Severity),
		"federation_incident_category":  string(incident.Category),
		"federation_shared_output_ids":  strings.Join(incident.SharedOutputIDs, ","),
		"federation_session_exchange_ids": strings.Join(incident.SessionExchangeIDs, ","),
		"federation_artifact_output_total": fmt.Sprintf("%d", len(outputIdxs)),
		"federation_artifact_exchange_total": fmt.Sprintf("%d", len(exchangeIdxs)),
		"transition_reason":             strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return 0, nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return 0, nil, fmt.Errorf("securecells/federation-incident: %w", ErrPolicyDenied)
	}
	now := time.Now().UTC()
	outputIDs := make([]string, 0, len(outputIdxs))
	exchangeIDs := make([]string, 0, len(exchangeIdxs))
	for _, idx := range outputIdxs {
		run.result.SharedOutputs[idx].ContainmentStatus = SecureCellArtifactContainmentStatusContained
		run.result.SharedOutputs[idx].ContainmentDecisionID = ""
		run.result.SharedOutputs[idx].ContainmentSourceType = "federation_incident"
		run.result.SharedOutputs[idx].ContainmentSourceID = incident.IncidentID
		run.result.SharedOutputs[idx].ContainmentReceiptID = receipt.ID
		run.result.SharedOutputs[idx].ContainmentReceiptHash = receipt.ContentHash
		run.result.SharedOutputs[idx].ContainmentSealID = ""
		run.result.SharedOutputs[idx].ContainmentTraceLinkID = ""
		run.result.SharedOutputs[idx].ContainedBy = actorDID
		run.result.SharedOutputs[idx].ContainedAt = &now
		run.result.SharedOutputs[idx].ReleasedBy = ""
		run.result.SharedOutputs[idx].ReleasedAt = nil
		outputIDs = append(outputIDs, run.result.SharedOutputs[idx].ID)
	}
	for _, idx := range exchangeIdxs {
		run.result.SessionExchanges[idx].ContainmentStatus = SecureCellArtifactContainmentStatusContained
		run.result.SessionExchanges[idx].ContainmentDecisionID = ""
		run.result.SessionExchanges[idx].ContainmentSourceType = "federation_incident"
		run.result.SessionExchanges[idx].ContainmentSourceID = incident.IncidentID
		run.result.SessionExchanges[idx].ContainmentReceiptID = receipt.ID
		run.result.SessionExchanges[idx].ContainmentReceiptHash = receipt.ContentHash
		run.result.SessionExchanges[idx].ContainmentSealID = ""
		run.result.SessionExchanges[idx].ContainmentTraceLinkID = ""
		run.result.SessionExchanges[idx].ContainedBy = actorDID
		run.result.SessionExchanges[idx].ContainedAt = &now
		run.result.SessionExchanges[idx].ReleasedBy = ""
		run.result.SessionExchanges[idx].ReleasedAt = nil
		exchangeIDs = append(exchangeIDs, run.result.SessionExchanges[idx].ID)
	}
	run.result.UpdatedAt = now
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_artifacts_contained", incident.IncidentID),
		Action:           "secure_cell.federation_incident_artifacts_contained",
		Actor:            actorDID,
		TargetType:       "federation_incident_artifacts",
		TargetDID:        incident.IncidentID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_incident_id":         incident.IncidentID,
			"federation_organization_id":     strings.TrimSpace(organizationID),
			"federation_incident_status":     string(incident.Status),
			"federation_incident_severity":   string(incident.Severity),
			"federation_incident_category":   string(incident.Category),
			"federation_shared_output_ids":   strings.Join(outputIDs, ","),
			"federation_session_exchange_ids": strings.Join(exchangeIDs, ","),
			"containment_mode":               "federation_incident_artifacts",
			"containment_status":             string(SecureCellArtifactContainmentStatusContained),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return 0, nil, err
	}
	s.setRun(run)
	result, err := cloneResult(run.result)
	if err != nil {
		return 0, nil, err
	}
	return len(outputIDs) + len(exchangeIDs), secureCellFederationIncidentActionRecordFromResult(result, map[string]string{
		"federation_incident_id":       incident.IncidentID,
		"federation_organization_id":   strings.TrimSpace(organizationID),
		"federation_incident_action":   "contain_artifacts",
		"federation_shared_output_ids": strings.Join(outputIDs, ","),
		"federation_session_exchange_ids": strings.Join(exchangeIDs, ","),
	}), nil
}

func secureCellFederationIncidentID(req SecureCellRequest, organizationID string, severity SecureCellFederationIncidentSeverity, category SecureCellFederationIncidentCategory, summary string, at time.Time) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s|%s", cellID(req), strings.TrimSpace(organizationID), strings.TrimSpace(string(severity)), strings.TrimSpace(string(category)), strings.TrimSpace(summary), at.UTC().Format(time.RFC3339Nano))
	return fmt.Sprintf("%s-federation-incident-%x", cellID(req), sha256.Sum256([]byte(seed)))
}

func findSecureCellFederationIncident(items []SecureCellFederationIncident, incidentID string) (int, *SecureCellFederationIncident) {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return -1, nil
	}
	for idx := range items {
		if strings.EqualFold(strings.TrimSpace(items[idx].ID), incidentID) {
			return idx, &items[idx]
		}
	}
	return -1, nil
}

func secureCellNormalizeFederationIncidentTargets(run *secureCellRun, organizationID string, contractIDs []string, sessionIDs []string, threadIDs []string, sharedOutputIDs []string, sessionExchangeIDs []string) (secureCellFederationIncidentTargetSet, error) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: secure cell result is required")
	}
	organizationID = strings.TrimSpace(organizationID)
	normalized := secureCellFederationIncidentTargetSet{
		contractIDs:        uniqueTrimmedStrings(contractIDs),
		sessionIDs:         uniqueTrimmedStrings(sessionIDs),
		threadIDs:          uniqueTrimmedStrings(threadIDs),
		sharedOutputIDs:    uniqueTrimmedStrings(sharedOutputIDs),
		sessionExchangeIDs: uniqueTrimmedStrings(sessionExchangeIDs),
	}
	for _, contractID := range normalized.contractIDs {
		_, contract := findSecureCellFederationContract(run.result.FederationContracts, contractID)
		if contract == nil || !strings.EqualFold(strings.TrimSpace(contract.OrganizationID), organizationID) {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: %w: contract %q does not belong to organization %q", ErrFederationContractNotFound, contractID, organizationID)
		}
		normalized.sessionIDs = append(normalized.sessionIDs, contract.SessionScopeIDs...)
	}
	for _, sessionID := range normalized.sessionIDs {
		if _, session := findSecureCellSession(run.result.Sessions, sessionID); session == nil {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: %w: %q", ErrSessionNotFound, sessionID)
		}
	}
	for _, threadID := range normalized.threadIDs {
		_, thread := findSecureCellThread(run.result.Threads, threadID)
		if thread == nil {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: %w: %q", ErrThreadNotFound, threadID)
		}
		normalized.sessionIDs = append(normalized.sessionIDs, thread.SessionID)
	}
	for _, outputID := range normalized.sharedOutputIDs {
		idx := findSecureCellSharedOutputIndex(run.result.SharedOutputs, outputID)
		if idx < 0 {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: shared output %q not found", outputID)
		}
		output := run.result.SharedOutputs[idx]
		if !secureCellFederationOutputBelongsToOrganization(output, organizationID) {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: shared output %q is not linked to organization %q", outputID, organizationID)
		}
		normalized.sessionIDs = append(normalized.sessionIDs, output.SessionID)
		normalized.contractIDs = append(normalized.contractIDs, output.FederationContractIDs...)
	}
	for _, exchangeID := range normalized.sessionExchangeIDs {
		idx := findSecureCellSessionExchangeIndex(run.result.SessionExchanges, exchangeID)
		if idx < 0 {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: session exchange %q not found", exchangeID)
		}
		item := run.result.SessionExchanges[idx]
		if !secureCellFederationExchangeBelongsToOrganization(item, organizationID) {
			return secureCellFederationIncidentTargetSet{}, fmt.Errorf("securecells/federation-incident: session exchange %q is not linked to organization %q", exchangeID, organizationID)
		}
		normalized.sessionIDs = append(normalized.sessionIDs, item.SessionID)
		if strings.TrimSpace(item.ThreadID) != "" {
			normalized.threadIDs = append(normalized.threadIDs, item.ThreadID)
		}
		normalized.contractIDs = append(normalized.contractIDs, item.FederationContractIDs...)
	}
	normalized.contractIDs = uniqueTrimmedStrings(normalized.contractIDs)
	normalized.sessionIDs = uniqueTrimmedStrings(normalized.sessionIDs)
	normalized.threadIDs = uniqueTrimmedStrings(normalized.threadIDs)
	normalized.sharedOutputIDs = uniqueTrimmedStrings(normalized.sharedOutputIDs)
	normalized.sessionExchangeIDs = uniqueTrimmedStrings(normalized.sessionExchangeIDs)
	return normalized, nil
}

func secureCellFederationIncidentSummaryFromRun(run *secureCellRun, incident SecureCellFederationIncident) SecureCellFederationIncidentSummary {
	return SecureCellFederationIncidentSummary{
		CellID:                   strings.TrimSpace(run.result.CellID),
		CellName:                 strings.TrimSpace(run.result.Name),
		CellStatus:               run.result.Status,
		Jurisdiction:             strings.TrimSpace(run.request.Jurisdiction),
		IncidentID:               strings.TrimSpace(incident.ID),
		OrganizationID:           strings.TrimSpace(incident.OrganizationID),
		SponsorOfRecord:          strings.TrimSpace(incident.SponsorOfRecord),
		OrganizationName:         strings.TrimSpace(incident.OrganizationName),
		Status:                   incident.Status,
		Severity:                 incident.Severity,
		Category:                 incident.Category,
		Summary:                  incident.Summary,
		Description:              incident.Description,
		ContractIDs:              append([]string(nil), incident.ContractIDs...),
		SessionIDs:               append([]string(nil), incident.SessionIDs...),
		ThreadIDs:                append([]string(nil), incident.ThreadIDs...),
		SharedOutputIDs:          append([]string(nil), incident.SharedOutputIDs...),
		SessionExchangeIDs:       append([]string(nil), incident.SessionExchangeIDs...),
		ContractCount:            len(incident.ContractIDs),
		SessionCount:             len(incident.SessionIDs),
		ThreadCount:              len(incident.ThreadIDs),
		SharedOutputCount:        len(incident.SharedOutputIDs),
		SessionExchangeCount:     len(incident.SessionExchangeIDs),
		AutoContainmentRequested: incident.AutoContainmentRequested,
		ReportedBy:               strings.TrimSpace(incident.ReportedBy),
		ReportedAt:               incident.ReportedAt.UTC(),
		ExpiresAt:                cloneTimePtr(incident.ExpiresAt),
		ResolvedBy:               strings.TrimSpace(incident.ResolvedBy),
		ResolvedAt:               cloneTimePtr(incident.ResolvedAt),
		ResolutionReason:         strings.TrimSpace(incident.ResolutionReason),
	}
}

func secureCellLatestCounterpartyIncidentSnapshots(items []SecureCellFederationCounterpartyIncidentSnapshot) []SecureCellFederationCounterpartyIncidentSnapshot {
	if len(items) == 0 {
		return nil
	}
	latest := make(map[string]SecureCellFederationCounterpartyIncidentSnapshot, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item.OrganizationID)
		current, ok := latest[key]
		if !ok || item.ReceivedAt.After(current.ReceivedAt) {
			latest[key] = item
		}
	}
	out := make([]SecureCellFederationCounterpartyIncidentSnapshot, 0, len(latest))
	for _, item := range latest {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ReceivedAt.After(out[j].ReceivedAt)
	})
	return out
}

func secureCellFederationCounterpartyIncidentSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentSnapshot) SecureCellFederationCounterpartyIncidentSummary {
	openCount := 0
	criticalCount := 0
	highCount := 0
	for _, incident := range snapshot.Bulletin.Incidents {
		if incident.Status == SecureCellFederationIncidentStatusOpen {
			openCount++
		}
		if incident.Severity == SecureCellFederationIncidentSeverityCritical {
			criticalCount++
		}
		if incident.Severity == SecureCellFederationIncidentSeverityHigh {
			highCount++
		}
	}
	return SecureCellFederationCounterpartyIncidentSummary{
		CellID:                  strings.TrimSpace(run.result.CellID),
		CellName:                strings.TrimSpace(run.result.Name),
		CellStatus:              run.result.Status,
		Jurisdiction:            strings.TrimSpace(run.request.Jurisdiction),
		OrganizationID:          strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:         strings.TrimSpace(snapshot.Bulletin.Organization.SponsorOfRecord),
		OrganizationName:        strings.TrimSpace(snapshot.Bulletin.Organization.OrganizationName),
		SnapshotID:              strings.TrimSpace(snapshot.SnapshotID),
		BulletinID:              strings.TrimSpace(snapshot.Bulletin.ID),
		BulletinVersion:         strings.TrimSpace(snapshot.Bulletin.Version),
		BulletinName:            strings.TrimSpace(snapshot.Bulletin.Name),
		Status:                  snapshot.Status,
		Verified:                snapshot.Verified,
		Signer:                  strings.TrimSpace(snapshot.Signer),
		KeyID:                   safeString(snapshot.Bulletin.Signature, func(sig *SecureCellFederationIncidentBulletinSignature) string { return strings.TrimSpace(sig.KeyID) }),
		ContractIDs:             append([]string(nil), snapshot.ContractIDs...),
		IncidentCount:           len(snapshot.Bulletin.Incidents),
		OpenIncidentCount:       openCount,
		CriticalIncidentCount:   criticalCount,
		HighIncidentCount:       highCount,
		GeneratedAt:             snapshot.Bulletin.GeneratedAt.UTC(),
		ExpiresAt:               cloneTimePtr(snapshot.Bulletin.ExpiresAt),
		ReceivedAt:              snapshot.ReceivedAt.UTC(),
		ControlLedgerID:         strings.TrimSpace(snapshot.Bulletin.ControlLedgerID),
		ControlLedgerHash:       strings.TrimSpace(snapshot.Bulletin.ControlLedgerHash),
		PortablePackageHash:     strings.TrimSpace(snapshot.Bulletin.PortablePackageHash),
		PortablePackageSigned:   snapshot.Bulletin.PortablePackageSigned,
		PortablePackageAnchored: snapshot.Bulletin.PortablePackageAnchored,
		VerificationMessage:     strings.TrimSpace(snapshot.VerificationMessage),
	}
}

func secureCellFederationContractIDsForOrganization(run *secureCellRun, organizationID string) []string {
	out := make([]string, 0)
	if run == nil || run.result == nil {
		return out
	}
	for _, contract := range run.result.FederationContracts {
		if strings.EqualFold(strings.TrimSpace(contract.OrganizationID), strings.TrimSpace(organizationID)) {
			out = append(out, contract.ID)
		}
	}
	return uniqueTrimmedStrings(out)
}

func secureCellFederationOutputBelongsToOrganization(output SecureCellSharedOutput, organizationID string) bool {
	return secureCellStringSliceContains(output.FederationOrgIDs, organizationID)
}

func secureCellFederationExchangeBelongsToOrganization(item SecureCellSessionExchange, organizationID string) bool {
	return secureCellStringSliceContains(item.FederationOrgIDs, organizationID)
}

func secureCellFederationIncidentMatchesOutput(incident SecureCellFederationIncidentSummary, organizationID string, output SecureCellSharedOutput) bool {
	if len(incident.SharedOutputIDs) > 0 {
		return secureCellStringSliceContains(incident.SharedOutputIDs, output.ID)
	}
	if len(incident.ContractIDs) > 0 {
		for _, contractID := range incident.ContractIDs {
			if secureCellStringSliceContains(output.FederationContractIDs, contractID) {
				return true
			}
		}
	}
	return secureCellFederationOutputBelongsToOrganization(output, organizationID)
}

func secureCellFederationIncidentMatchesExchange(incident SecureCellFederationIncidentSummary, organizationID string, item SecureCellSessionExchange) bool {
	if len(incident.SessionExchangeIDs) > 0 {
		return secureCellStringSliceContains(incident.SessionExchangeIDs, item.ID)
	}
	if len(incident.ContractIDs) > 0 {
		for _, contractID := range incident.ContractIDs {
			if secureCellStringSliceContains(item.FederationContractIDs, contractID) {
				return true
			}
		}
	}
	return secureCellFederationExchangeBelongsToOrganization(item, organizationID)
}

func secureCellFederationBulletinIncidentActionable(incident SecureCellFederationIncidentSummary, at time.Time) bool {
	if incident.Status != SecureCellFederationIncidentStatusOpen {
		return false
	}
	if incident.ExpiresAt != nil && !incident.ExpiresAt.After(at.UTC()) {
		return false
	}
	return incident.AutoContainmentRequested || secureCellFederationIncidentSeverityRank(incident.Severity) >= secureCellFederationIncidentSeverityRank(SecureCellFederationIncidentSeverityHigh)
}

func secureCellFederationIncidentActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentActionRecord, bool) {
	incidentID := strings.TrimSpace(transition.Metadata["federation_incident_id"])
	if incidentID == "" {
		return SecureCellFederationIncidentActionRecord{}, false
	}
	record := SecureCellFederationIncidentActionRecord{
		CellID:            strings.TrimSpace(run.result.CellID),
		CellName:          strings.TrimSpace(run.result.Name),
		Jurisdiction:      strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:        run.result.Status,
		OrganizationID:    strings.TrimSpace(transition.Metadata["federation_organization_id"]),
		SponsorOfRecord:   strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
		IncidentID:        incidentID,
		IncidentStatus:    SecureCellFederationIncidentStatus(strings.TrimSpace(transition.Metadata["federation_incident_status"])),
		Severity:          SecureCellFederationIncidentSeverity(strings.TrimSpace(transition.Metadata["federation_incident_severity"])),
		Category:          SecureCellFederationIncidentCategory(strings.TrimSpace(transition.Metadata["federation_incident_category"])),
		ContractID:        firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_contract_id"]), strings.TrimSpace(transition.Metadata["contract_id"])),
		SessionID:         firstNonEmpty(strings.TrimSpace(transition.SessionID), strings.TrimSpace(transition.Metadata["session_id"])),
		ThreadID:          firstNonEmpty(strings.TrimSpace(transition.ThreadID), strings.TrimSpace(transition.Metadata["thread_id"])),
		SharedOutputIDs:   uniqueTrimmedStrings(strings.Split(strings.TrimSpace(transition.Metadata["federation_shared_output_ids"]), ",")),
		SessionExchangeIDs: uniqueTrimmedStrings(strings.Split(strings.TrimSpace(transition.Metadata["federation_session_exchange_ids"]), ",")),
		Action:            firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_incident_action"]), strings.TrimSpace(transition.Action)),
		Trigger:           strings.TrimSpace(transition.Metadata["federation_incident_trigger"]),
		Actor:             strings.TrimSpace(transition.Actor),
		AutomatedActor:    strings.TrimSpace(transition.Metadata["automated_actor"]),
		Reason:            strings.TrimSpace(transition.Reason),
		TransitionID:      strings.TrimSpace(transition.ID),
		OccurredAt:        transition.OccurredAt.UTC(),
		Metadata:          cloneStringMap(transition.Metadata),
	}
	return record, true
}

func secureCellFederationIncidentActionRecordFromResult(result *SecureCellResult, required map[string]string) *SecureCellFederationIncidentActionRecord {
	if result == nil || len(result.Transitions) == 0 {
		return nil
	}
	transition := result.Transitions[len(result.Transitions)-1]
	run := &secureCellRun{
		request: SecureCellRequest{Jurisdiction: ""},
		result:  result,
	}
	record, ok := secureCellFederationIncidentActionFromTransition(run, transition)
	if !ok {
		return nil
	}
	for key, value := range required {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.Metadata[key]), strings.TrimSpace(value)) && !strings.EqualFold(strings.TrimSpace(record.Action), strings.TrimSpace(value)) {
			return nil
		}
	}
	return &record
}

func matchesSecureCellFederationIncidentFilter(item SecureCellFederationIncidentSummary, filter SecureCellFederationIncidentFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" && !secureCellStringSliceContains(item.ContractIDs, strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Severity != "" && item.Severity != filter.Severity {
		return false
	}
	if filter.Category != "" && item.Category != filter.Category {
		return false
	}
	if filter.Since != nil && !filter.Since.IsZero() && item.ReportedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && !filter.Until.IsZero() && item.ReportedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func matchesSecureCellFederationCounterpartyIncidentFilter(item SecureCellFederationCounterpartyIncidentSummary, filter SecureCellFederationCounterpartyIncidentFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" && !secureCellStringSliceContains(item.ContractIDs, strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Signer != "" && !strings.EqualFold(strings.TrimSpace(item.Signer), strings.TrimSpace(filter.Signer)) {
		return false
	}
	return true
}

func matchesSecureCellFederationIncidentActionFilter(item SecureCellFederationIncidentActionRecord, filter SecureCellFederationIncidentActionFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" && !strings.EqualFold(strings.TrimSpace(item.ContractID), strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.Action != "" && !strings.EqualFold(strings.TrimSpace(item.Action), strings.TrimSpace(filter.Action)) {
		return false
	}
	if filter.Since != nil && !filter.Since.IsZero() && item.OccurredAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && !filter.Until.IsZero() && item.OccurredAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationIncidentSeverityAllowed(severity SecureCellFederationIncidentSeverity) bool {
	switch severity {
	case SecureCellFederationIncidentSeverityInfo,
		SecureCellFederationIncidentSeverityWarning,
		SecureCellFederationIncidentSeverityHigh,
		SecureCellFederationIncidentSeverityCritical:
		return true
	default:
		return false
	}
}

func secureCellFederationIncidentCategoryAllowed(category SecureCellFederationIncidentCategory) bool {
	switch category {
	case SecureCellFederationIncidentCategoryIdentityCompromise,
		SecureCellFederationIncidentCategoryCredentialCompromise,
		SecureCellFederationIncidentCategoryConfidentialComputeFailure,
		SecureCellFederationIncidentCategoryDataExposure,
		SecureCellFederationIncidentCategoryUnauthorizedExchange,
		SecureCellFederationIncidentCategoryPolicyBreach,
		SecureCellFederationIncidentCategoryMalwareOrTamper,
		SecureCellFederationIncidentCategoryCounterpartyOutage:
		return true
	default:
		return false
	}
}

func secureCellFederationIncidentSeverityRank(severity SecureCellFederationIncidentSeverity) int {
	switch severity {
	case SecureCellFederationIncidentSeverityCritical:
		return 4
	case SecureCellFederationIncidentSeverityHigh:
		return 3
	case SecureCellFederationIncidentSeverityWarning:
		return 2
	case SecureCellFederationIncidentSeverityInfo:
		return 1
	default:
		return 0
	}
}

func secureCellFederationIncidentsByStatus(items []SecureCellFederationIncident, status SecureCellFederationIncidentStatus) []SecureCellFederationIncident {
	if len(items) == 0 {
		return nil
	}
	status = SecureCellFederationIncidentStatus(strings.TrimSpace(string(status)))
	if status == "" {
		return append([]SecureCellFederationIncident(nil), items...)
	}
	filtered := make([]SecureCellFederationIncident, 0, len(items))
	for _, item := range items {
		if item.Status != status {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func secureCellFederationIncidentSeverityCount(items []SecureCellFederationIncident, severity SecureCellFederationIncidentSeverity) int {
	if len(items) == 0 {
		return 0
	}
	severity = SecureCellFederationIncidentSeverity(strings.TrimSpace(string(severity)))
	if severity == "" {
		return len(items)
	}
	count := 0
	for _, item := range items {
		if item.Severity == severity {
			count++
		}
	}
	return count
}

func secureCellFederationCounterpartyIncidentsByStatus(items []SecureCellFederationCounterpartyIncidentSnapshot, status SecureCellFederationCounterpartyIncidentStatus) []SecureCellFederationCounterpartyIncidentSnapshot {
	if len(items) == 0 {
		return nil
	}
	status = SecureCellFederationCounterpartyIncidentStatus(strings.TrimSpace(string(status)))
	if status == "" {
		return append([]SecureCellFederationCounterpartyIncidentSnapshot(nil), items...)
	}
	filtered := make([]SecureCellFederationCounterpartyIncidentSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status != status {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func secureCellCloneFederationIncidentBulletin(in SecureCellFederationIncidentBulletin) SecureCellFederationIncidentBulletin {
	out := in
	out.ExpiresAt = cloneTimePtr(in.ExpiresAt)
	out.Contracts = append([]SecureCellFederationContractSummary(nil), in.Contracts...)
	out.Incidents = append([]SecureCellFederationIncidentSummary(nil), in.Incidents...)
	out.OperatorSurfaces = cloneSecureCellFederationOperatorSurfaces(in.OperatorSurfaces)
	out.Metadata = cloneStringMap(in.Metadata)
	if in.Signature != nil {
		signature := *in.Signature
		out.Signature = &signature
	}
	return out
}

func secureCellFederationIncidentBulletinDigest(bulletin *SecureCellFederationIncidentBulletin) [32]byte {
	clone := secureCellCloneFederationIncidentBulletin(*bulletin)
	clone.Signature = nil
	clone.ContentHash = ""
	data, _ := json.Marshal(clone)
	return sha256.Sum256(data)
}
