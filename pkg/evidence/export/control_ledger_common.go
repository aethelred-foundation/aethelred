package export

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
)

const controlLedgerExportVersion = "1.0.0"

// ControlLedgerExport is the canonical export envelope for auditor-ready
// control ledger data. It is intentionally richer than the underlying ledger
// so that downstream systems can ingest a single verified snapshot.
type ControlLedgerExport struct {
	ExportVersion           string                                `json:"export_version"`
	ExportedAt              string                                `json:"exported_at"`
	LedgerID                string                                `json:"ledger_id,omitempty"`
	Framework               string                                `json:"framework,omitempty"`
	CreatedAt               string                                `json:"created_at,omitempty"`
	Version                 string                                `json:"version,omitempty"`
	Metadata                map[string]string                     `json:"metadata,omitempty"`
	Summary                 ControlLedgerSummary                  `json:"summary"`
	Passports               []ControlLedgerPassport               `json:"passports,omitempty"`
	Attestations            []ControlLedgerAttestation            `json:"attestations,omitempty"`
	ApproverAttestations    []ControlLedgerApproverAttestation    `json:"approver_attestations,omitempty"`
	ValueSettlements        []ControlLedgerValueSettlement        `json:"value_settlements,omitempty"`
	PolicyReceipts          []ControlLedgerPolicyReceipt          `json:"policy_receipts,omitempty"`
	Seals                   []ControlLedgerSeal                   `json:"seals,omitempty"`
	TraceLinks              []ControlLedgerTraceLink              `json:"trace_links,omitempty"`
	TrustCompliancePackages []ControlLedgerTrustCompliancePackage `json:"trust_compliance_packages,omitempty"`
	Controls                []ControlLedgerControl                `json:"controls,omitempty"`
}

// ControlLedgerSummary captures the aggregate posture of the exported ledger.
type ControlLedgerSummary struct {
	TotalControls                int  `json:"total_controls"`
	TotalPassports               int  `json:"total_passports"`
	TotalAttestations            int  `json:"total_attestations"`
	TotalApproverAttestations    int  `json:"total_approver_attestations"`
	TotalValueSettlements        int  `json:"total_value_settlements"`
	TotalPolicyReceipts          int  `json:"total_policy_receipts"`
	TotalSeals                   int  `json:"total_seals"`
	TotalTraceLinks              int  `json:"total_trace_links"`
	TotalTrustCompliancePackages int  `json:"total_trust_compliance_packages"`
	ChainIntact                  bool `json:"chain_intact"`
}

// ControlLedgerPassport exports the accountable agent identity context.
type ControlLedgerPassport struct {
	DID              string                         `json:"did"`
	Issuer           string                         `json:"issuer,omitempty"`
	PublicKeyHash    string                         `json:"public_key_hash,omitempty"`
	Capabilities     []string                       `json:"capabilities,omitempty"`
	SponsorChain     []ControlLedgerPassportSponsor `json:"sponsor_chain,omitempty"`
	HumanOwner       string                         `json:"human_owner,omitempty"`
	BusinessUnit     string                         `json:"business_unit,omitempty"`
	SponsorOfRecord  string                         `json:"sponsor_of_record,omitempty"`
	FallbackApprover string                         `json:"fallback_approver,omitempty"`
	IncidentContact  string                         `json:"incident_contact,omitempty"`
	LiabilityModel   string                         `json:"liability_model,omitempty"`
	JurisdictionTags []string                       `json:"jurisdiction_tags,omitempty"`
	AllowedTools     []string                       `json:"allowed_tools,omitempty"`
	IssuedAt         string                         `json:"issued_at,omitempty"`
	ExpiresAt        string                         `json:"expires_at,omitempty"`
	Metadata         map[string]string              `json:"metadata,omitempty"`
}

// ControlLedgerPassportSponsor records one sponsor in the passport chain.
type ControlLedgerPassportSponsor struct {
	SponsorDID        string `json:"sponsor_did"`
	SponsorName       string `json:"sponsor_name,omitempty"`
	Jurisdiction      string `json:"jurisdiction,omitempty"`
	Role              string `json:"role,omitempty"`
	LiabilityAccepted bool   `json:"liability_accepted"`
	SignedAt          string `json:"signed_at,omitempty"`
}

// ControlLedgerAttestation exports one canonical TEE/validator attestation.
type ControlLedgerAttestation struct {
	ID          string            `json:"id"`
	Type        string            `json:"type,omitempty"`
	Platform    string            `json:"platform,omitempty"`
	EnclaveID   string            `json:"enclave_id,omitempty"`
	Measurement string            `json:"measurement,omitempty"`
	Timestamp   string            `json:"timestamp,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerApproverAttestation exports one authenticated approval action.
type ControlLedgerApproverAttestation struct {
	ID                string            `json:"id"`
	ApprovalRecordID  string            `json:"approval_record_id,omitempty"`
	Approver          string            `json:"approver,omitempty"`
	ApproverDID       string            `json:"approver_did,omitempty"`
	PassportDID       string            `json:"passport_did,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
	Action            string            `json:"action,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Decision          string            `json:"decision,omitempty"`
	TraceLinkID       string            `json:"trace_link_id,omitempty"`
	SealID            string            `json:"seal_id,omitempty"`
	AuthorizedAt      string            `json:"authorized_at,omitempty"`
	Comment           string            `json:"comment,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerValueSettlement exports one policy-bound value settlement.
type ControlLedgerValueSettlement struct {
	ID                string            `json:"id"`
	SettlementID      string            `json:"settlement_id,omitempty"`
	WorkflowID        string            `json:"workflow_id,omitempty"`
	Network           string            `json:"network,omitempty"`
	Method            string            `json:"method,omitempty"`
	Counterparty      string            `json:"counterparty,omitempty"`
	Beneficiary       string            `json:"beneficiary,omitempty"`
	FiatAmount        float64           `json:"fiat_amount,omitempty"`
	FiatCurrency      string            `json:"fiat_currency,omitempty"`
	TokenAmount       float64           `json:"token_amount,omitempty"`
	TokenDenomination string            `json:"token_denomination,omitempty"`
	ExchangeRate      float64           `json:"exchange_rate,omitempty"`
	Status            string            `json:"status,omitempty"`
	ReasonCode        string            `json:"reason_code,omitempty"`
	Reference         string            `json:"reference,omitempty"`
	TxHash            string            `json:"tx_hash,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
	SealID            string            `json:"seal_id,omitempty"`
	SettledAt         string            `json:"settled_at,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerPolicyReceipt exports a signed policy decision.
type ControlLedgerPolicyReceipt struct {
	ID                  string            `json:"id"`
	RequestID           string            `json:"request_id,omitempty"`
	Actor               string            `json:"actor,omitempty"`
	Action              string            `json:"action,omitempty"`
	Resource            string            `json:"resource,omitempty"`
	Decision            string            `json:"decision,omitempty"`
	AuditTrail          string            `json:"audit_trail,omitempty"`
	Signer              string            `json:"signer,omitempty"`
	ContentHash         string            `json:"content_hash,omitempty"`
	PreviousReceiptHash string            `json:"previous_receipt_hash,omitempty"`
	EvaluatedAt         string            `json:"evaluated_at,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerSeal exports the sealed execution outcome.
type ControlLedgerSeal struct {
	SealID         string            `json:"seal_id"`
	JobID          string            `json:"job_id,omitempty"`
	OutputHash     string            `json:"output_hash,omitempty"`
	ValidatorCount int               `json:"validator_count,omitempty"`
	BlockHeight    int64             `json:"block_height,omitempty"`
	Timestamp      string            `json:"timestamp,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerTraceLink binds identity, policy, and seal evidence together.
type ControlLedgerTraceLink struct {
	ID                string `json:"id"`
	AgentDID          string `json:"agent_did"`
	PolicyReceiptID   string `json:"policy_receipt_id"`
	PolicyReceiptHash string `json:"policy_receipt_hash"`
	SealID            string `json:"seal_id"`
	OutputHash        string `json:"output_hash,omitempty"`
	LinkedAt          string `json:"linked_at,omitempty"`
	Description       string `json:"description,omitempty"`
}

// ControlLedgerTrustCompliancePackage exports one anchored trust-compliance
// package artifact from the control ledger.
type ControlLedgerTrustCompliancePackage struct {
	ID                    string            `json:"id"`
	PackageHash           string            `json:"package_hash"`
	PayloadHash           string            `json:"payload_hash,omitempty"`
	DocumentHash          string            `json:"document_hash,omitempty"`
	Format                string            `json:"format,omitempty"`
	ExportVersion         string            `json:"export_version,omitempty"`
	GeneratedAt           string            `json:"generated_at,omitempty"`
	TrustRegistryVersion  string            `json:"trust_registry_version,omitempty"`
	TrustRegistrySource   string            `json:"trust_registry_source,omitempty"`
	BlockHeight           int64             `json:"block_height,omitempty"`
	CurrentEpoch          uint64            `json:"current_epoch,omitempty"`
	TotalUWU              uint64            `json:"total_uwu,omitempty"`
	HistoryCount          int               `json:"history_count,omitempty"`
	ComplianceTotal       int               `json:"compliance_total_controls,omitempty"`
	ComplianceMapped      int               `json:"compliance_mapped_controls,omitempty"`
	ComplianceGap         int               `json:"compliance_gap_controls,omitempty"`
	CustodyEntries        int               `json:"custody_entries,omitempty"`
	Signed                bool              `json:"signed"`
	Signer                string            `json:"signer,omitempty"`
	SignatureKeyID        string            `json:"signature_key_id,omitempty"`
	SignatureAlgorithm    string            `json:"signature_algorithm,omitempty"`
	SignedAt              string            `json:"signed_at,omitempty"`
	AuditAnchorSequence   uint64            `json:"audit_anchor_sequence,omitempty"`
	AuditAnchorRecordHash string            `json:"audit_anchor_record_hash,omitempty"`
	AuditAnchorAction     string            `json:"audit_anchor_action,omitempty"`
	AuditAnchorActor      string            `json:"audit_anchor_actor,omitempty"`
	AuditAnchorTimestamp  string            `json:"audit_anchor_timestamp,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// ControlLedgerControl exports one assessed control.
type ControlLedgerControl struct {
	ControlID     string            `json:"control_id"`
	ControlName   string            `json:"control_name,omitempty"`
	Status        string            `json:"status,omitempty"`
	Description   string            `json:"description,omitempty"`
	EvidenceCount int               `json:"evidence_count,omitempty"`
	EvidenceRefs  []string          `json:"evidence_refs,omitempty"`
	Findings      []string          `json:"findings,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type controlLedgerSnapshot struct {
	ControlLedgerExport
}

func normalizeControlLedger(ledger any) (*controlLedgerSnapshot, error) {
	if ledger == nil {
		return nil, fmt.Errorf("evidence/export: nil control ledger")
	}

	switch typed := ledger.(type) {
	case *evidence.ControlLedger:
		return snapshotFromTypedLedger(typed), nil
	case evidence.ControlLedger:
		return snapshotFromTypedLedger(&typed), nil
	}

	data, err := json.Marshal(ledger)
	if err != nil {
		return nil, fmt.Errorf("evidence/export: marshal control ledger: %w", err)
	}
	if string(data) == "null" {
		return nil, fmt.Errorf("evidence/export: nil control ledger")
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("evidence/export: decode control ledger: %w", err)
	}

	snap := &controlLedgerSnapshot{
		ControlLedgerExport: ControlLedgerExport{
			ExportVersion:           controlLedgerExportVersion,
			ExportedAt:              time.Now().UTC().Format(time.RFC3339Nano),
			Metadata:                firstStringMap(raw, "metadata", "labels", "annotations"),
			Passports:               []ControlLedgerPassport{},
			Attestations:            []ControlLedgerAttestation{},
			ApproverAttestations:    []ControlLedgerApproverAttestation{},
			ValueSettlements:        []ControlLedgerValueSettlement{},
			PolicyReceipts:          []ControlLedgerPolicyReceipt{},
			Seals:                   []ControlLedgerSeal{},
			TraceLinks:              []ControlLedgerTraceLink{},
			TrustCompliancePackages: []ControlLedgerTrustCompliancePackage{},
			Controls:                []ControlLedgerControl{},
		},
	}

	snap.LedgerID = firstString(raw, "ledger_id", "control_ledger_id", "bundle_id", "id")
	snap.Framework = firstString(raw, "framework", "standard", "program")
	snap.CreatedAt = firstString(raw, "created_at", "generated_at", "timestamp")
	snap.Version = firstString(raw, "version", "schema_version")

	if summaryMap, ok := firstMap(raw, "summary", "ledger_summary", "control_summary"); ok {
		snap.Summary = parseSummary(summaryMap)
	}

	snap.Passports = decodeCollection[ControlLedgerPassport](firstArray(raw, "passports", "agent_passports", "identity_passports", "portfolios"))
	snap.Attestations = decodeCollection[ControlLedgerAttestation](firstArray(raw, "attestations", "tee_attestations", "execution_attestations"))
	snap.ApproverAttestations = decodeCollection[ControlLedgerApproverAttestation](firstArray(raw, "approver_attestations", "approval_attestations", "approvals"))
	snap.ValueSettlements = decodeCollection[ControlLedgerValueSettlement](firstArray(raw, "value_settlements", "settlements", "payment_settlements"))
	snap.PolicyReceipts = decodeCollection[ControlLedgerPolicyReceipt](firstArray(raw, "policy_receipts", "receipts", "policy_authorizations"))
	snap.Seals = decodeCollection[ControlLedgerSeal](firstArray(raw, "seals", "execution_seals"))
	snap.TraceLinks = decodeCollection[ControlLedgerTraceLink](firstArray(raw, "trace_links", "links", "traceability_links"))
	snap.TrustCompliancePackages = decodeCollection[ControlLedgerTrustCompliancePackage](firstArray(raw, "trust_compliance_packages", "compliance_packages", "anchored_compliance_exports"))
	snap.Controls = decodeCollection[ControlLedgerControl](firstArray(raw, "controls", "entries", "records", "control_entries"))

	snap.Summary.TotalPassports = maxInt(snap.Summary.TotalPassports, len(snap.Passports))
	snap.Summary.TotalAttestations = maxInt(snap.Summary.TotalAttestations, len(snap.Attestations))
	snap.Summary.TotalApproverAttestations = maxInt(snap.Summary.TotalApproverAttestations, len(snap.ApproverAttestations))
	snap.Summary.TotalValueSettlements = maxInt(snap.Summary.TotalValueSettlements, len(snap.ValueSettlements))
	snap.Summary.TotalPolicyReceipts = maxInt(snap.Summary.TotalPolicyReceipts, len(snap.PolicyReceipts))
	snap.Summary.TotalSeals = maxInt(snap.Summary.TotalSeals, len(snap.Seals))
	snap.Summary.TotalTraceLinks = maxInt(snap.Summary.TotalTraceLinks, len(snap.TraceLinks))
	snap.Summary.TotalTrustCompliancePackages = maxInt(snap.Summary.TotalTrustCompliancePackages, len(snap.TrustCompliancePackages))
	snap.Summary.TotalControls = maxInt(snap.Summary.TotalControls, len(snap.Controls))
	if !summaryMapHasChainIntact(raw) && !snap.Summary.ChainIntact {
		snap.Summary.ChainIntact = len(snap.TraceLinks) == 0 || (len(snap.Passports) > 0 && len(snap.PolicyReceipts) > 0 && len(snap.Seals) > 0)
	}

	return snap, nil
}

func snapshotFromTypedLedger(ledger *evidence.ControlLedger) *controlLedgerSnapshot {
	if ledger == nil || ledger.Bundle == nil {
		return &controlLedgerSnapshot{
			ControlLedgerExport: ControlLedgerExport{
				ExportVersion: controlLedgerExportVersion,
				ExportedAt:    time.Now().UTC().Format(time.RFC3339Nano),
			},
		}
	}

	snap := &controlLedgerSnapshot{
		ControlLedgerExport: ControlLedgerExport{
			ExportVersion:           controlLedgerExportVersion,
			ExportedAt:              time.Now().UTC().Format(time.RFC3339Nano),
			Metadata:                cloneStringMap(ledger.Metadata),
			Passports:               make([]ControlLedgerPassport, 0, len(ledger.Bundle.AgentPassports)),
			Attestations:            make([]ControlLedgerAttestation, 0, len(ledger.Bundle.Attestations)),
			ApproverAttestations:    make([]ControlLedgerApproverAttestation, 0, len(ledger.Bundle.ApproverAttestations)),
			ValueSettlements:        make([]ControlLedgerValueSettlement, 0, len(ledger.Bundle.ValueSettlements)),
			PolicyReceipts:          make([]ControlLedgerPolicyReceipt, 0, len(ledger.Bundle.PolicyReceipts)),
			Seals:                   make([]ControlLedgerSeal, 0, len(ledger.Bundle.Seals)),
			TraceLinks:              make([]ControlLedgerTraceLink, 0, len(ledger.Bundle.TraceLinks)),
			TrustCompliancePackages: make([]ControlLedgerTrustCompliancePackage, 0, len(ledger.Bundle.TrustCompliancePackages)),
			Controls:                make([]ControlLedgerControl, 0, len(ledger.Controls)),
		},
	}

	snap.LedgerID = ledger.Bundle.ID
	snap.Framework = ledger.Bundle.Framework
	snap.CreatedAt = ledger.Bundle.CreatedAt
	snap.Version = ledger.Bundle.Version
	snap.Metadata = firstNonEmptyMap(snap.Metadata, cloneStringMap(ledger.Bundle.Metadata))
	snap.Summary = ControlLedgerSummary{
		TotalControls:                ledger.Summary.TotalControls,
		TotalPassports:               ledger.Summary.TotalPassports,
		TotalAttestations:            ledger.Summary.TotalAttestations,
		TotalApproverAttestations:    ledger.Summary.TotalApproverAttestations,
		TotalValueSettlements:        ledger.Summary.TotalValueSettlements,
		TotalPolicyReceipts:          ledger.Summary.TotalPolicyReceipts,
		TotalSeals:                   ledger.Summary.TotalSeals,
		TotalTraceLinks:              ledger.Summary.TotalTraceLinks,
		TotalTrustCompliancePackages: ledger.Summary.TotalTrustCompliancePackages,
		ChainIntact:                  ledger.Summary.TraceIntact,
	}

	for _, passport := range ledger.Bundle.AgentPassports {
		sponsorChain := make([]ControlLedgerPassportSponsor, 0, len(passport.SponsorChain))
		for _, sponsor := range passport.SponsorChain {
			sponsorChain = append(sponsorChain, ControlLedgerPassportSponsor{
				SponsorDID:        sponsor.SponsorDID,
				SponsorName:       sponsor.SponsorName,
				Jurisdiction:      sponsor.Jurisdiction,
				Role:              sponsor.Role,
				LiabilityAccepted: sponsor.LiabilityAccepted,
				SignedAt:          sponsor.SignedAt,
			})
		}
		snap.Passports = append(snap.Passports, ControlLedgerPassport{
			DID:              passport.DID,
			Issuer:           passport.Issuer,
			PublicKeyHash:    passport.PublicKeyHash,
			Capabilities:     cloneStringSlice(passport.Capabilities),
			SponsorChain:     sponsorChain,
			HumanOwner:       passport.HumanOwner,
			BusinessUnit:     passport.BusinessUnit,
			SponsorOfRecord:  passport.SponsorOfRecord,
			FallbackApprover: passport.FallbackApprover,
			IncidentContact:  passport.IncidentContact,
			LiabilityModel:   passport.LiabilityModel,
			JurisdictionTags: cloneStringSlice(passport.JurisdictionTags),
			AllowedTools:     cloneStringSlice(passport.AllowedTools),
			IssuedAt:         passport.IssuedAt,
			ExpiresAt:        passport.ExpiresAt,
			Metadata:         cloneStringMap(passport.Metadata),
		})
	}

	for _, attestation := range ledger.Bundle.Attestations {
		snap.Attestations = append(snap.Attestations, ControlLedgerAttestation{
			ID:          attestation.ID,
			Type:        attestation.Type,
			Platform:    attestation.Platform,
			EnclaveID:   attestation.EnclaveID,
			Measurement: attestation.Measurement,
			Timestamp:   attestation.Timestamp,
			Metadata:    cloneStringMap(attestation.Metadata),
		})
	}

	for _, attestation := range ledger.Bundle.ApproverAttestations {
		snap.ApproverAttestations = append(snap.ApproverAttestations, ControlLedgerApproverAttestation{
			ID:                attestation.ID,
			ApprovalRecordID:  attestation.ApprovalRecordID,
			Approver:          attestation.Approver,
			ApproverDID:       attestation.ApproverDID,
			PassportDID:       attestation.PassportDID,
			PolicyReceiptID:   attestation.PolicyReceiptID,
			PolicyReceiptHash: attestation.PolicyReceiptHash,
			Action:            attestation.Action,
			Resource:          attestation.Resource,
			Decision:          attestation.Decision,
			TraceLinkID:       attestation.TraceLinkID,
			SealID:            attestation.SealID,
			AuthorizedAt:      attestation.AuthorizedAt,
			Comment:           attestation.Comment,
			Metadata:          cloneStringMap(attestation.Metadata),
		})
	}

	for _, settlement := range ledger.Bundle.ValueSettlements {
		snap.ValueSettlements = append(snap.ValueSettlements, ControlLedgerValueSettlement{
			ID:                settlement.ID,
			SettlementID:      settlement.SettlementID,
			WorkflowID:        settlement.WorkflowID,
			Network:           settlement.Network,
			Method:            settlement.Method,
			Counterparty:      settlement.Counterparty,
			Beneficiary:       settlement.Beneficiary,
			FiatAmount:        settlement.FiatAmount,
			FiatCurrency:      settlement.FiatCurrency,
			TokenAmount:       settlement.TokenAmount,
			TokenDenomination: settlement.TokenDenomination,
			ExchangeRate:      settlement.ExchangeRate,
			Status:            settlement.Status,
			ReasonCode:        settlement.ReasonCode,
			Reference:         settlement.Reference,
			TxHash:            settlement.TxHash,
			PolicyReceiptID:   settlement.PolicyReceiptID,
			PolicyReceiptHash: settlement.PolicyReceiptHash,
			SealID:            settlement.SealID,
			SettledAt:         settlement.SettledAt,
			Metadata:          cloneStringMap(settlement.Metadata),
		})
	}

	for _, receipt := range ledger.Bundle.PolicyReceipts {
		snap.PolicyReceipts = append(snap.PolicyReceipts, ControlLedgerPolicyReceipt{
			ID:                  receipt.ID,
			RequestID:           receipt.RequestID,
			Actor:               receipt.Actor,
			Action:              receipt.Action,
			Resource:            receipt.Resource,
			Decision:            receipt.Decision,
			AuditTrail:          receipt.AuditTrail,
			Signer:              receipt.Signer,
			ContentHash:         receipt.ContentHash,
			PreviousReceiptHash: receipt.PreviousReceiptHash,
			EvaluatedAt:         receipt.EvaluatedAt,
		})
	}

	for _, seal := range ledger.Bundle.Seals {
		snap.Seals = append(snap.Seals, ControlLedgerSeal{
			SealID:         seal.SealID,
			JobID:          seal.JobID,
			OutputHash:     seal.OutputHash,
			ValidatorCount: seal.ValidatorCount,
			BlockHeight:    seal.BlockHeight,
			Timestamp:      seal.Timestamp,
		})
	}

	for _, link := range ledger.Bundle.TraceLinks {
		snap.TraceLinks = append(snap.TraceLinks, ControlLedgerTraceLink{
			ID:                link.ID,
			AgentDID:          link.AgentDID,
			PolicyReceiptID:   link.PolicyReceiptID,
			PolicyReceiptHash: link.PolicyReceiptHash,
			SealID:            link.SealID,
			OutputHash:        link.OutputHash,
			LinkedAt:          link.LinkedAt,
			Description:       link.Description,
		})
	}

	for _, pkg := range ledger.Bundle.TrustCompliancePackages {
		exported := ControlLedgerTrustCompliancePackage{
			ID:                   pkg.ID,
			PackageHash:          pkg.PackageHash,
			PayloadHash:          pkg.PayloadHash,
			DocumentHash:         pkg.DocumentHash,
			Format:               pkg.Format,
			ExportVersion:        pkg.ExportVersion,
			GeneratedAt:          pkg.GeneratedAt,
			TrustRegistryVersion: pkg.TrustRegistryVersion,
			TrustRegistrySource:  pkg.TrustRegistrySource,
			BlockHeight:          pkg.BlockHeight,
			CurrentEpoch:         pkg.CurrentEpoch,
			TotalUWU:             pkg.TotalUWU,
			HistoryCount:         pkg.HistoryCount,
			ComplianceTotal:      pkg.ComplianceTotal,
			ComplianceMapped:     pkg.ComplianceMapped,
			ComplianceGap:        pkg.ComplianceGap,
			CustodyEntries:       pkg.CustodyEntries,
			Signed:               pkg.Signed,
			Metadata:             cloneStringMap(pkg.Metadata),
		}
		if pkg.Signature != nil {
			exported.Signer = pkg.Signature.Signer
			exported.SignatureKeyID = pkg.Signature.KeyID
			exported.SignatureAlgorithm = pkg.Signature.Algorithm
			exported.SignedAt = pkg.Signature.SignedAt
		}
		if pkg.AuditAnchor != nil {
			exported.AuditAnchorSequence = pkg.AuditAnchor.Sequence
			exported.AuditAnchorRecordHash = pkg.AuditAnchor.RecordHash
			exported.AuditAnchorAction = pkg.AuditAnchor.Action
			exported.AuditAnchorActor = pkg.AuditAnchor.Actor
			exported.AuditAnchorTimestamp = pkg.AuditAnchor.Timestamp
		}
		snap.TrustCompliancePackages = append(snap.TrustCompliancePackages, exported)
	}

	for _, control := range ledger.Controls {
		snap.Controls = append(snap.Controls, ControlLedgerControl{
			ControlID:     control.ControlID,
			ControlName:   control.ControlName,
			Status:        string(control.Status),
			Description:   control.Description,
			EvidenceCount: len(control.EvidenceRefs.RecordIDs) + len(control.EvidenceRefs.ApproverAttestationIDs) + len(control.EvidenceRefs.ValueSettlementIDs) + len(control.EvidenceRefs.PolicyReceiptIDs) + len(control.EvidenceRefs.SealIDs) + len(control.EvidenceRefs.TraceLinkIDs) + len(control.EvidenceRefs.TrustCompliancePackageIDs),
			EvidenceRefs:  flattenEvidenceRefs(control.EvidenceRefs),
			Findings:      cloneStringSlice(control.Findings),
			Metadata:      cloneStringMap(control.Metadata),
		})
	}

	return snap
}

func parseSummary(summary map[string]any) ControlLedgerSummary {
	return ControlLedgerSummary{
		TotalControls:                firstInt(summary, "total_controls", "controls_total", "controls", "control_count"),
		TotalPassports:               firstInt(summary, "total_passports", "passports_total", "passport_count"),
		TotalAttestations:            firstInt(summary, "total_attestations", "attestations_total", "tee_attestation_count"),
		TotalApproverAttestations:    firstInt(summary, "total_approver_attestations", "approver_attestations_total", "approval_attestation_count"),
		TotalValueSettlements:        firstInt(summary, "total_value_settlements", "value_settlements_total", "settlement_count"),
		TotalPolicyReceipts:          firstInt(summary, "total_policy_receipts", "policy_receipts_total", "receipt_count"),
		TotalSeals:                   firstInt(summary, "total_seals", "seals_total", "seal_count"),
		TotalTraceLinks:              firstInt(summary, "total_trace_links", "trace_links_total", "trace_count"),
		TotalTrustCompliancePackages: firstInt(summary, "total_trust_compliance_packages", "trust_compliance_packages_total", "trust_package_count"),
		ChainIntact:                  firstBool(summary, "chain_intact", "traceability_intact", "integrity_ok"),
	}
}

func summaryMapHasChainIntact(raw map[string]any) bool {
	if summaryMap, ok := firstMap(raw, "summary", "ledger_summary", "control_summary"); ok {
		_, exists := lookupAny(summaryMap, "chain_intact", "traceability_intact", "integrity_ok")
		return exists
	}
	return false
}

func firstString(raw map[string]any, keys ...string) string {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func firstBool(raw map[string]any, keys ...string) bool {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true") || x == "1"
	default:
		return false
	}
}

func firstInt(raw map[string]any, keys ...string) int {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int(x)
	case float32:
		return int(x)
	case int:
		return x
	case int64:
		return int(x)
	case int32:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		var n int
		_, _ = fmt.Sscanf(x, "%d", &n)
		return n
	default:
		return 0
	}
}

func firstStringMap(raw map[string]any, keys ...string) map[string]string {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case map[string]string:
		if len(x) == 0 {
			return nil
		}
		out := make(map[string]string, len(x))
		for k, v := range x {
			out[k] = v
		}
		return out
	case map[string]any:
		if len(x) == 0 {
			return nil
		}
		out := make(map[string]string, len(x))
		for k, v := range x {
			out[k] = fmt.Sprint(v)
		}
		return out
	default:
		return nil
	}
}

func firstMap(raw map[string]any, keys ...string) (map[string]any, bool) {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	return m, true
}

func firstArray(raw map[string]any, keys ...string) []any {
	v, ok := lookupAny(raw, keys...)
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []any:
		return x
	case []map[string]any:
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func lookupAny(raw map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		for existingKey, value := range raw {
			if strings.EqualFold(existingKey, key) {
				return value, true
			}
		}
	}
	return nil, false
}

func decodeCollection[T any](items []any) []T {
	if len(items) == 0 {
		return nil
	}
	out := make([]T, 0, len(items))
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			continue
		}
		var decoded T
		if err := json.Unmarshal(data, &decoded); err != nil {
			continue
		}
		out = append(out, decoded)
	}
	return out
}

func maxInt(a, b int) int {
	if b > a {
		return b
	}
	return a
}

func encodeMetadata(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
	}
	return strings.Join(parts, ";")
}

func flattenEvidenceRefs(refs evidence.ControlEvidenceRefs) []string {
	out := make([]string, 0, len(refs.RecordIDs)+len(refs.AttestationIDs)+len(refs.ApproverAttestationIDs)+len(refs.ValueSettlementIDs)+len(refs.PolicyReceiptIDs)+len(refs.SealIDs)+len(refs.TraceLinkIDs)+len(refs.TrustCompliancePackageIDs))
	out = append(out, refs.RecordIDs...)
	out = append(out, refs.AttestationIDs...)
	out = append(out, refs.ApproverAttestationIDs...)
	out = append(out, refs.ValueSettlementIDs...)
	out = append(out, refs.PolicyReceiptIDs...)
	out = append(out, refs.SealIDs...)
	out = append(out, refs.TraceLinkIDs...)
	out = append(out, refs.TrustCompliancePackageIDs...)
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func firstNonEmptyMap(primary, fallback map[string]string) map[string]string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}
