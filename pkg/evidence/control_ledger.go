package evidence

import (
	"fmt"
	"strings"
)

// ControlStatus represents the assessment state of one auditor-facing control.
type ControlStatus string

const (
	ControlSatisfied     ControlStatus = "satisfied"
	ControlPartial       ControlStatus = "partially_satisfied"
	ControlNotSatisfied  ControlStatus = "not_satisfied"
	ControlNotApplicable ControlStatus = "not_applicable"
)

// ControlEvidenceRefs links a control to concrete trust artifacts inside the
// control ledger.
type ControlEvidenceRefs struct {
	RecordIDs                 []string `json:"record_ids,omitempty"`
	AttestationIDs            []string `json:"attestation_ids,omitempty"`
	ApproverAttestationIDs    []string `json:"approver_attestation_ids,omitempty"`
	ValueSettlementIDs        []string `json:"value_settlement_ids,omitempty"`
	PolicyReceiptIDs          []string `json:"policy_receipt_ids,omitempty"`
	SealIDs                   []string `json:"seal_ids,omitempty"`
	TraceLinkIDs              []string `json:"trace_link_ids,omitempty"`
	TrustCompliancePackageIDs []string `json:"trust_compliance_package_ids,omitempty"`
}

// LedgerControl maps one auditor-facing control to the exact evidence that
// satisfies it.
type LedgerControl struct {
	ControlID    string              `json:"control_id"`
	ControlName  string              `json:"control_name"`
	Description  string              `json:"description,omitempty"`
	Status       ControlStatus       `json:"status"`
	EvidenceRefs ControlEvidenceRefs `json:"evidence_refs"`
	Findings     []string            `json:"findings,omitempty"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
}

// ControlLedgerSummary provides the compact operator and auditor view of the
// verified trust chain.
type ControlLedgerSummary struct {
	BundleID                     string   `json:"bundle_id"`
	Framework                    string   `json:"framework"`
	TotalControls                int      `json:"total_controls"`
	TotalRecords                 int      `json:"total_records"`
	TotalPassports               int      `json:"total_passports"`
	TotalAttestations            int      `json:"total_attestations"`
	TotalApproverAttestations    int      `json:"total_approver_attestations"`
	TotalValueSettlements        int      `json:"total_value_settlements"`
	TotalPolicyReceipts          int      `json:"total_policy_receipts"`
	TotalSeals                   int      `json:"total_seals"`
	TotalTraceLinks              int      `json:"total_trace_links"`
	TotalTrustCompliancePackages int      `json:"total_trust_compliance_packages"`
	TotalCustodyEntries          int      `json:"total_custody_entries"`
	Actors                       []string `json:"actors,omitempty"`
	Jurisdictions                []string `json:"jurisdictions,omitempty"`
	TraceIntact                  bool     `json:"trace_intact"`
	Finalized                    bool     `json:"finalized"`
	PortableReady                bool     `json:"portable_ready"`
}

// ControlLedger is the enterprise-grade system-of-record facade over an
// evidence bundle. It keeps the passport -> policy receipt -> seal -> trace
// chain auditor-readable and export-ready.
type ControlLedger struct {
	Bundle   *EvidenceBundle      `json:"bundle"`
	Controls []LedgerControl      `json:"controls,omitempty"`
	Summary  ControlLedgerSummary `json:"summary"`
	Metadata map[string]string    `json:"metadata,omitempty"`
}

// NewControlLedger creates a new control ledger for the given framework.
func NewControlLedger(framework string) *ControlLedger {
	bundle := NewEvidenceBundle(framework)
	ledger := &ControlLedger{
		Bundle:   bundle,
		Controls: make([]LedgerControl, 0),
		Metadata: make(map[string]string),
	}
	ledger.refreshSummary()
	return ledger
}

// AddRecord appends a canonical evidence record to the ledger.
func (cl *ControlLedger) AddRecord(record Record) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddRecord(record)
	cl.refreshSummary()
}

// AddPolicyReceipt appends a signed policy receipt to the ledger.
func (cl *ControlLedger) AddPolicyReceipt(receipt PolicyReceiptEvidence) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddPolicyReceipt(receipt)
	cl.refreshSummary()
}

// AddAgentPassport appends an enterprise agent passport to the ledger.
func (cl *ControlLedger) AddAgentPassport(passport AgentPassportEvidence) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddAgentPassport(passport)
	cl.refreshSummary()
}

// AddAttestation appends a canonical TEE or validator attestation artifact to
// the ledger.
func (cl *ControlLedger) AddAttestation(attestation Attestation) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddAttestation(attestation)
	cl.refreshSummary()
}

// AddApproverAttestation appends a first-class authenticated approval artifact
// to the ledger.
func (cl *ControlLedger) AddApproverAttestation(attestation ApproverAttestationEvidence) error {
	if cl == nil || cl.Bundle == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if err := cl.Bundle.AddApproverAttestation(attestation); err != nil {
		return err
	}
	cl.refreshSummary()
	return nil
}

// AddValueSettlement appends a canonical value-settlement artifact to the
// ledger.
func (cl *ControlLedger) AddValueSettlement(settlement ValueSettlementEvidence) error {
	if cl == nil || cl.Bundle == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if err := cl.Bundle.AddValueSettlement(settlement); err != nil {
		return err
	}
	cl.refreshSummary()
	return nil
}

// AddSeal appends a verification seal to the ledger.
func (cl *ControlLedger) AddSeal(seal Seal) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddSeal(seal)
	cl.refreshSummary()
}

// AddTraceLink appends a trace link to the ledger.
func (cl *ControlLedger) AddTraceLink(link TraceLink) {
	if cl == nil || cl.Bundle == nil {
		return
	}
	cl.Bundle.AddTraceLink(link)
	cl.refreshSummary()
}

// AddTrustCompliancePackage appends a packaged trust-compliance artifact to the
// ledger and projects its audit anchor into the canonical record stream.
func (cl *ControlLedger) AddTrustCompliancePackage(pkg TrustCompliancePackageEvidence) error {
	if cl == nil || cl.Bundle == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if err := cl.Bundle.AddTrustCompliancePackage(pkg); err != nil {
		return err
	}
	cl.refreshSummary()
	return nil
}

// WithMetadata adds control-ledger-level metadata and mirrors it into the
// underlying evidence bundle metadata.
func (cl *ControlLedger) WithMetadata(key, value string) {
	if cl == nil || strings.TrimSpace(key) == "" {
		return
	}
	if cl.Metadata == nil {
		cl.Metadata = make(map[string]string)
	}
	if cl.Bundle != nil && cl.Bundle.Metadata == nil {
		cl.Bundle.Metadata = make(map[string]string)
	}
	cl.Metadata[key] = value
	if cl.Bundle != nil {
		cl.Bundle.Metadata[key] = value
	}
}

// AddControl appends an auditor-facing control mapping to the ledger.
func (cl *ControlLedger) AddControl(control LedgerControl) error {
	if cl == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if strings.TrimSpace(control.ControlID) == "" {
		return fmt.Errorf("evidence/control_ledger: control ID is required")
	}
	if strings.TrimSpace(control.ControlName) == "" {
		return fmt.Errorf("evidence/control_ledger: control name is required")
	}
	if !control.hasEvidenceRefs() {
		return fmt.Errorf("evidence/control_ledger: control %q must reference at least one evidence artifact", control.ControlID)
	}

	control.EvidenceRefs = cloneControlEvidenceRefs(control.EvidenceRefs)
	control.Findings = cloneStringSlice(control.Findings)
	control.Metadata = cloneMetadata(control.Metadata)
	cl.Controls = append(cl.Controls, control)
	cl.refreshSummary()
	return nil
}

// Finalize seals the underlying bundle and refreshes the ledger summary.
func (cl *ControlLedger) Finalize(signer string) error {
	if cl == nil || cl.Bundle == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if err := cl.Bundle.Finalize(signer); err != nil {
		return err
	}
	cl.refreshSummary()
	return nil
}

// Validate verifies both the underlying evidence bundle and the auditor-facing
// control mappings.
func (cl *ControlLedger) Validate() error {
	if cl == nil {
		return fmt.Errorf("evidence/control_ledger: nil control ledger")
	}
	if cl.Bundle == nil {
		return fmt.Errorf("evidence/control_ledger: nil evidence bundle")
	}
	if err := cl.Bundle.Validate(); err != nil {
		return err
	}
	if err := cl.validateControls(); err != nil {
		return err
	}
	cl.refreshSummary()
	return nil
}

// ToEvidenceBundle returns a defensive copy of the validated underlying
// evidence bundle.
func (cl *ControlLedger) ToEvidenceBundle() (*EvidenceBundle, error) {
	if err := cl.Validate(); err != nil {
		return nil, err
	}
	return cloneEvidenceBundle(cl.Bundle)
}

// Package creates a portable evidence package directly from the control ledger.
func (cl *ControlLedger) Package(includeVerificationKeys bool) (*PortableEvidence, error) {
	return PackageControlLedger(cl, includeVerificationKeys)
}

func (cl *ControlLedger) validateControls() error {
	recordIDs := make(map[string]struct{}, len(cl.Bundle.Records))
	for _, record := range cl.Bundle.Records {
		recordIDs[record.ID] = struct{}{}
	}

	approverAttestationIDs := make(map[string]struct{}, len(cl.Bundle.ApproverAttestations))
	for _, attestation := range cl.Bundle.ApproverAttestations {
		approverAttestationIDs[attestation.ID] = struct{}{}
	}
	attestationIDs := make(map[string]struct{}, len(cl.Bundle.Attestations))
	for _, attestation := range cl.Bundle.Attestations {
		attestationIDs[attestation.ID] = struct{}{}
	}
	valueSettlementIDs := make(map[string]struct{}, len(cl.Bundle.ValueSettlements))
	for _, settlement := range cl.Bundle.ValueSettlements {
		valueSettlementIDs[settlement.ID] = struct{}{}
	}

	policyIDs := make(map[string]struct{}, len(cl.Bundle.PolicyReceipts))
	for _, receipt := range cl.Bundle.PolicyReceipts {
		policyIDs[receipt.ID] = struct{}{}
	}

	sealIDs := make(map[string]struct{}, len(cl.Bundle.Seals))
	for _, seal := range cl.Bundle.Seals {
		sealIDs[seal.SealID] = struct{}{}
	}

	traceIDs := make(map[string]struct{}, len(cl.Bundle.TraceLinks))
	for _, trace := range cl.Bundle.TraceLinks {
		traceIDs[trace.ID] = struct{}{}
	}

	trustComplianceIDs := make(map[string]struct{}, len(cl.Bundle.TrustCompliancePackages))
	for _, pkg := range cl.Bundle.TrustCompliancePackages {
		trustComplianceIDs[pkg.ID] = struct{}{}
	}

	for _, control := range cl.Controls {
		if strings.TrimSpace(control.ControlID) == "" || strings.TrimSpace(control.ControlName) == "" {
			return fmt.Errorf("evidence/control_ledger: control is missing required identity fields")
		}
		if !control.hasEvidenceRefs() {
			return fmt.Errorf("evidence/control_ledger: control %q has no evidence references", control.ControlID)
		}

		for _, recordID := range control.EvidenceRefs.RecordIDs {
			if _, ok := recordIDs[recordID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown record %q", control.ControlID, recordID)
			}
		}
		for _, approverAttestationID := range control.EvidenceRefs.ApproverAttestationIDs {
			if _, ok := approverAttestationIDs[approverAttestationID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown approver attestation %q", control.ControlID, approverAttestationID)
			}
		}
		for _, attestationID := range control.EvidenceRefs.AttestationIDs {
			if _, ok := attestationIDs[attestationID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown attestation %q", control.ControlID, attestationID)
			}
		}
		for _, valueSettlementID := range control.EvidenceRefs.ValueSettlementIDs {
			if _, ok := valueSettlementIDs[valueSettlementID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown value settlement %q", control.ControlID, valueSettlementID)
			}
		}
		for _, policyReceiptID := range control.EvidenceRefs.PolicyReceiptIDs {
			if _, ok := policyIDs[policyReceiptID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown policy receipt %q", control.ControlID, policyReceiptID)
			}
		}
		for _, sealID := range control.EvidenceRefs.SealIDs {
			if _, ok := sealIDs[sealID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown seal %q", control.ControlID, sealID)
			}
		}
		for _, traceLinkID := range control.EvidenceRefs.TraceLinkIDs {
			if _, ok := traceIDs[traceLinkID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown trace link %q", control.ControlID, traceLinkID)
			}
		}
		for _, trustCompliancePackageID := range control.EvidenceRefs.TrustCompliancePackageIDs {
			if _, ok := trustComplianceIDs[trustCompliancePackageID]; !ok {
				return fmt.Errorf("evidence/control_ledger: control %q references unknown trust compliance package %q", control.ControlID, trustCompliancePackageID)
			}
		}
	}

	return nil
}

func (cl *ControlLedger) refreshSummary() {
	if cl == nil || cl.Bundle == nil {
		return
	}

	actors := make([]string, 0, len(cl.Bundle.AgentPassports)+len(cl.Bundle.PolicyReceipts)+len(cl.Bundle.Records))
	for _, record := range cl.Bundle.Records {
		if strings.TrimSpace(record.Actor) != "" {
			actors = append(actors, record.Actor)
		}
	}
	for _, passport := range cl.Bundle.AgentPassports {
		if strings.TrimSpace(passport.DID) != "" {
			actors = append(actors, passport.DID)
		}
	}
	for _, attestation := range cl.Bundle.ApproverAttestations {
		if strings.TrimSpace(attestation.ApproverDID) != "" {
			actors = append(actors, attestation.ApproverDID)
		}
		if strings.TrimSpace(attestation.Approver) != "" {
			actors = append(actors, attestation.Approver)
		}
	}
	for _, settlement := range cl.Bundle.ValueSettlements {
		if strings.TrimSpace(settlement.Counterparty) != "" {
			actors = append(actors, settlement.Counterparty)
		}
		if strings.TrimSpace(settlement.Beneficiary) != "" {
			actors = append(actors, settlement.Beneficiary)
		}
	}
	for _, receipt := range cl.Bundle.PolicyReceipts {
		if strings.TrimSpace(receipt.Actor) != "" {
			actors = append(actors, receipt.Actor)
		}
	}
	for _, pkg := range cl.Bundle.TrustCompliancePackages {
		if pkg.Signature != nil && strings.TrimSpace(pkg.Signature.Signer) != "" {
			actors = append(actors, pkg.Signature.Signer)
		}
		if pkg.AuditAnchor != nil && strings.TrimSpace(pkg.AuditAnchor.Actor) != "" {
			actors = append(actors, pkg.AuditAnchor.Actor)
		}
	}

	jurisdictions := make([]string, 0, len(cl.Bundle.AgentPassports)*2)
	for _, passport := range cl.Bundle.AgentPassports {
		jurisdictions = append(jurisdictions, passport.JurisdictionTags...)
		for _, sponsor := range passport.SponsorChain {
			if strings.TrimSpace(sponsor.Jurisdiction) != "" {
				jurisdictions = append(jurisdictions, sponsor.Jurisdiction)
			}
		}
	}

	traceIntact := false
	if cl.Bundle.ContentHash != "" {
		traceIntact = cl.Bundle.Validate() == nil && cl.validateControls() == nil
	} else {
		traceIntact = validateTraceability(cl.Bundle) == nil && cl.validateControls() == nil
	}

	cl.Summary = ControlLedgerSummary{
		BundleID:                     cl.Bundle.ID,
		Framework:                    cl.Bundle.Framework,
		TotalControls:                len(cl.Controls),
		TotalRecords:                 len(cl.Bundle.Records),
		TotalPassports:               len(cl.Bundle.AgentPassports),
		TotalAttestations:            len(cl.Bundle.Attestations),
		TotalApproverAttestations:    len(cl.Bundle.ApproverAttestations),
		TotalValueSettlements:        len(cl.Bundle.ValueSettlements),
		TotalPolicyReceipts:          len(cl.Bundle.PolicyReceipts),
		TotalSeals:                   len(cl.Bundle.Seals),
		TotalTraceLinks:              len(cl.Bundle.TraceLinks),
		TotalTrustCompliancePackages: len(cl.Bundle.TrustCompliancePackages),
		TotalCustodyEntries:          len(cl.Bundle.ChainOfCustody),
		Actors:                       sortedUniqueStrings(actors),
		Jurisdictions:                sortedUniqueStrings(jurisdictions),
		TraceIntact:                  traceIntact,
		Finalized:                    cl.Bundle.ContentHash != "",
		PortableReady:                cl.Bundle.ContentHash != "" && traceIntact,
	}
}

func (c LedgerControl) hasEvidenceRefs() bool {
	return len(c.EvidenceRefs.RecordIDs) > 0 ||
		len(c.EvidenceRefs.AttestationIDs) > 0 ||
		len(c.EvidenceRefs.ApproverAttestationIDs) > 0 ||
		len(c.EvidenceRefs.ValueSettlementIDs) > 0 ||
		len(c.EvidenceRefs.PolicyReceiptIDs) > 0 ||
		len(c.EvidenceRefs.SealIDs) > 0 ||
		len(c.EvidenceRefs.TraceLinkIDs) > 0 ||
		len(c.EvidenceRefs.TrustCompliancePackageIDs) > 0
}

func cloneControlEvidenceRefs(in ControlEvidenceRefs) ControlEvidenceRefs {
	return ControlEvidenceRefs{
		RecordIDs:                 cloneStringSlice(in.RecordIDs),
		AttestationIDs:            cloneStringSlice(in.AttestationIDs),
		ApproverAttestationIDs:    cloneStringSlice(in.ApproverAttestationIDs),
		ValueSettlementIDs:        cloneStringSlice(in.ValueSettlementIDs),
		PolicyReceiptIDs:          cloneStringSlice(in.PolicyReceiptIDs),
		SealIDs:                   cloneStringSlice(in.SealIDs),
		TraceLinkIDs:              cloneStringSlice(in.TraceLinkIDs),
		TrustCompliancePackageIDs: cloneStringSlice(in.TrustCompliancePackageIDs),
	}
}

func cloneEvidenceBundle(bundle *EvidenceBundle) (*EvidenceBundle, error) {
	if bundle == nil {
		return nil, fmt.Errorf("evidence/control_ledger: nil evidence bundle")
	}

	cloned := &EvidenceBundle{
		ID:                      bundle.ID,
		Version:                 bundle.Version,
		CreatedAt:               bundle.CreatedAt,
		Framework:               bundle.Framework,
		Records:                 cloneRecords(bundle.Records),
		Seals:                   cloneSeals(bundle.Seals),
		Attestations:            cloneAttestations(bundle.Attestations),
		PolicyReceipts:          clonePolicyReceipts(bundle.PolicyReceipts),
		AgentPassports:          cloneAgentPassports(bundle.AgentPassports),
		ApproverAttestations:    cloneApproverAttestations(bundle.ApproverAttestations),
		ValueSettlements:        cloneValueSettlements(bundle.ValueSettlements),
		TraceLinks:              cloneTraceLinks(bundle.TraceLinks),
		TrustCompliancePackages: cloneTrustCompliancePackages(bundle.TrustCompliancePackages),
		ChainOfCustody:          cloneCustodyEntries(bundle.ChainOfCustody),
		ContentHash:             bundle.ContentHash,
		Signature:               bundle.Signature,
		Metadata:                cloneStringMapPreserve(bundle.Metadata),
	}

	return cloned, nil
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}

	for i := 1; i < len(out); i++ {
		key := out[i]
		j := i - 1
		for j >= 0 && out[j] > key {
			out[j+1] = out[j]
			j--
		}
		out[j+1] = key
	}

	return out
}

func cloneRecords(in []Record) []Record {
	if in == nil {
		return nil
	}
	out := make([]Record, len(in))
	for i, record := range in {
		out[i] = record
		out[i].Data = cloneStringMapPreserve(record.Data)
	}
	return out
}

func cloneSeals(in []Seal) []Seal {
	if in == nil {
		return nil
	}
	out := make([]Seal, len(in))
	copy(out, in)
	return out
}

func cloneAttestations(in []Attestation) []Attestation {
	if in == nil {
		return nil
	}
	out := make([]Attestation, len(in))
	for i, attestation := range in {
		out[i] = attestation
		out[i].Metadata = cloneStringMapPreserve(attestation.Metadata)
	}
	return out
}

func clonePolicyReceipts(in []PolicyReceiptEvidence) []PolicyReceiptEvidence {
	if in == nil {
		return nil
	}
	out := make([]PolicyReceiptEvidence, len(in))
	copy(out, in)
	return out
}

func cloneAgentPassports(in []AgentPassportEvidence) []AgentPassportEvidence {
	if in == nil {
		return nil
	}
	out := make([]AgentPassportEvidence, len(in))
	for i, passport := range in {
		out[i] = passport
		out[i].Capabilities = cloneStringSlicePreserve(passport.Capabilities)
		out[i].SponsorChain = clonePassportSponsors(passport.SponsorChain)
		out[i].JurisdictionTags = cloneStringSlicePreserve(passport.JurisdictionTags)
		out[i].AllowedTools = cloneStringSlicePreserve(passport.AllowedTools)
		out[i].Metadata = cloneStringMapPreserve(passport.Metadata)
	}
	return out
}

func cloneTraceLinks(in []TraceLink) []TraceLink {
	if in == nil {
		return nil
	}
	out := make([]TraceLink, len(in))
	copy(out, in)
	return out
}

func cloneApproverAttestations(in []ApproverAttestationEvidence) []ApproverAttestationEvidence {
	if in == nil {
		return nil
	}
	out := make([]ApproverAttestationEvidence, len(in))
	for i, attestation := range in {
		out[i] = attestation
		out[i].Metadata = cloneStringMapPreserve(attestation.Metadata)
	}
	return out
}

func cloneValueSettlements(in []ValueSettlementEvidence) []ValueSettlementEvidence {
	if in == nil {
		return nil
	}
	out := make([]ValueSettlementEvidence, len(in))
	for i, settlement := range in {
		out[i] = settlement
		out[i].Metadata = cloneStringMapPreserve(settlement.Metadata)
	}
	return out
}

func cloneTrustCompliancePackages(in []TrustCompliancePackageEvidence) []TrustCompliancePackageEvidence {
	if in == nil {
		return nil
	}
	out := make([]TrustCompliancePackageEvidence, len(in))
	for i, pkg := range in {
		out[i] = pkg
		out[i].VerificationKeyIDs = cloneStringSlicePreserve(pkg.VerificationKeyIDs)
		if pkg.Signature != nil {
			signature := *pkg.Signature
			out[i].Signature = &signature
		}
		if pkg.AuditAnchor != nil {
			auditAnchor := *pkg.AuditAnchor
			out[i].AuditAnchor = &auditAnchor
		}
		out[i].Metadata = cloneStringMapPreserve(pkg.Metadata)
	}
	return out
}

func cloneCustodyEntries(in []CustodyEntry) []CustodyEntry {
	if in == nil {
		return nil
	}
	out := make([]CustodyEntry, len(in))
	copy(out, in)
	return out
}

func clonePassportSponsors(in []PassportSponsor) []PassportSponsor {
	if in == nil {
		return nil
	}
	out := make([]PassportSponsor, len(in))
	copy(out, in)
	return out
}

func cloneStringMapPreserve(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneStringSlicePreserve(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
