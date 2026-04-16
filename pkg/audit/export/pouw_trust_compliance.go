package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

const PouwTrustComplianceExportVersion = "1.0.0"

type PouwTrustRegistryHistorySummary struct {
	TotalRecords     int            `json:"total_records"`
	ActionCounts     map[string]int `json:"action_counts,omitempty"`
	GovernanceActors []string       `json:"governance_actors,omitempty"`
	LatestSequence   uint64         `json:"latest_sequence,omitempty"`
	LatestAction     string         `json:"latest_action,omitempty"`
	LatestActor      string         `json:"latest_actor,omitempty"`
	LatestTimestamp  string         `json:"latest_timestamp,omitempty"`
}

type PouwComplianceRegulationSummary struct {
	Regulation     string  `json:"regulation"`
	TotalControls  int     `json:"total_controls"`
	MappedControls int     `json:"mapped_controls"`
	GapControls    int     `json:"gap_controls"`
	CoveragePct    float64 `json:"coverage_pct"`
}

type PouwComplianceSummary struct {
	TotalControls       int                               `json:"total_controls"`
	MappedControls      int                               `json:"mapped_controls"`
	GapControls         int                               `json:"gap_controls"`
	CoveragePct         float64                           `json:"coverage_pct"`
	RegulationBreakdown []PouwComplianceRegulationSummary `json:"regulation_breakdown,omitempty"`
}

type PouwTrustComplianceExport struct {
	ExportVersion       string                                         `json:"export_version"`
	GeneratedAt         string                                         `json:"generated_at"`
	ModuleStatus        *pouwkeeper.QueryModuleStatusResponse          `json:"module_status,omitempty"`
	TrustRegistryStatus *pouwkeeper.EnterpriseAuditTrustRegistryStatus `json:"trust_registry_status,omitempty"`
	TrustRegistry       *pouwkeeper.EnterpriseAuditTrustRegistry       `json:"trust_registry,omitempty"`
	HistorySummary      *PouwTrustRegistryHistorySummary               `json:"history_summary,omitempty"`
	History             []pouwkeeper.AuditRecord                       `json:"history,omitempty"`
	ComplianceSummary   *PouwComplianceSummary                         `json:"compliance_summary,omitempty"`
	ComplianceReport    *pouwkeeper.ComplianceReport                   `json:"compliance_report,omitempty"`
}

func BuildPouwTrustComplianceExport(
	generatedAt string,
	moduleStatus *pouwkeeper.QueryModuleStatusResponse,
	trustStatus *pouwkeeper.EnterpriseAuditTrustRegistryStatus,
	registry *pouwkeeper.EnterpriseAuditTrustRegistry,
	history []pouwkeeper.AuditRecord,
	report *pouwkeeper.ComplianceReport,
) *PouwTrustComplianceExport {
	generatedAt = strings.TrimSpace(generatedAt)
	if generatedAt == "" {
		generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	clonedHistory := make([]pouwkeeper.AuditRecord, 0, len(history))
	clonedHistory = append(clonedHistory, history...)

	return &PouwTrustComplianceExport{
		ExportVersion:       PouwTrustComplianceExportVersion,
		GeneratedAt:         generatedAt,
		ModuleStatus:        moduleStatus,
		TrustRegistryStatus: trustStatus,
		TrustRegistry:       registry,
		HistorySummary:      SummarizePouwTrustRegistryHistory(clonedHistory),
		History:             clonedHistory,
		ComplianceSummary:   SummarizePouwComplianceReport(report),
		ComplianceReport:    report,
	}
}

func SummarizePouwTrustRegistryHistory(records []pouwkeeper.AuditRecord) *PouwTrustRegistryHistorySummary {
	summary := &PouwTrustRegistryHistorySummary{
		TotalRecords: len(records),
		ActionCounts: make(map[string]int),
	}
	if len(records) == 0 {
		return summary
	}

	actors := make(map[string]struct{}, len(records))
	for _, record := range records {
		summary.ActionCounts[record.Action]++
		if actor := strings.TrimSpace(record.Actor); actor != "" {
			actors[actor] = struct{}{}
		}
		if record.Sequence >= summary.LatestSequence {
			summary.LatestSequence = record.Sequence
			summary.LatestAction = record.Action
			summary.LatestActor = record.Actor
			summary.LatestTimestamp = record.Timestamp
		}
	}
	for actor := range actors {
		summary.GovernanceActors = append(summary.GovernanceActors, actor)
	}
	sort.Strings(summary.GovernanceActors)
	return summary
}

func SummarizePouwComplianceReport(report *pouwkeeper.ComplianceReport) *PouwComplianceSummary {
	if report == nil {
		return nil
	}

	summary := &PouwComplianceSummary{
		TotalControls:  report.TotalCount,
		MappedControls: report.MappedCount,
		GapControls:    report.GapCount,
		CoveragePct:    report.CoverageP,
	}

	byRegulation := report.ByRegulation()
	regulations := make([]string, 0, len(byRegulation))
	for regulation := range byRegulation {
		regulations = append(regulations, regulation)
	}
	sort.Strings(regulations)

	for _, regulation := range regulations {
		controls := byRegulation[regulation]
		regulationSummary := PouwComplianceRegulationSummary{
			Regulation:    regulation,
			TotalControls: len(controls),
		}
		for _, control := range controls {
			if control.Status == pouwkeeper.ComplianceStatusMapped {
				regulationSummary.MappedControls++
			} else {
				regulationSummary.GapControls++
			}
		}
		if regulationSummary.TotalControls > 0 {
			regulationSummary.CoveragePct = float64(regulationSummary.MappedControls) / float64(regulationSummary.TotalControls) * 100
		}
		summary.RegulationBreakdown = append(summary.RegulationBreakdown, regulationSummary)
	}

	return summary
}

func NormalizePouwTrustComplianceFormat(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "json":
		return "json", nil
	case "csv":
		return "csv", nil
	case "oscal":
		return "oscal", nil
	default:
		return "", fmt.Errorf("unsupported export format %q", raw)
	}
}

func ExportPouwTrustComplianceJSON(doc *PouwTrustComplianceExport) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance: nil document")
	}
	return json.MarshalIndent(doc, "", "  ")
}

func ExportPouwTrustComplianceCSV(doc *PouwTrustComplianceExport) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance: nil document")
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{
		"row_type",
		"generated_at",
		"export_version",
		"entity_type",
		"entity_id",
		"status",
		"action",
		"actor",
		"sequence",
		"timestamp",
		"module_block_height",
		"current_epoch",
		"total_uwu",
		"trust_configured",
		"trust_version",
		"trust_source",
		"required_action",
		"required_jurisdiction",
		"policy_signer_count",
		"active_policy_signer_count",
		"allowed_sponsor_count",
		"active_sponsor_count",
		"compliance_total_controls",
		"compliance_mapped_controls",
		"compliance_gap_controls",
		"compliance_coverage_pct",
		"regulation",
		"control_id",
		"control_name",
		"artifact",
		"evidence_type",
		"details",
	}
	if err := w.Write(header); err != nil {
		return nil, fmt.Errorf("write csv header: %w", err)
	}

	writeRow := func(row []string) error {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
		return nil
	}

	moduleBlockHeight := ""
	currentEpoch := ""
	totalUWU := ""
	if doc.ModuleStatus != nil {
		moduleBlockHeight = strconv.FormatInt(doc.ModuleStatus.BlockHeight, 10)
		currentEpoch = strconv.FormatUint(doc.ModuleStatus.CurrentEpoch, 10)
		totalUWU = strconv.FormatUint(doc.ModuleStatus.TotalUWU, 10)
	}

	trustConfigured := "false"
	trustVersion := ""
	trustSource := ""
	requiredAction := ""
	requiredJurisdiction := ""
	policySignerCount := "0"
	activePolicySignerCount := "0"
	allowedSponsorCount := "0"
	activeSponsorCount := "0"
	if doc.TrustRegistryStatus != nil {
		if doc.TrustRegistryStatus.Configured {
			trustConfigured = "true"
		}
		trustVersion = doc.TrustRegistryStatus.Version
		trustSource = doc.TrustRegistryStatus.Source
		requiredAction = doc.TrustRegistryStatus.RequiredAction
		requiredJurisdiction = doc.TrustRegistryStatus.RequiredJurisdiction
		policySignerCount = strconv.Itoa(doc.TrustRegistryStatus.PolicySignerCount)
		activePolicySignerCount = strconv.Itoa(doc.TrustRegistryStatus.ActivePolicySignerCount)
		allowedSponsorCount = strconv.Itoa(doc.TrustRegistryStatus.AllowedSponsorCount)
		activeSponsorCount = strconv.Itoa(doc.TrustRegistryStatus.ActiveSponsorCount)
	}

	complianceTotalControls := "0"
	complianceMappedControls := "0"
	complianceGapControls := "0"
	complianceCoveragePct := ""
	if doc.ComplianceSummary != nil {
		complianceTotalControls = strconv.Itoa(doc.ComplianceSummary.TotalControls)
		complianceMappedControls = strconv.Itoa(doc.ComplianceSummary.MappedControls)
		complianceGapControls = strconv.Itoa(doc.ComplianceSummary.GapControls)
		complianceCoveragePct = formatPouwCoveragePct(doc.ComplianceSummary.CoveragePct)
	}

	if err := writeRow([]string{
		"summary",
		doc.GeneratedAt,
		doc.ExportVersion,
		"pouw_trust_compliance",
		"summary",
		"summary",
		"",
		"",
		"",
		"",
		moduleBlockHeight,
		currentEpoch,
		totalUWU,
		trustConfigured,
		trustVersion,
		trustSource,
		requiredAction,
		requiredJurisdiction,
		policySignerCount,
		activePolicySignerCount,
		allowedSponsorCount,
		activeSponsorCount,
		complianceTotalControls,
		complianceMappedControls,
		complianceGapControls,
		complianceCoveragePct,
		"",
		"",
		"",
		"",
		"",
		encodePouwComplianceStringMap(map[string]string{
			"history_records": strconv.Itoa(len(doc.History)),
		}),
	}); err != nil {
		return nil, err
	}

	if doc.TrustRegistry != nil {
		for _, signer := range doc.TrustRegistry.PolicySigners {
			if err := writeRow([]string{
				"policy_signer",
				doc.GeneratedAt,
				doc.ExportVersion,
				"policy_signer",
				signer.DID,
				string(signer.Status),
				"",
				"",
				"",
				"",
				moduleBlockHeight,
				currentEpoch,
				totalUWU,
				trustConfigured,
				trustVersion,
				trustSource,
				requiredAction,
				requiredJurisdiction,
				policySignerCount,
				activePolicySignerCount,
				allowedSponsorCount,
				activeSponsorCount,
				complianceTotalControls,
				complianceMappedControls,
				complianceGapControls,
				complianceCoveragePct,
				"",
				"",
				"",
				"",
				"",
				encodePouwComplianceStringMap(signer.Metadata,
					"public_key="+signer.PublicKeyHex,
					"actions="+strings.Join(signer.Actions, "|"),
					"jurisdictions="+strings.Join(signer.Jurisdictions, "|")),
			}); err != nil {
				return nil, err
			}
		}
		for _, sponsor := range doc.TrustRegistry.AllowedSponsors {
			if err := writeRow([]string{
				"allowed_sponsor",
				doc.GeneratedAt,
				doc.ExportVersion,
				"allowed_sponsor",
				sponsor.DID,
				string(sponsor.Status),
				"",
				"",
				"",
				"",
				moduleBlockHeight,
				currentEpoch,
				totalUWU,
				trustConfigured,
				trustVersion,
				trustSource,
				requiredAction,
				requiredJurisdiction,
				policySignerCount,
				activePolicySignerCount,
				allowedSponsorCount,
				activeSponsorCount,
				complianceTotalControls,
				complianceMappedControls,
				complianceGapControls,
				complianceCoveragePct,
				"",
				"",
				"",
				"",
				"",
				encodePouwComplianceStringMap(sponsor.Metadata,
					"actions="+strings.Join(sponsor.Actions, "|"),
					"jurisdictions="+strings.Join(sponsor.Jurisdictions, "|")),
			}); err != nil {
				return nil, err
			}
		}
	}

	if doc.HistorySummary != nil {
		if err := writeRow([]string{
			"history_summary",
			doc.GeneratedAt,
			doc.ExportVersion,
			"trust_registry_history",
			"summary",
			"summary",
			doc.HistorySummary.LatestAction,
			doc.HistorySummary.LatestActor,
			strconv.FormatUint(doc.HistorySummary.LatestSequence, 10),
			doc.HistorySummary.LatestTimestamp,
			moduleBlockHeight,
			currentEpoch,
			totalUWU,
			trustConfigured,
			trustVersion,
			trustSource,
			requiredAction,
			requiredJurisdiction,
			policySignerCount,
			activePolicySignerCount,
			allowedSponsorCount,
			activeSponsorCount,
			complianceTotalControls,
			complianceMappedControls,
			complianceGapControls,
			complianceCoveragePct,
			"",
			"",
			"",
			"",
			"",
			encodePouwComplianceStringMap(doc.HistorySummary.ActionCounts,
				"governance_actors="+strings.Join(doc.HistorySummary.GovernanceActors, "|"),
				"total_records="+strconv.Itoa(doc.HistorySummary.TotalRecords)),
		}); err != nil {
			return nil, err
		}
	}

	for _, record := range doc.History {
		if err := writeRow([]string{
			"history_record",
			doc.GeneratedAt,
			doc.ExportVersion,
			string(record.Category),
			record.RecordHash,
			string(record.Severity),
			record.Action,
			record.Actor,
			strconv.FormatUint(record.Sequence, 10),
			record.Timestamp,
			strconv.FormatInt(record.BlockHeight, 10),
			currentEpoch,
			totalUWU,
			trustConfigured,
			trustVersion,
			trustSource,
			requiredAction,
			requiredJurisdiction,
			policySignerCount,
			activePolicySignerCount,
			allowedSponsorCount,
			activeSponsorCount,
			complianceTotalControls,
			complianceMappedControls,
			complianceGapControls,
			complianceCoveragePct,
			"",
			"",
			"",
			"",
			"",
			encodePouwComplianceStringMap(record.Details, "previous_hash="+record.PreviousHash),
		}); err != nil {
			return nil, err
		}
	}

	if doc.ComplianceSummary != nil {
		if err := writeRow([]string{
			"compliance_summary",
			doc.GeneratedAt,
			doc.ExportVersion,
			"compliance_report",
			"summary",
			"summary",
			"",
			"",
			"",
			"",
			moduleBlockHeight,
			currentEpoch,
			totalUWU,
			trustConfigured,
			trustVersion,
			trustSource,
			requiredAction,
			requiredJurisdiction,
			policySignerCount,
			activePolicySignerCount,
			allowedSponsorCount,
			activeSponsorCount,
			complianceTotalControls,
			complianceMappedControls,
			complianceGapControls,
			complianceCoveragePct,
			"",
			"",
			"",
			"",
			"",
			"",
		}); err != nil {
			return nil, err
		}

		for _, regulation := range doc.ComplianceSummary.RegulationBreakdown {
			if err := writeRow([]string{
				"regulation_summary",
				doc.GeneratedAt,
				doc.ExportVersion,
				"compliance_regulation",
				regulation.Regulation,
				"summary",
				"",
				"",
				"",
				"",
				moduleBlockHeight,
				currentEpoch,
				totalUWU,
				trustConfigured,
				trustVersion,
				trustSource,
				requiredAction,
				requiredJurisdiction,
				policySignerCount,
				activePolicySignerCount,
				allowedSponsorCount,
				activeSponsorCount,
				complianceTotalControls,
				complianceMappedControls,
				complianceGapControls,
				complianceCoveragePct,
				regulation.Regulation,
				"",
				"",
				"",
				"",
				encodePouwComplianceStringMap(map[string]string{
					"total_controls":  strconv.Itoa(regulation.TotalControls),
					"mapped_controls": strconv.Itoa(regulation.MappedControls),
					"gap_controls":    strconv.Itoa(regulation.GapControls),
					"coverage_pct":    formatPouwCoveragePct(regulation.CoveragePct),
				}),
			}); err != nil {
				return nil, err
			}
		}
	}

	if doc.ComplianceReport != nil {
		for _, control := range doc.ComplianceReport.Controls {
			if err := writeRow([]string{
				"compliance_control",
				doc.GeneratedAt,
				doc.ExportVersion,
				"compliance_control",
				control.ControlID,
				string(control.Status),
				"",
				"",
				"",
				"",
				moduleBlockHeight,
				currentEpoch,
				totalUWU,
				trustConfigured,
				trustVersion,
				trustSource,
				requiredAction,
				requiredJurisdiction,
				policySignerCount,
				activePolicySignerCount,
				allowedSponsorCount,
				activeSponsorCount,
				complianceTotalControls,
				complianceMappedControls,
				complianceGapControls,
				complianceCoveragePct,
				control.Regulation,
				control.ControlID,
				control.ControlName,
				control.Artifact,
				control.EvidenceType,
				"",
			}); err != nil {
				return nil, err
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("flush csv: %w", err)
	}
	return buf.Bytes(), nil
}

func ExportPouwTrustComplianceOSCAL(doc *PouwTrustComplianceExport) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance: nil document")
	}

	now := doc.GeneratedAt
	if strings.TrimSpace(now) == "" {
		now = time.Now().UTC().Format(time.RFC3339Nano)
	}
	start := now
	if doc.TrustRegistryStatus != nil && strings.TrimSpace(doc.TrustRegistryStatus.UpdatedAt) != "" {
		start = doc.TrustRegistryStatus.UpdatedAt
	}

	controlIDs := make([]string, 0)
	findings := make([]OSCALFinding, 0)
	observations := make([]OSCALObservation, 0)

	if doc.TrustRegistry != nil {
		collected := now
		if strings.TrimSpace(doc.TrustRegistry.UpdatedAt) != "" {
			collected = doc.TrustRegistry.UpdatedAt
		}
		for _, signer := range doc.TrustRegistry.PolicySigners {
			observations = append(observations, OSCALObservation{
				UUID:        deterministicUUID(pouwTrustComplianceSeed(doc) + ":policy-signer:" + signer.DID),
				Title:       "Trusted Policy Signer",
				Description: signer.DID,
				Methods:     []string{"EXAMINE"},
				Collected:   collected,
				Props: []OSCALProperty{
					{Name: "did", Value: signer.DID},
					{Name: "status", Value: string(signer.Status)},
					{Name: "public-key", Value: signer.PublicKeyHex},
					{Name: "actions", Value: strings.Join(signer.Actions, "|")},
					{Name: "jurisdictions", Value: strings.Join(signer.Jurisdictions, "|")},
				},
			})
		}
		for _, sponsor := range doc.TrustRegistry.AllowedSponsors {
			observations = append(observations, OSCALObservation{
				UUID:        deterministicUUID(pouwTrustComplianceSeed(doc) + ":allowed-sponsor:" + sponsor.DID),
				Title:       "Allowed Enterprise Sponsor",
				Description: sponsor.DID,
				Methods:     []string{"EXAMINE"},
				Collected:   collected,
				Props: []OSCALProperty{
					{Name: "did", Value: sponsor.DID},
					{Name: "status", Value: string(sponsor.Status)},
					{Name: "actions", Value: strings.Join(sponsor.Actions, "|")},
					{Name: "jurisdictions", Value: strings.Join(sponsor.Jurisdictions, "|")},
				},
			})
		}
	}

	for _, record := range doc.History {
		observations = append(observations, OSCALObservation{
			UUID:        deterministicUUID(pouwTrustComplianceSeed(doc) + ":history:" + strconv.FormatUint(record.Sequence, 10)),
			Title:       fmt.Sprintf("Trust Governance Record #%d", record.Sequence),
			Description: record.Action,
			Methods:     []string{"EXAMINE", "TEST"},
			Collected:   record.Timestamp,
			Props: []OSCALProperty{
				{Name: "record-hash", Value: record.RecordHash},
				{Name: "previous-hash", Value: record.PreviousHash},
				{Name: "actor", Value: record.Actor},
				{Name: "category", Value: string(record.Category)},
				{Name: "severity", Value: string(record.Severity)},
				{Name: "block-height", Value: strconv.FormatInt(record.BlockHeight, 10)},
			},
		})
	}

	if doc.ComplianceReport != nil {
		for _, control := range doc.ComplianceReport.Controls {
			controlIDs = append(controlIDs, control.ControlID)
			findings = append(findings, OSCALFinding{
				UUID:        deterministicUUID(pouwTrustComplianceSeed(doc) + ":control:" + control.ControlID),
				Title:       fmt.Sprintf("%s: %s", control.ControlID, control.ControlName),
				Description: control.Regulation,
				Target: OSCALFindingTarget{
					Type:     "objective-id",
					TargetID: control.ControlID,
					Status: OSCALFindingStatus{
						State: normalizePouwComplianceFindingState(control.Status),
					},
				},
				Props: []OSCALProperty{
					{Name: "regulation", Value: control.Regulation},
					{Name: "artifact", Value: control.Artifact},
					{Name: "evidence-type", Value: control.EvidenceType},
				},
			})
		}
	}

	props := []OSCALProperty{
		{Name: "export-version", Value: doc.ExportVersion},
		{Name: "generated-at", Value: now},
		{Name: "history-total", Value: strconv.Itoa(len(doc.History))},
	}
	if doc.ModuleStatus != nil {
		props = append(props,
			OSCALProperty{Name: "block-height", Value: strconv.FormatInt(doc.ModuleStatus.BlockHeight, 10)},
			OSCALProperty{Name: "current-epoch", Value: strconv.FormatUint(doc.ModuleStatus.CurrentEpoch, 10)},
			OSCALProperty{Name: "total-uwu", Value: strconv.FormatUint(doc.ModuleStatus.TotalUWU, 10)},
		)
	}
	if doc.TrustRegistryStatus != nil {
		props = append(props,
			OSCALProperty{Name: "trust-configured", Value: strconv.FormatBool(doc.TrustRegistryStatus.Configured)},
			OSCALProperty{Name: "registry-version", Value: doc.TrustRegistryStatus.Version},
			OSCALProperty{Name: "registry-source", Value: doc.TrustRegistryStatus.Source},
			OSCALProperty{Name: "required-action", Value: doc.TrustRegistryStatus.RequiredAction},
			OSCALProperty{Name: "required-jurisdiction", Value: doc.TrustRegistryStatus.RequiredJurisdiction},
			OSCALProperty{Name: "policy-signer-count", Value: strconv.Itoa(doc.TrustRegistryStatus.PolicySignerCount)},
			OSCALProperty{Name: "active-policy-signer-count", Value: strconv.Itoa(doc.TrustRegistryStatus.ActivePolicySignerCount)},
			OSCALProperty{Name: "allowed-sponsor-count", Value: strconv.Itoa(doc.TrustRegistryStatus.AllowedSponsorCount)},
			OSCALProperty{Name: "active-sponsor-count", Value: strconv.Itoa(doc.TrustRegistryStatus.ActiveSponsorCount)},
		)
	}
	if doc.ComplianceSummary != nil {
		props = append(props,
			OSCALProperty{Name: "compliance-total-controls", Value: strconv.Itoa(doc.ComplianceSummary.TotalControls)},
			OSCALProperty{Name: "compliance-mapped-controls", Value: strconv.Itoa(doc.ComplianceSummary.MappedControls)},
			OSCALProperty{Name: "compliance-gap-controls", Value: strconv.Itoa(doc.ComplianceSummary.GapControls)},
			OSCALProperty{Name: "compliance-coverage-pct", Value: formatPouwCoveragePct(doc.ComplianceSummary.CoveragePct)},
		)
	}

	result := OSCALAssessmentResult{
		AssessmentResults: OSCALAssessmentResults{
			UUID: deterministicUUID(pouwTrustComplianceSeed(doc) + ":document"),
			Metadata: OSCALMetadata{
				Title:        "Aethelred PoUW Trust Compliance Assessment",
				LastModified: now,
				Version:      doc.ExportVersion,
				OSCALVersion: "1.1.2",
				Roles: []OSCALRole{
					{ID: "assessor", Title: "Automated Trust Compliance Exporter"},
					{ID: "system-owner", Title: "Aethelred PoUW Control Plane"},
				},
				Parties: []OSCALParty{
					{
						UUID: deterministicUUID(pouwTrustComplianceSeed(doc) + ":party:aethelred"),
						Type: "organization",
						Name: "Aethelred",
					},
				},
				Props: props,
			},
			Results: []OSCALResult{
				{
					UUID:        deterministicUUID(pouwTrustComplianceSeed(doc) + ":result"),
					Title:       "PoUW Trust Compliance Result",
					Description: "Auditor-ready view of managed trust state, governance history, and regulatory control coverage",
					Start:       start,
					End:         now,
					Props:       props,
					ReviewedControls: OSCALReviewedControls{
						ControlSelections: []OSCALControlSelection{
							{IncludeControls: []OSCALSelectControlByID{{WithIDs: controlIDs}}},
						},
					},
					Findings:     findings,
					Observations: observations,
					Attestations: []OSCALAttestation{
						{
							Parts: []OSCALAttestationPart{
								{Name: "trust-summary", Prose: fmt.Sprintf("trust_configured=%s, history_total=%d", truthyString(doc.TrustRegistryStatus != nil && doc.TrustRegistryStatus.Configured), len(doc.History))},
								{Name: "compliance-summary", Prose: formatPouwComplianceAttestation(doc.ComplianceSummary)},
							},
						},
					},
				},
			},
		},
	}

	return json.MarshalIndent(result, "", "  ")
}

func pouwTrustComplianceSeed(doc *PouwTrustComplianceExport) string {
	parts := []string{"pouw-trust-compliance", doc.ExportVersion, doc.GeneratedAt}
	if doc.ModuleStatus != nil {
		parts = append(parts,
			strconv.FormatInt(doc.ModuleStatus.BlockHeight, 10),
			strconv.FormatUint(doc.ModuleStatus.CurrentEpoch, 10),
			strconv.FormatUint(doc.ModuleStatus.TotalUWU, 10),
		)
	}
	if doc.TrustRegistryStatus != nil {
		parts = append(parts,
			doc.TrustRegistryStatus.Version,
			doc.TrustRegistryStatus.Source,
			doc.TrustRegistryStatus.RequiredAction,
			doc.TrustRegistryStatus.RequiredJurisdiction,
		)
	}
	return strings.Join(parts, "|")
}

func normalizePouwComplianceFindingState(status pouwkeeper.ComplianceStatus) string {
	switch status {
	case pouwkeeper.ComplianceStatusMapped:
		return "satisfied"
	case pouwkeeper.ComplianceStatusUnmapped:
		return "not-satisfied"
	default:
		return "unknown"
	}
}

func formatPouwComplianceAttestation(summary *PouwComplianceSummary) string {
	if summary == nil {
		return "compliance_summary=unavailable"
	}
	return fmt.Sprintf(
		"controls=%d,mapped=%d,gaps=%d,coverage_pct=%s",
		summary.TotalControls,
		summary.MappedControls,
		summary.GapControls,
		formatPouwCoveragePct(summary.CoveragePct),
	)
}

func formatPouwCoveragePct(value float64) string {
	return strconv.FormatFloat(value, 'f', 1, 64)
}

func truthyString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func encodePouwComplianceStringMap(details any, extras ...string) string {
	parts := make([]string, 0, len(extras)+4)
	switch typed := details.(type) {
	case map[string]string:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+typed[k])
		}
	case map[string]int:
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, k+"="+strconv.Itoa(typed[k]))
		}
	}
	for _, extra := range extras {
		if strings.TrimSpace(extra) != "" {
			parts = append(parts, extra)
		}
	}
	return strings.Join(parts, ";")
}
