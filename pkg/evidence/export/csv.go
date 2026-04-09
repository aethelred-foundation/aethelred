package export

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	"github.com/aethelred/aethelred/pkg/evidence"
)

// ---------------------------------------------------------------------------
// CSV Export
// ---------------------------------------------------------------------------
//
// Exports evidence bundles to CSV format for spreadsheet analysis and
// data warehousing. Each evidence component (records, seals, attestations,
// custody chain) gets its own CSV section.
// ---------------------------------------------------------------------------

// CSVExporter exports evidence bundles to CSV format.
type CSVExporter struct{}

// NewCSVExporter creates a new CSV exporter.
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{}
}

// ExportRecords exports evidence records to CSV.
func (e *CSVExporter) ExportRecords(bundle *evidence.EvidenceBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("evidence/export/csv: nil bundle")
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	// Header.
	if err := w.Write([]string{
		"Record ID", "Type", "Action", "Actor", "Timestamp", "Block Height", "Hash",
	}); err != nil {
		return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
	}

	for _, r := range bundle.Records {
		if err := w.Write([]string{
			r.ID,
			r.Type,
			r.Action,
			r.Actor,
			r.Timestamp,
			strconv.FormatInt(r.BlockHeight, 10),
			r.Hash,
		}); err != nil {
			return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
		}
	}

	w.Flush()
	return sb.String(), w.Error()
}

// ExportSeals exports verification seals to CSV.
func (e *CSVExporter) ExportSeals(bundle *evidence.EvidenceBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("evidence/export/csv: nil bundle")
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	if err := w.Write([]string{
		"Seal ID", "Job ID", "Output Hash", "Validator Count", "Block Height", "Timestamp",
	}); err != nil {
		return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
	}

	for _, s := range bundle.Seals {
		if err := w.Write([]string{
			s.SealID,
			s.JobID,
			s.OutputHash,
			strconv.Itoa(s.ValidatorCount),
			strconv.FormatInt(s.BlockHeight, 10),
			s.Timestamp,
		}); err != nil {
			return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
		}
	}

	w.Flush()
	return sb.String(), w.Error()
}

// ExportAttestations exports attestations to CSV.
func (e *CSVExporter) ExportAttestations(bundle *evidence.EvidenceBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("evidence/export/csv: nil bundle")
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	if err := w.Write([]string{
		"Attestation ID", "Type", "Platform", "Enclave ID", "Measurement", "Timestamp",
	}); err != nil {
		return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
	}

	for _, a := range bundle.Attestations {
		if err := w.Write([]string{
			a.ID,
			a.Type,
			a.Platform,
			a.EnclaveID,
			a.Measurement,
			a.Timestamp,
		}); err != nil {
			return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
		}
	}

	w.Flush()
	return sb.String(), w.Error()
}

// ExportCustodyChain exports the chain of custody to CSV.
func (e *CSVExporter) ExportCustodyChain(bundle *evidence.EvidenceBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("evidence/export/csv: nil bundle")
	}

	var sb strings.Builder
	w := csv.NewWriter(&sb)

	if err := w.Write([]string{
		"Custodian", "Action", "Timestamp", "Previous Hash", "Hash", "Signature",
	}); err != nil {
		return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
	}

	for _, c := range bundle.ChainOfCustody {
		if err := w.Write([]string{
			c.Custodian,
			c.Action,
			c.Timestamp,
			c.PreviousHash,
			c.Hash,
			c.Signature,
		}); err != nil {
			return "", fmt.Errorf("evidence/export/csv: write error: %w", err)
		}
	}

	w.Flush()
	return sb.String(), w.Error()
}

// ExportAll exports all bundle components to a combined CSV.
func (e *CSVExporter) ExportAll(bundle *evidence.EvidenceBundle) (string, error) {
	if bundle == nil {
		return "", fmt.Errorf("evidence/export/csv: nil bundle")
	}

	var sb strings.Builder

	sb.WriteString("# Evidence Bundle: " + bundle.ID + "\n")
	sb.WriteString("# Framework: " + bundle.Framework + "\n")
	sb.WriteString("# Created: " + bundle.CreatedAt + "\n\n")

	sb.WriteString("## Records\n")
	records, err := e.ExportRecords(bundle)
	if err != nil {
		return "", err
	}
	sb.WriteString(records)
	sb.WriteString("\n")

	if len(bundle.Seals) > 0 {
		sb.WriteString("## Seals\n")
		seals, err := e.ExportSeals(bundle)
		if err != nil {
			return "", err
		}
		sb.WriteString(seals)
		sb.WriteString("\n")
	}

	if len(bundle.Attestations) > 0 {
		sb.WriteString("## Attestations\n")
		atts, err := e.ExportAttestations(bundle)
		if err != nil {
			return "", err
		}
		sb.WriteString(atts)
		sb.WriteString("\n")
	}

	if len(bundle.ChainOfCustody) > 0 {
		sb.WriteString("## Chain of Custody\n")
		custody, err := e.ExportCustodyChain(bundle)
		if err != nil {
			return "", err
		}
		sb.WriteString(custody)
	}

	return sb.String(), nil
}
