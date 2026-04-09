// Package export provides format-specific evidence export capabilities.
package export

import (
	"encoding/json"
	"fmt"

	"github.com/aethelred/aethelred/pkg/evidence"
)

// ---------------------------------------------------------------------------
// JSON Export
// ---------------------------------------------------------------------------

// JSONExporter exports evidence bundles to JSON format.
type JSONExporter struct {
	// PrettyPrint enables indented output for human readability.
	PrettyPrint bool
}

// NewJSONExporter creates a new JSON exporter.
func NewJSONExporter(prettyPrint bool) *JSONExporter {
	return &JSONExporter{PrettyPrint: prettyPrint}
}

// ExportBundle exports an evidence bundle to JSON bytes.
func (e *JSONExporter) ExportBundle(bundle *evidence.EvidenceBundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("evidence/export/json: nil bundle")
	}

	if e.PrettyPrint {
		return json.MarshalIndent(bundle, "", "  ")
	}
	return json.Marshal(bundle)
}

// ExportPortable exports a portable evidence package to JSON bytes.
func (e *JSONExporter) ExportPortable(pe *evidence.PortableEvidence) ([]byte, error) {
	if pe == nil {
		return nil, fmt.Errorf("evidence/export/json: nil portable evidence")
	}

	if e.PrettyPrint {
		return json.MarshalIndent(pe, "", "  ")
	}
	return json.Marshal(pe)
}

// ImportBundle imports an evidence bundle from JSON bytes.
func ImportBundle(data []byte) (*evidence.EvidenceBundle, error) {
	var bundle evidence.EvidenceBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("evidence/export/json: unmarshal failed: %w", err)
	}
	return &bundle, nil
}
