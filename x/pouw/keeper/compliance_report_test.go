package keeper_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// =============================================================================
// SQ09: Compliance Mapping Engine Tests
// =============================================================================

func TestEnterprise_ComplianceReportGenerates(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.GenerateComplianceReport(ctx, k)
	require.NotNil(t, report)

	// Must have controls from all four regulation families.
	require.Greater(t, report.TotalCount, 0, "report must contain controls")
	require.Greater(t, report.MappedCount, 0, "report must have mapped controls")

	// Verify all four regulation families are present.
	byReg := report.ByRegulation()
	require.Contains(t, byReg, "HIPAA", "missing HIPAA controls")
	require.Contains(t, byReg, "GDPR", "missing GDPR controls")
	require.Contains(t, byReg, "PCI DSS v4.0", "missing PCI DSS controls")
	require.Contains(t, byReg, "UAE", "missing UAE controls")

	// Coverage must be above 50% (technical artifacts are strong).
	require.Greater(t, report.CoverageP, 50.0,
		"coverage should exceed 50%% given available technical artifacts")

	// Gap count must be non-zero (BAA, DPIA, IRP are known gaps).
	require.Greater(t, report.GapCount, 0, "should have known gaps")

	// Mapped + gap must equal total.
	require.Equal(t, report.TotalCount, report.MappedCount+report.GapCount,
		"mapped + gap must equal total")

	t.Logf("Compliance report: %d total, %d mapped (%.1f%%), %d gaps",
		report.TotalCount, report.MappedCount, report.CoverageP, report.GapCount)
}

func TestEnterprise_ComplianceReportGaps(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.GenerateComplianceReport(ctx, k)
	gaps := report.Gaps()

	// Known mandatory gaps: BAA, DPIA, IRP, cross-border transfers.
	require.NotEmpty(t, gaps, "should have unmapped controls")

	// BAA is a known gap for HIPAA.
	foundBAA := false
	for _, g := range gaps {
		if g.Regulation == "HIPAA" && strings.Contains(g.ControlName, "Business Associate") {
			foundBAA = true
			break
		}
	}
	require.True(t, foundBAA, "HIPAA BAA should be identified as a gap")

	t.Logf("Total gaps: %d", len(gaps))
	for _, g := range gaps {
		t.Logf("  GAP: [%s] %s -- %s", g.Regulation, g.ControlID, g.ControlName)
	}
}

func TestEnterprise_ComplianceReportMappedArtifacts(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.GenerateComplianceReport(ctx, k)
	mapped := report.MappedControls()

	require.NotEmpty(t, mapped, "should have mapped controls")

	// Every mapped control must have a non-empty artifact path.
	for _, c := range mapped {
		require.NotEmpty(t, c.Artifact,
			"mapped control %s/%s must have an artifact path", c.Regulation, c.ControlID)
	}
}

func TestEnterprise_ComplianceReportSummaryRendering(t *testing.T) {
	k, ctx := newTestKeeper(t)

	report := keeper.GenerateComplianceReport(ctx, k)
	summary := report.RenderSummary()

	require.Contains(t, summary, "Compliance Mapping Report")
	require.Contains(t, summary, "HIPAA")
	require.Contains(t, summary, "GDPR")
	require.Contains(t, summary, "PCI DSS")
	require.Contains(t, summary, "UAE")
	require.Contains(t, summary, "Gaps")

	t.Log(summary)
}
