package sovereign_test

import (
	"context"
	"testing"

	"github.com/aethelred/aethelred/pkg/deploy/sovereign"
)

func benchSetupController(b *testing.B) *sovereign.SovereignController {
	b.Helper()
	ctrl, err := sovereign.NewSovereignController(sovereign.ControllerConfig{
		DefaultMode:            sovereign.Cloud,
		AllowedRegions:         []string{"eu-west-1", "us-east-1", "ap-southeast-1"},
		ComplianceRequirements: []string{"gdpr", "hipaa"},
	})
	if err != nil {
		b.Fatalf("setup: NewSovereignController failed: %v", err)
	}
	return ctrl
}

func BenchmarkDeployValidation(b *testing.B) {
	ctrl := benchSetupController(b)
	ctx := context.Background()
	spec := sovereign.DeploymentSpec{
		Name:   "bench-deployment",
		Mode:   sovereign.Cloud,
		Region: "eu-west-1",
		Storage: sovereign.StorageConfig{
			EncryptionAtRest:    true,
			EncryptionAlgorithm: "AES-256-GCM",
		},
		Network: sovereign.NetworkConfig{
			TLSMinVersion: "1.3",
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ctrl.Deploy(ctx, spec)
	}
}

func BenchmarkRegionRouting(b *testing.B) {
	ctrl := benchSetupController(b)
	ctx := context.Background()

	// Deploy to multiple regions first.
	regions := []string{"eu-west-1", "us-east-1", "ap-southeast-1"}
	for _, region := range regions {
		_, _ = ctrl.Deploy(ctx, sovereign.DeploymentSpec{
			Name:   "bench-" + region,
			Mode:   sovereign.Cloud,
			Region: region,
			Storage: sovereign.StorageConfig{
				EncryptionAtRest:    true,
				EncryptionAlgorithm: "AES-256-GCM",
			},
			Network: sovereign.NetworkConfig{
				TLSMinVersion: "1.3",
			},
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ctrl.ListDeployments()
	}
}

func BenchmarkComplianceCheck(b *testing.B) {
	ctrl := benchSetupController(b)
	ctx := context.Background()

	dep, err := ctrl.Deploy(ctx, sovereign.DeploymentSpec{
		Name:   "bench-compliance",
		Mode:   sovereign.Cloud,
		Region: "eu-west-1",
		Storage: sovereign.StorageConfig{
			EncryptionAtRest:    true,
			EncryptionAlgorithm: "AES-256-GCM",
		},
		Network: sovereign.NetworkConfig{
			TLSMinVersion: "1.3",
		},
	})
	if err != nil {
		b.Fatalf("setup: Deploy failed: %v", err)
	}

	checker := sovereign.NewDeploymentChecker()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = checker.CheckCompliance(ctx, dep, []string{"gdpr"})
	}
}
