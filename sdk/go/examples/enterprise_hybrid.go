// Enterprise Hybrid Compute Job -- The Recommended Path (Go SDK).
//
// Demonstrates the full enterprise lifecycle:
//   1. Configure enterprise client
//   2. Submit a hybrid job (TEE + zkML -- the default)
//   3. Poll for completion
//   4. Fetch the evidence bundle (Digital Seal)
//   5. Verify the audit trail
//
// Build: go build -o enterprise_hybrid ./examples/enterprise_hybrid.go
// Run:   AETHELRED_API_KEY=<key> ./enterprise_hybrid
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aethelred/sdk-go/client"
	"github.com/aethelred/sdk-go/jobs"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  Enterprise Hybrid Verification -- Go SDK")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// -- Step 1: Configure enterprise client ----------------------
	apiKey := os.Getenv("AETHELRED_API_KEY")
	c, err := client.NewClient(
		client.Testnet,
		client.WithAPIKey(apiKey),
		client.WithTimeout(120*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("[1/5] Client configured (testnet)")
	fmt.Printf("      RPC:      %s\n", c.RPCURL())
	fmt.Printf("      Chain ID: %s\n", c.ChainID())

	// -- Step 2: Submit a hybrid job (the default) ----------------
	//
	// ProofType is left empty -- the SDK fills in HYBRID
	// (TEE attestation + zkML proof) for maximum assurance.
	resp, err := c.Jobs.Submit(ctx, jobs.SubmitRequest{
		ModelHash:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		InputHash:     "sha256:7d793037a0760186574b0282f2f435e7cee9c11619c6e091b3bc44b34c3e8c14",
		Priority:      5,
		TimeoutBlocks: 100,
	})
	if err != nil {
		log.Fatalf("Failed to submit job: %v", err)
	}
	fmt.Println("[2/5] Submitted enterprise hybrid job")
	fmt.Printf("      Job ID:  %s\n", resp.JobID)
	fmt.Printf("      Tx hash: %s\n", resp.TxHash)
	fmt.Println("      proof_type = HYBRID (TEE attestation + zkML proof)")

	// -- Step 3: Poll for completion ------------------------------
	fmt.Println("[3/5] Polling for completion (timeout 120 s)...")
	job, err := c.Jobs.WaitForCompletion(ctx, resp.JobID, 2*time.Second, 120*time.Second)
	if err != nil {
		log.Fatalf("Job did not complete: %v", err)
	}
	fmt.Printf("      Job status: %s\n", job.Status)

	// -- Step 4: Fetch evidence bundle ----------------------------
	//
	// The completed job's metadata contains the seal_id linking to
	// the on-chain Digital Seal with TEE attestation + zkML proof.
	sealID, ok := job.Metadata["seal_id"]
	if !ok {
		fmt.Println("[4/5] No seal_id in job metadata (job may still be finalizing)")
		fmt.Println("[5/5] Skipped -- no seal to verify")
		return
	}

	seal, err := c.Seals.Get(ctx, sealID)
	if err != nil {
		log.Fatalf("Failed to get seal: %v", err)
	}
	fmt.Println("[4/5] Evidence bundle retrieved")
	fmt.Printf("      Seal ID:    %s\n", seal.ID)
	fmt.Printf("      Validators: %d\n", len(seal.Validators))
	if seal.TEEAttestation != nil {
		fmt.Println("      TEE:        present")
	}
	if seal.ZKMLProof != nil {
		fmt.Println("      zkML proof: present")
	}

	// -- Step 5: Verify audit trail -------------------------------
	result, err := c.Seals.Verify(ctx, seal.ID)
	if err != nil {
		log.Fatalf("Failed to verify seal: %v", err)
	}
	fmt.Printf("[5/5] Audit trail verified: %v\n", result.Valid)
	for check, passed := range result.VerificationDetails {
		status := "FAIL"
		if passed {
			status = "PASS"
		}
		fmt.Printf("      %s: %s\n", check, status)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  Enterprise hybrid flow complete.")
	fmt.Println()
	fmt.Println("  Why HYBRID is the enterprise default:")
	fmt.Println("    - TEE gives fast hardware attestation (~1 s)")
	fmt.Println("    - zkML adds a mathematical proof (~30 s)")
	fmt.Println("    - Together they satisfy SOC 2 / HIPAA / GDPR audits")
	fmt.Println("    - The Digital Seal anchors both proofs on-chain")
	fmt.Println(strings.Repeat("=", 60))
}
