// Submit a compute job to the Aethelred network (Go SDK).
//
// Demonstrates job submission, polling for completion, and seal retrieval.
//
// Build: go build -o submit_job ./examples/submit_job.go
// Run:   AETHELRED_API_KEY=<key> ./submit_job
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aethelred/sdk-go/client"
	"github.com/aethelred/sdk-go/jobs"
)

func main() {
	ctx := context.Background()

	// Create a testnet client.
	apiKey := os.Getenv("AETHELRED_API_KEY")
	c, err := client.NewClient(
		client.Testnet,
		client.WithAPIKey(apiKey),
		client.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("Connected to:", c.RPCURL())

	// Verify the node is reachable.
	if !c.HealthCheck(ctx) {
		log.Fatal("Node is not healthy")
	}
	fmt.Println("Node healthy: true")

	// Step 1: Submit a compute job.
	//
	// proof_type is left empty -- the SDK defaults to HYBRID
	// (TEE attestation + zkML proof) for maximum assurance.
	fmt.Println("\nSubmitting compute job...")
	resp, err := c.Jobs.Submit(ctx, jobs.SubmitRequest{
		ModelHash:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		InputHash:     "sha256:7d793037a0760186574b0282f2f435e7cee9c11619c6e091b3bc44b34c3e8c14",
		Priority:      5,
		TimeoutBlocks: 100,
	})
	if err != nil {
		log.Fatalf("Failed to submit job: %v", err)
	}
	fmt.Printf("Job ID:           %s\n", resp.JobID)
	fmt.Printf("Tx hash:          %s\n", resp.TxHash)
	fmt.Printf("Estimated blocks: %d\n", resp.EstimatedBlocks)

	// Step 2: Poll until the job completes or times out.
	fmt.Println("\nPolling for completion (timeout 120 s)...")
	job, err := c.Jobs.WaitForCompletion(ctx, resp.JobID, 2*time.Second, 120*time.Second)
	if err != nil {
		log.Fatalf("Job did not complete: %v", err)
	}
	fmt.Printf("Job status: %s\n", job.Status)

	// Step 3: Retrieve the Digital Seal anchored on-chain.
	sealID, ok := job.Metadata["seal_id"]
	if !ok {
		fmt.Println("No seal_id in job metadata (job may still be finalizing)")
		return
	}

	fmt.Printf("\nFetching seal %s...\n", sealID)
	seal, err := c.Seals.Get(ctx, sealID)
	if err != nil {
		log.Fatalf("Failed to get seal: %v", err)
	}
	fmt.Printf("Seal ID:     %s\n", seal.ID)
	fmt.Printf("Status:      %s\n", seal.Status)
	fmt.Printf("Validators:  %d\n", len(seal.Validators))

	if seal.TEEAttestation != nil {
		fmt.Printf("TEE platform: %s\n", seal.TEEAttestation.Platform)
	}
	if seal.ZKMLProof != nil {
		fmt.Printf("zkML proof system: %s\n", seal.ZKMLProof.ProofSystem)
	}
}
