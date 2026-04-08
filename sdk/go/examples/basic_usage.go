// Basic usage of the Aethelred Go SDK.
//
// Demonstrates client creation, health check, node info, and listing
// jobs and seals from the testnet.
//
// Build: go build -o basic_usage ./examples/basic_usage.go
// Run:   AETHELRED_API_KEY=<key> ./basic_usage
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aethelred/sdk-go/client"
)

func main() {
	ctx := context.Background()

	// Create a testnet client with an API key from the environment.
	apiKey := os.Getenv("AETHELRED_API_KEY")
	c, err := client.NewClient(
		client.Testnet,
		client.WithAPIKey(apiKey),
		client.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("RPC URL: ", c.RPCURL())
	fmt.Println("Chain ID:", c.ChainID())

	// Health check -- returns true when the node responds.
	healthy := c.HealthCheck(ctx)
	fmt.Printf("Node healthy: %v\n", healthy)

	// Get node info
	info, err := c.GetNodeInfo(ctx)
	if err != nil {
		log.Fatalf("Failed to get node info: %v", err)
	}
	fmt.Printf("Network:  %s\n", info.Network)
	fmt.Printf("Version:  %s\n", info.Version)
	fmt.Printf("Moniker:  %s\n", info.Moniker)

	// List compute jobs
	fmt.Println("\n--- Compute Jobs ---")
	jobs, err := c.Jobs.List(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to list jobs: %v", err)
	}
	fmt.Printf("Found %d job(s)\n", len(jobs))
	for _, j := range jobs {
		fmt.Printf("  Job %s | Status: %s | Proof: %s\n",
			j.ID, j.Status, j.ProofType)
	}

	// List digital seals
	fmt.Println("\n--- Digital Seals ---")
	seals, err := c.Seals.List(ctx, nil)
	if err != nil {
		log.Fatalf("Failed to list seals: %v", err)
	}
	fmt.Printf("Found %d seal(s)\n", len(seals))
	for _, s := range seals {
		fmt.Printf("  Seal %s | Status: %s | Job: %s\n",
			s.ID, s.Status, s.JobID)
	}
}
