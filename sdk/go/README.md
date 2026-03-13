<h1 align="center">aethelred-sdk-go</h1>

<p align="center">
  <strong>Official Go SDK for the Aethelred blockchain</strong>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/aethelred/aethelred-sdk-go"><img src="https://pkg.go.dev/badge/github.com/aethelred/aethelred-sdk-go.svg" alt="Go Reference"></a>
  <a href="https://github.com/AethelredFoundation/aethelred-sdk-go/actions"><img src="https://img.shields.io/github/actions/workflow/status/AethelredFoundation/aethelred-sdk-go/go-sdk-ci.yml?style=flat-square&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go version">
</p>

---

## Install

```bash
go get github.com/aethelred/aethelred-sdk-go
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    aethelred "github.com/aethelred/aethelred-sdk-go"
)

func main() {
    ctx := context.Background()

    // Connect to testnet
    client, err := aethelred.NewClient("https://rpc.testnet.aethelred.io")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Load wallet from mnemonic
    wallet, err := aethelred.WalletFromMnemonic("your twelve word mnemonic...")
    if err != nil {
        log.Fatal(err)
    }

    // Submit a compute job
    job, err := client.PoUW().SubmitJob(ctx, &aethelred.SubmitJobRequest{
        ModelHash:        []byte("abc123..."),
        InputData:        []byte(`{"prompt":"Hello AI"}`),
        VerificationType: "hybrid",
        Priority:         "standard",
        Signer:           wallet,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Job submitted: %s\n", job.JobID)

    // Query the resulting seal
    seal, err := client.Seal().GetSealByJob(ctx, job.JobID)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Output hash: %x\n", seal.OutputHash)
    fmt.Printf("Agreement: %d/%d\n", seal.AgreementPower, seal.TotalPower)
}
```

Full API docs: [pkg.go.dev/github.com/aethelred/aethelred-sdk-go](https://pkg.go.dev/github.com/aethelred/aethelred-sdk-go)

---

## Development

```bash
go test ./...
go vet ./...
golangci-lint run
```
