// Package cli provides cobra-based CLI commands for the Digital Seal SDK.
// These commands expose seal creation, verification, inspection, export,
// listing, revocation, and batch operations from the command line.
package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aethelred/aethelred/pkg/seal/sdk"
	"github.com/aethelred/aethelred/x/seal/types"
)

// NewSealCmd returns the root "seal" command with all subcommands registered.
func NewSealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Digital Seal operations for verified AI computation provenance",
		Long: `Manage Digital Seals on the Aethelred blockchain.

Digital Seals are cryptographically verifiable records that attest to the
integrity and provenance of AI computations. They combine TEE attestations,
zero-knowledge proofs, and regulatory metadata into an immutable on-chain record.`,
	}

	cmd.AddCommand(
		newCreateCmd(),
		newVerifyCmd(),
		newInspectCmd(),
		newExportCmd(),
		newListCmd(),
		newRevokeCmd(),
		newBatchCmd(),
	)

	return cmd
}

// --- seal create ---

func newCreateCmd() *cobra.Command {
	var (
		modelHash  string
		inputHash  string
		outputHash string
		purpose    string
		frameworks string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new Digital Seal",
		Long: `Create a new Digital Seal from model, input, and output hashes.

Hashes must be provided as 64-character hex strings (SHA-256).
Use 'seal create --model-hash <hex> --input-hash <hex> --output-hash <hex> --purpose <purpose>'`,
		Example: `  seal create \
    --model-hash a1b2c3...64chars \
    --input-hash d4e5f6...64chars \
    --output-hash 789abc...64chars \
    --purpose credit_scoring \
    --frameworks "GDPR,SOC2"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			modelBytes, err := parseHash("model-hash", modelHash)
			if err != nil {
				return err
			}
			inputBytes, err := parseHash("input-hash", inputHash)
			if err != nil {
				return err
			}
			outputBytes, err := parseHash("output-hash", outputHash)
			if err != nil {
				return err
			}
			if purpose == "" {
				return fmt.Errorf("--purpose is required")
			}

			req := sdk.SealRequest{
				ModelHash:  modelBytes,
				InputHash:  inputBytes,
				OutputHash: outputBytes,
				Purpose:    purpose,
			}

			if frameworks != "" {
				req.RegulatoryInfo = &sdk.RegulatoryConfig{
					ComplianceFrameworks: strings.Split(frameworks, ","),
				}
			}

			// In a full integration, the SDK would be initialized with a keeper
			// connected to a running node. For CLI purposes, we print the request.
			out := map[string]interface{}{
				"action":           "create_seal",
				"model_commitment": modelHash,
				"input_commitment": inputHash,
				"output_commitment": outputHash,
				"purpose":          purpose,
				"status":           "request_prepared",
			}
			if frameworks != "" {
				out["compliance_frameworks"] = strings.Split(frameworks, ",")
			}

			return writeOutput(out, outputFile)
		},
	}

	cmd.Flags().StringVar(&modelHash, "model-hash", "", "SHA-256 hash of the model (64 hex chars)")
	cmd.Flags().StringVar(&inputHash, "input-hash", "", "SHA-256 hash of the input (64 hex chars)")
	cmd.Flags().StringVar(&outputHash, "output-hash", "", "SHA-256 hash of the output (64 hex chars)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "Use case (e.g., credit_scoring, fraud_detection)")
	cmd.Flags().StringVar(&frameworks, "frameworks", "", "Comma-separated compliance frameworks (e.g., GDPR,SOC2)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write result to file instead of stdout")

	_ = cmd.MarkFlagRequired("model-hash")
	_ = cmd.MarkFlagRequired("input-hash")
	_ = cmd.MarkFlagRequired("output-hash")
	_ = cmd.MarkFlagRequired("purpose")

	return cmd
}

// --- seal verify ---

func newVerifyCmd() *cobra.Command {
	var sealID string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a Digital Seal by ID",
		Long:  `Verify the integrity and attestation chain of a Digital Seal.`,
		Example: `  seal verify --id <seal-id>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sealID == "" {
				return fmt.Errorf("--id is required")
			}

			out := map[string]interface{}{
				"action":  "verify_seal",
				"seal_id": sealID,
				"status":  "verification_requested",
			}
			return writeJSON(out)
		},
	}

	cmd.Flags().StringVar(&sealID, "id", "", "Seal ID to verify")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// --- seal inspect ---

func newInspectCmd() *cobra.Command {
	var (
		sealID    string
		fromFile  string
		format    string
	)

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show detailed seal information",
		Long:  `Inspect a Digital Seal to display its full contents, attestations, proof, and regulatory info.`,
		Example: `  seal inspect --id <seal-id>
  seal inspect --file exported-seal.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sealID == "" && fromFile == "" {
				return fmt.Errorf("either --id or --file is required")
			}

			if fromFile != "" {
				return inspectFromFile(fromFile, format)
			}

			out := map[string]interface{}{
				"action":  "inspect_seal",
				"seal_id": sealID,
				"status":  "inspection_requested",
			}
			return writeJSON(out)
		},
	}

	cmd.Flags().StringVar(&sealID, "id", "", "Seal ID to inspect")
	cmd.Flags().StringVar(&fromFile, "file", "", "Inspect seal from exported file")
	cmd.Flags().StringVar(&format, "format", "json", "Input format: json, cbor, protobuf")

	return cmd
}

// --- seal export ---

func newExportCmd() *cobra.Command {
	var (
		sealID     string
		format     string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a seal in various formats",
		Long: `Export a Digital Seal to JSON, CBOR, or Protobuf format.

Exported seals include all attestations, proofs, regulatory metadata,
and evidence references.`,
		Example: `  seal export --id <seal-id> --format json -o seal.json
  seal export --id <seal-id> --format protobuf -o seal.pb`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sealID == "" {
				return fmt.Errorf("--id is required")
			}

			validFormats := map[string]bool{"json": true, "cbor": true, "protobuf": true}
			if !validFormats[format] {
				return fmt.Errorf("unsupported format: %s (use json, cbor, or protobuf)", format)
			}

			out := map[string]interface{}{
				"action":  "export_seal",
				"seal_id": sealID,
				"format":  format,
				"status":  "export_requested",
			}
			if outputFile != "" {
				out["output_file"] = outputFile
			}
			return writeOutput(out, outputFile)
		},
	}

	cmd.Flags().StringVar(&sealID, "id", "", "Seal ID to export")
	cmd.Flags().StringVar(&format, "format", "json", "Export format: json, cbor, protobuf")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

// --- seal list ---

func newListCmd() *cobra.Command {
	var (
		requester    string
		modelHash    string
		status       string
		framework    string
		jurisdiction string
		limit        int
		offset       int
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List seals with filters",
		Long: `List Digital Seals with optional filtering by requester, model hash,
status, compliance framework, or jurisdiction.`,
		Example: `  seal list --requester aethel1abc... --status ACTIVE --limit 50
  seal list --model-hash a1b2c3... --framework GDPR`,
		RunE: func(cmd *cobra.Command, args []string) error {
			filter := map[string]interface{}{
				"action": "list_seals",
				"limit":  limit,
				"offset": offset,
			}
			if requester != "" {
				filter["requester"] = requester
			}
			if modelHash != "" {
				filter["model_hash"] = modelHash
			}
			if status != "" {
				filter["status"] = status
			}
			if framework != "" {
				filter["framework"] = framework
			}
			if jurisdiction != "" {
				filter["jurisdiction"] = jurisdiction
			}

			return writeOutput(filter, outputFile)
		},
	}

	cmd.Flags().StringVar(&requester, "requester", "", "Filter by requester address")
	cmd.Flags().StringVar(&modelHash, "model-hash", "", "Filter by model hash")
	cmd.Flags().StringVar(&status, "status", "", "Filter by status (PENDING, ACTIVE, REVOKED, EXPIRED)")
	cmd.Flags().StringVar(&framework, "framework", "", "Filter by compliance framework")
	cmd.Flags().StringVar(&jurisdiction, "jurisdiction", "", "Filter by jurisdiction")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum results to return")
	cmd.Flags().IntVar(&offset, "offset", 0, "Pagination offset")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	return cmd
}

// --- seal revoke ---

func newRevokeCmd() *cobra.Command {
	var (
		sealID string
		reason string
	)

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a Digital Seal",
		Long:  `Revoke a seal with a mandatory reason, creating an audit trail entry.`,
		Example: `  seal revoke --id <seal-id> --reason "Model vulnerability discovered"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sealID == "" {
				return fmt.Errorf("--id is required")
			}
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}

			out := map[string]interface{}{
				"action":  "revoke_seal",
				"seal_id": sealID,
				"reason":  reason,
				"status":  "revocation_requested",
			}
			return writeJSON(out)
		},
	}

	cmd.Flags().StringVar(&sealID, "id", "", "Seal ID to revoke")
	cmd.Flags().StringVar(&reason, "reason", "", "Reason for revocation")

	_ = cmd.MarkFlagRequired("id")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}

// --- seal batch ---

func newBatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Batch seal operations",
		Long:  `Perform batch seal creation or verification from a JSON file.`,
	}

	cmd.AddCommand(newBatchCreateCmd())
	cmd.AddCommand(newBatchVerifyCmd())

	return cmd
}

func newBatchCreateCmd() *cobra.Command {
	var (
		inputFile   string
		concurrency int
		outputFile  string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Batch create seals from a JSON file",
		Example: `  seal batch create --file requests.json --concurrency 5 -o results.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--file is required")
			}

			data, err := os.ReadFile(inputFile)
			if err != nil {
				return fmt.Errorf("failed to read input file: %w", err)
			}

			var requests []map[string]interface{}
			if err := json.Unmarshal(data, &requests); err != nil {
				return fmt.Errorf("failed to parse input file: %w", err)
			}

			out := map[string]interface{}{
				"action":      "batch_create",
				"count":       len(requests),
				"concurrency": concurrency,
				"status":      "batch_prepared",
			}
			return writeOutput(out, outputFile)
		},
	}

	cmd.Flags().StringVar(&inputFile, "file", "", "JSON file with seal requests")
	cmd.Flags().IntVar(&concurrency, "concurrency", sdk.DefaultBatchConcurrency, "Number of parallel workers")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	_ = cmd.MarkFlagRequired("file")

	return cmd
}

func newBatchVerifyCmd() *cobra.Command {
	var (
		sealIDs     string
		concurrency int
		outputFile  string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Batch verify seals by IDs",
		Example: `  seal batch verify --ids "id1,id2,id3" --concurrency 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if sealIDs == "" {
				return fmt.Errorf("--ids is required")
			}

			ids := strings.Split(sealIDs, ",")
			out := map[string]interface{}{
				"action":      "batch_verify",
				"count":       len(ids),
				"concurrency": concurrency,
				"status":      "batch_prepared",
			}
			return writeOutput(out, outputFile)
		},
	}

	cmd.Flags().StringVar(&sealIDs, "ids", "", "Comma-separated seal IDs to verify")
	cmd.Flags().IntVar(&concurrency, "concurrency", sdk.DefaultBatchConcurrency, "Number of parallel workers")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	_ = cmd.MarkFlagRequired("ids")

	return cmd
}

// --- helpers ---

func parseHash(name, hexStr string) ([]byte, error) {
	if len(hexStr) != 64 {
		return nil, fmt.Errorf("--%s must be a 64-character hex string (SHA-256), got %d chars", name, len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("--%s contains invalid hex: %w", name, err)
	}
	return b, nil
}

func writeJSON(v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func writeOutput(v interface{}, filePath string) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if filePath != "" {
		return os.WriteFile(filePath, data, 0644)
	}
	fmt.Println(string(data))
	return nil
}

func inspectFromFile(filePath, format string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var seal *types.DigitalSeal
	switch format {
	case "json":
		seal, err = sdk.ImportJSON(data)
	case "cbor":
		seal, err = sdk.ImportCBOR(data)
	case "protobuf":
		seal, err = sdk.ImportProtobuf(data)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
	if err != nil {
		return fmt.Errorf("failed to import seal: %w", err)
	}

	info := map[string]interface{}{
		"seal_id":           seal.GetId(),
		"status":            seal.GetStatus().String(),
		"model_commitment":  hex.EncodeToString(seal.GetModelCommitment()),
		"input_commitment":  hex.EncodeToString(seal.GetInputCommitment()),
		"output_commitment": hex.EncodeToString(seal.GetOutputCommitment()),
		"block_height":      seal.GetBlockHeight(),
		"requested_by":      seal.GetRequestedBy(),
		"purpose":           seal.GetPurpose(),
		"validator_count":   len(seal.GetValidatorSet()),
		"attestation_count": len(seal.GetTeeAttestations()),
		"has_proof":         seal.GetZkProof() != nil,
		"verification_type": seal.GetVerificationType(),
	}

	if seal.GetTimestamp() != nil {
		info["timestamp"] = seal.GetTimestamp().AsTime().Format(time.RFC3339)
	}
	if seal.GetRegulatoryInfo() != nil {
		info["regulatory_info"] = map[string]interface{}{
			"data_classification":       seal.GetRegulatoryInfo().GetDataClassification(),
			"compliance_frameworks":     seal.GetRegulatoryInfo().GetComplianceFrameworks(),
			"jurisdiction_restrictions": seal.GetRegulatoryInfo().GetJurisdictionRestrictions(),
			"audit_required":            seal.GetRegulatoryInfo().GetAuditRequired(),
		}
	}

	return writeJSON(info)
}

// NewSealCmdWithSDK creates a seal command wired to a live SDK instance.
// This is used when embedding the CLI in a running application.
func NewSealCmdWithSDK(sdkInstance *sdk.SealSDK) *cobra.Command {
	cmd := NewSealCmd()

	// Override the create command with a live implementation
	for _, sub := range cmd.Commands() {
		if sub.Use == "create" {
			wrapCreateWithSDK(sub, sdkInstance)
		}
		if sub.Use == "verify" {
			wrapVerifyWithSDK(sub, sdkInstance)
		}
	}

	return cmd
}

func wrapCreateWithSDK(cmd *cobra.Command, sdkInstance *sdk.SealSDK) {
	original := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if sdkInstance == nil {
			return original(cmd, args)
		}

		modelHash, _ := cmd.Flags().GetString("model-hash")
		inputHash, _ := cmd.Flags().GetString("input-hash")
		outputHash, _ := cmd.Flags().GetString("output-hash")
		purpose, _ := cmd.Flags().GetString("purpose")

		modelBytes, err := parseHash("model-hash", modelHash)
		if err != nil {
			return err
		}
		inputBytes, err := parseHash("input-hash", inputHash)
		if err != nil {
			return err
		}
		outputBytes, err := parseHash("output-hash", outputHash)
		if err != nil {
			return err
		}

		ctx := context.Background()
		resp, err := sdkInstance.CreateSeal(ctx, sdk.SealRequest{
			ModelHash:  modelBytes,
			InputHash:  inputBytes,
			OutputHash: outputBytes,
			Purpose:    purpose,
		})
		if err != nil {
			return fmt.Errorf("failed to create seal: %w", err)
		}

		return writeJSON(map[string]interface{}{
			"seal_id":     resp.SealID,
			"status":      resp.Status.String(),
			"block_height": resp.BlockHeight,
			"timestamp":   resp.Timestamp.Format(time.RFC3339),
		})
	}
}

func wrapVerifyWithSDK(cmd *cobra.Command, sdkInstance *sdk.SealSDK) {
	original := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if sdkInstance == nil {
			return original(cmd, args)
		}

		sealID, _ := cmd.Flags().GetString("id")
		ctx := context.Background()

		resp, err := sdkInstance.VerifySeal(ctx, sealID)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}

		return writeJSON(map[string]interface{}{
			"seal_id":          resp.SealID,
			"status":           resp.Status.String(),
			"attestation_count": len(resp.Attestations),
			"has_proof":        resp.Proof != nil,
			"verified":         resp.Status == types.SealStatusActive,
		})
	}
}
