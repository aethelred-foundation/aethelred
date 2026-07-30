package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	aethelredapp "github.com/aethelred/aethelred/app"
	"github.com/spf13/cobra"
)

const maxConsensusEvidenceRequestSize int64 = 16 << 20

func auditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run deterministic audit checks",
	}
	cmd.AddCommand(auditConsensusEvidenceCommand())
	return cmd
}

func auditConsensusEvidenceCommand() *cobra.Command {
	var (
		requestFile string
		pretty      bool
	)

	cmd := &cobra.Command{
		Use:   "consensus-evidence",
		Short: "Audit injected consensus evidence against commit vote totals",
		Long: `Run the same injected consensus evidence checks used by ProcessProposal.

The request file must be JSON with:
- consensus_threshold (optional; clamped to minimum 67)
- proposed_last_commit (abci.CommitInfo JSON)
- txs (array of tx payloads; each entry can be JSON object, hex string, or base64 string)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if requestFile == "" {
				return fmt.Errorf("--request-file is required")
			}

			payload, err := readConsensusEvidenceRequest(requestFile)
			if err != nil {
				return fmt.Errorf("read request file: %w", err)
			}

			var req aethelredapp.ConsensusEvidenceAuditRequest
			if err := json.Unmarshal(payload, &req); err != nil {
				return fmt.Errorf("parse request JSON: %w", err)
			}

			resp, err := aethelredapp.RunConsensusEvidenceAudit(req)
			if err != nil {
				return err
			}

			var out []byte
			if pretty {
				out, err = json.MarshalIndent(resp, "", "  ")
			} else {
				out, err = json.Marshal(resp)
			}
			if err != nil {
				return fmt.Errorf("marshal response: %w", err)
			}

			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}

	cmd.Flags().StringVar(&requestFile, "request-file", "", "Path to JSON request payload")
	cmd.Flags().BoolVar(&pretty, "pretty", true, "Pretty-print JSON output")
	return cmd
}

func readConsensusEvidenceRequest(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("request path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve request path: %w", err)
	}

	// #nosec G304 -- --request-file is an explicit local operator input,
	// canonicalized and verified as a bounded regular file after opening.
	file, err := os.Open(absolutePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("request path must be a regular file")
	}
	if info.Size() > maxConsensusEvidenceRequestSize {
		return nil, fmt.Errorf("request file exceeds %d bytes", maxConsensusEvidenceRequestSize)
	}

	payload, err := io.ReadAll(io.LimitReader(file, maxConsensusEvidenceRequestSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxConsensusEvidenceRequestSize {
		return nil, fmt.Errorf("request file exceeds %d bytes", maxConsensusEvidenceRequestSize)
	}
	return payload, nil
}
