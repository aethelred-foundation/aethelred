package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	audithttp "github.com/aethelred/aethelred/pkg/audit"
	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	schedulerMetaAssignedTo   = "scheduler.assigned_to"
	schedulerMetaBeaconSource = "scheduler.beacon_source"
	dkgBeaconSource           = "dkg-threshold-beacon"
	flagAPIURL                = "api-url"
	flagActor                 = "actor"
	flagKeyword               = "keyword"
	flagLimit                 = "limit"
	flagOffset                = "offset"
	flagFormat                = "format"
	flagPackage               = "package"
	flagSigner                = "signer"
	flagSigned                = "signed"
	flagPackageHash           = "package-hash"
	flagLedgerID              = "ledger-id"
	flagFile                  = "file"
	defaultAPIURL             = "http://127.0.0.1:1317"
	envAPIURL                 = "AETHELRED_API_URL"
)

// CmdQueryValidatorPCR0 creates a CLI query command for validator PCR0 mappings.
func CmdQueryValidatorPCR0() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validator-pcr0 [validator-address]",
		Short: "Query a validator's registered AWS Nitro PCR0 hash",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.ValidatorPCR0(cmd.Context(), &types.QueryValidatorPCR0Request{
				ValidatorAddress: args[0],
			})
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

type validatorPoUWStatusReport struct {
	InputAddress         string   `json:"input_address"`
	ValidatorAddress     string   `json:"validator_address"`
	OperatorAddress      string   `json:"operator_address"`
	Bonded               bool     `json:"bonded"`
	BondedStake          string   `json:"bonded_stake"`
	MinimumStake         string   `json:"minimum_stake"`
	StakeRequirementMet  bool     `json:"stake_requirement_met"`
	PCR0Registered       bool     `json:"pcr0_registered"`
	PCR0Hex              string   `json:"pcr0_hex,omitempty"`
	ValidatorStatsFound  bool     `json:"validator_stats_found"`
	TotalJobsProcessed   int64    `json:"total_jobs_processed,omitempty"`
	SuccessfulJobs       int64    `json:"successful_jobs,omitempty"`
	FailedJobs           int64    `json:"failed_jobs,omitempty"`
	PendingAssignments   int      `json:"pending_assignments"`
	DKGBackedAssignments int      `json:"dkg_backed_assignments"`
	DKGState             string   `json:"dkg_state"`
	ReadyForPoUW         bool     `json:"ready_for_pouw"`
	Notes                []string `json:"notes,omitempty"`
}

// CmdQueryPoUWStatus creates a CLI query command for validator PoUW onboarding status.
func CmdQueryPoUWStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Query validator onboarding status for PoUW readiness and DKG eligibility",
		Long: "Returns a single status report that combines staking, PCR0 attestation,\n" +
			"validator stats, and DKG-backed assignment signals for the requested validator.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			inputAddr, err := cmd.Flags().GetString(flagValidator)
			if err != nil {
				return err
			}
			inputAddr = strings.TrimSpace(inputAddr)
			if inputAddr == "" {
				if clientCtx.FromAddress.Empty() {
					return fmt.Errorf("set --%s or provide --from to resolve validator address", flagValidator)
				}
				inputAddr = clientCtx.FromAddress.String()
			}

			validatorAddr, operatorAddr, err := resolveValidatorAddresses(inputAddr)
			if err != nil {
				return err
			}

			report := validatorPoUWStatusReport{
				InputAddress:     inputAddr,
				ValidatorAddress: validatorAddr,
				OperatorAddress:  operatorAddr,
				BondedStake:      "0" + stakeBaseDenom,
				MinimumStake:     minimumStakeUAETHEL().String() + stakeBaseDenom,
				Notes:            []string{},
			}

			minimumStake := minimumStakeUAETHEL()
			pouwQuery := types.NewQueryClient(clientCtx)
			stakingQuery := stakingtypes.NewQueryClient(clientCtx)

			if stakingRes, stakingErr := stakingQuery.Validator(cmd.Context(), &stakingtypes.QueryValidatorRequest{
				ValidatorAddr: operatorAddr,
			}); stakingErr == nil && stakingRes != nil {
				report.Bonded = stakingRes.Validator.Status == stakingtypes.Bonded
				report.BondedStake = stakingRes.Validator.Tokens.String() + stakeBaseDenom
				report.StakeRequirementMet = report.Bonded && stakingRes.Validator.Tokens.GTE(minimumStake)
			} else {
				report.Notes = append(report.Notes, "validator operator not found in staking set")
			}

			if pcr0Res, pcr0Err := pouwQuery.ValidatorPCR0(cmd.Context(), &types.QueryValidatorPCR0Request{
				ValidatorAddress: validatorAddr,
			}); pcr0Err == nil && pcr0Res != nil && pcr0Res.Pcr0Hex != "" {
				report.PCR0Registered = true
				report.PCR0Hex = pcr0Res.Pcr0Hex
			} else {
				report.Notes = append(report.Notes, "validator PCR0 is not registered")
			}

			if statsRes, statsErr := pouwQuery.ValidatorStats(cmd.Context(), &types.QueryValidatorStatsRequest{
				ValidatorAddress: validatorAddr,
			}); statsErr == nil && statsRes != nil && statsRes.Stats != nil {
				report.ValidatorStatsFound = true
				report.TotalJobsProcessed = statsRes.Stats.TotalJobsProcessed
				report.SuccessfulJobs = statsRes.Stats.SuccessfulJobs
				report.FailedJobs = statsRes.Stats.FailedJobs
			} else {
				report.Notes = append(report.Notes, "validator stats not found (capability not observed yet)")
			}

			if pendingRes, pendingErr := pouwQuery.PendingJobs(cmd.Context(), &types.QueryPendingJobsRequest{}); pendingErr == nil && pendingRes != nil {
				candidates := map[string]struct{}{
					validatorAddr: {},
					operatorAddr:  {},
				}
				report.PendingAssignments, report.DKGBackedAssignments = assignmentSnapshot(pendingRes.Jobs, candidates)
			}

			switch {
			case !report.StakeRequirementMet || !report.PCR0Registered:
				report.DKGState = "blocked"
			case report.DKGBackedAssignments > 0:
				report.DKGState = "active"
			default:
				report.DKGState = "eligible"
			}

			report.ReadyForPoUW = report.StakeRequirementMet && report.PCR0Registered
			if report.ReadyForPoUW && !report.ValidatorStatsFound {
				report.Notes = append(report.Notes, "validator has not produced finalized PoUW jobs yet")
			}
			if !report.ReadyForPoUW {
				if !report.StakeRequirementMet {
					report.Notes = append(report.Notes, "stake not bonded or below 100000aethel minimum")
				}
				report.Notes = append(report.Notes, "submit tx pouw register-validator-capability to join assignment pool")
			}

			rendered, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}

			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagValidator, "", "Validator account or valoper address (defaults to --from)")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWModuleStatus creates a CLI command for keeper-backed module
// status, including managed enterprise trust posture.
func CmdQueryPoUWModuleStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "module-status",
		Aliases: []string{"operator-status"},
		Short:   "Query PoUW module status and managed trust-registry posture",
		Long: "Queries the app's public PoUW operator endpoint to return keeper-backed\n" +
			"module status, including epoch counters and enterprise trust-registry posture.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			status, err := fetchPouwModuleStatus(cmd.Context(), &http.Client{Timeout: 10 * time.Second}, apiBaseURL)
			if err != nil {
				return err
			}

			rendered, err := json.MarshalIndent(status, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWTrustRegistry creates a CLI command for normalized enterprise
// trust-registry inspection.
func CmdQueryPoUWTrustRegistry() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust-registry",
		Short: "Query the PoUW enterprise trust registry",
		Long: "Queries the app's public PoUW trust-registry endpoint to return the\n" +
			"normalized enterprise trust registry and its derived status summary.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			registry, err := fetchPouwTrustRegistry(cmd.Context(), &http.Client{Timeout: 10 * time.Second}, apiBaseURL)
			if err != nil {
				return err
			}

			rendered, err := json.MarshalIndent(registry, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWTrustRegistryHistory creates a CLI command for trust-registry
// governance history inspection.
func CmdQueryPoUWTrustRegistryHistory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "trust-registry-history",
		Aliases: []string{"trust-history"},
		Short:   "Query PoUW trust-registry governance history",
		Long: "Queries the app's public PoUW trust-registry history endpoint to return\n" +
			"governance audit records for trust-registry updates and clears.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			params, err := buildPouwTrustRegistryHistoryQueryParams(cmd)
			if err != nil {
				return err
			}

			history, err := fetchPouwTrustRegistryHistory(cmd.Context(), &http.Client{Timeout: 10 * time.Second}, apiBaseURL, params)
			if err != nil {
				return err
			}

			rendered, err := json.MarshalIndent(history, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	cmd.Flags().String(flagActor, "", "Filter trust-registry history by governance actor")
	cmd.Flags().StringArray(flagKeyword, nil, "Filter trust-registry history by keyword (repeatable)")
	cmd.Flags().Int(flagLimit, 0, "Limit the number of trust-registry history records returned")
	cmd.Flags().Int(flagOffset, 0, "Skip the first N trust-registry history records")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWTrustComplianceExport creates a CLI command for auditor-friendly
// trust compliance exports across current state and governance history.
func CmdQueryPoUWTrustComplianceExport() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust-compliance-export",
		Short: "Export PoUW trust compliance state and history",
		Long: "Queries the app's public PoUW trust compliance export endpoint to return\n" +
			"current module status, trust-registry posture, governance mutation history,\n" +
			"and regulatory control coverage in JSON, CSV, or OSCAL form.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			params, err := buildPouwTrustComplianceQueryParams(cmd)
			if err != nil {
				return err
			}

			payload, err := fetchPouwTrustComplianceExport(cmd.Context(), &http.Client{Timeout: 15 * time.Second}, apiBaseURL, params)
			if err != nil {
				return err
			}

			text := string(payload)
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			return clientCtx.PrintString(text)
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	cmd.Flags().String(flagFormat, "json", "Compliance export format: json, csv, or oscal")
	cmd.Flags().Bool(flagPackage, false, "Wrap the export in a tamper-evident package with hashes and optional runtime signature")
	cmd.Flags().String(flagActor, "", "Filter trust-registry history by governance actor")
	cmd.Flags().StringArray(flagKeyword, nil, "Filter trust-registry history by keyword (repeatable)")
	cmd.Flags().Int(flagLimit, 0, "Limit the number of trust-registry history records returned")
	cmd.Flags().Int(flagOffset, 0, "Skip the first N trust-registry history records")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWTrustComplianceExportAnchors creates a CLI command for normalized
// anchored-export discovery.
func CmdQueryPoUWTrustComplianceExportAnchors() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust-compliance-export-anchors",
		Short: "Query anchored PoUW trust-compliance export packages",
		Long: "Queries the app's public anchored-export endpoint to return normalized\n" +
			"package anchor records, including format, signer, package hash, and custody metadata.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			params, err := buildPouwTrustComplianceAnchorQueryParams(cmd)
			if err != nil {
				return err
			}

			resp, err := fetchPouwTrustComplianceExportAnchors(cmd.Context(), &http.Client{Timeout: 15 * time.Second}, apiBaseURL, params)
			if err != nil {
				return err
			}

			rendered, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	cmd.Flags().String(flagFormat, "", "Anchor filter by export format: json, csv, or oscal")
	cmd.Flags().String(flagSigner, "", "Anchor filter by package signer")
	cmd.Flags().String(flagSigned, "", "Anchor filter by signed status: true or false")
	cmd.Flags().String(flagPackageHash, "", "Anchor filter by exact package hash")
	cmd.Flags().String(flagActor, "", "Filter anchored export history by governance actor")
	cmd.Flags().StringArray(flagKeyword, nil, "Filter anchored export history by keyword (repeatable)")
	cmd.Flags().Int(flagLimit, 0, "Limit the number of anchored export records returned")
	cmd.Flags().Int(flagOffset, 0, "Skip the first N anchored export records")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdVerifyPouwTrustCompliancePackage verifies a packaged trust-compliance
// export either locally or against a running node for anchor correlation.
func CmdVerifyPouwTrustCompliancePackage() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-trust-compliance-package",
		Short: "Verify a packaged PoUW trust-compliance export",
		Long: "Verifies a packaged trust-compliance export from a file or stdin.\n" +
			"When --api-url is provided, the package is also checked against the\n" +
			"running node's anchored export history.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			inputPath, err := cmd.Flags().GetString(flagFile)
			if err != nil {
				return err
			}
			payload, err := readPouwTrustCompliancePackageInput(inputPath)
			if err != nil {
				return err
			}

			var resp auditexport.PouwTrustCompliancePackageVerificationResponse
			if apiURL, err := cmd.Flags().GetString(flagAPIURL); err != nil {
				return err
			} else if strings.TrimSpace(apiURL) != "" {
				apiBaseURL, err := normalizeAPIBaseURL(apiURL)
				if err != nil {
					return err
				}
				resp, err = verifyPouwTrustCompliancePackageRemote(cmd.Context(), &http.Client{Timeout: 15 * time.Second}, apiBaseURL, payload)
				if err != nil {
					return err
				}
			} else {
				var pkg auditexport.PouwTrustCompliancePackage
				if err := json.Unmarshal(payload, &pkg); err != nil {
					return fmt.Errorf("decode pouw trust compliance package: %w", err)
				}
				resp = auditexport.PouwTrustCompliancePackageVerificationResponse{
					Verification: auditexport.VerifyPouwTrustCompliancePackageDetailed(&pkg),
				}
			}

			rendered, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagFile, "-", "Path to a trust-compliance package JSON file, or - for stdin")
	cmd.Flags().String(flagAPIURL, "", "Optional HTTP API base URL for remote verification and anchor correlation")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdQueryPoUWControlLedgerPackageAnchors creates a CLI command for normalized
// portable control-ledger package anchor discovery.
func CmdQueryPoUWControlLedgerPackageAnchors() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control-ledger-package-anchors",
		Short: "Query anchored portable control-ledger packages",
		Long: "Queries the app's public anchored portable control-ledger package\n" +
			"endpoint to return normalized package anchor records, including ledger,\n" +
			"signer, signed status, and package hash metadata.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			apiBaseURL, err := resolvePouwAPIBaseURL(clientCtx, cmd)
			if err != nil {
				return err
			}

			params, err := buildPouwControlLedgerPackageAnchorQueryParams(cmd)
			if err != nil {
				return err
			}

			resp, err := fetchPouwControlLedgerPackageAnchors(cmd.Context(), &http.Client{Timeout: 15 * time.Second}, apiBaseURL, params)
			if err != nil {
				return err
			}

			rendered, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagAPIURL, "", "HTTP API base URL for public PoUW operator routes (default: derive from --node or use http://127.0.0.1:1317)")
	cmd.Flags().String(flagLedgerID, "", "Anchor filter by exact control-ledger ID")
	cmd.Flags().String(flagSigner, "", "Anchor filter by package signer")
	cmd.Flags().String(flagSigned, "", "Anchor filter by signed status: true or false")
	cmd.Flags().String(flagPackageHash, "", "Anchor filter by exact package hash")
	cmd.Flags().String(flagActor, "", "Filter anchored package history by governance actor")
	cmd.Flags().StringArray(flagKeyword, nil, "Filter anchored package history by keyword (repeatable)")
	cmd.Flags().Int(flagLimit, 0, "Limit the number of anchored package records returned")
	cmd.Flags().Int(flagOffset, 0, "Skip the first N anchored package records")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

// CmdVerifyPortableControlLedgerPackage verifies a portable control-ledger
// package either locally or against a running node for anchor correlation.
func CmdVerifyPortableControlLedgerPackage() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-control-ledger-package",
		Short: "Verify a portable control-ledger package",
		Long: "Verifies a portable control-ledger package from a file or stdin.\n" +
			"When --api-url is provided, the package is also checked against the\n" +
			"running node's anchored portable package history.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			inputPath, err := cmd.Flags().GetString(flagFile)
			if err != nil {
				return err
			}
			payload, err := readPortableControlLedgerPackageInput(inputPath)
			if err != nil {
				return err
			}

			var resp audithttp.VerifyPortableControlLedgerPackageResponse
			if apiURL, err := cmd.Flags().GetString(flagAPIURL); err != nil {
				return err
			} else if strings.TrimSpace(apiURL) != "" {
				apiBaseURL, err := normalizeAPIBaseURL(apiURL)
				if err != nil {
					return err
				}
				resp, err = verifyPortableControlLedgerPackageRemote(cmd.Context(), &http.Client{Timeout: 15 * time.Second}, apiBaseURL, payload)
				if err != nil {
					return err
				}
			} else {
				var pkg evidence.PortableControlLedgerPackage
				if err := json.Unmarshal(payload, &pkg); err != nil {
					return fmt.Errorf("decode portable control ledger package: %w", err)
				}
				resp = audithttp.VerifyPortableControlLedgerPackageResponse{
					Valid:       false,
					PackageHash: pkg.PackageHash,
				}
				if pkg.Ledger != nil && pkg.Ledger.Bundle != nil {
					resp.LedgerID = pkg.Ledger.Bundle.ID
					resp.Summary = &pkg.Ledger.Summary
				}
				if err := evidence.VerifyPortableControlLedgerPackage(&pkg); err != nil {
					resp.Error = err.Error()
				} else {
					resp.Valid = true
				}
			}

			rendered, err := json.MarshalIndent(resp, "", "  ")
			if err != nil {
				return err
			}
			return clientCtx.PrintString(string(rendered) + "\n")
		},
	}

	cmd.Flags().String(flagFile, "-", "Path to a portable control-ledger package JSON file, or - for stdin")
	cmd.Flags().String(flagAPIURL, "", "Optional HTTP API base URL for remote verification and anchor correlation")
	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func resolveValidatorAddresses(input string) (validatorAddr string, operatorAddr string, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", "", fmt.Errorf("validator address cannot be empty")
	}

	if accAddr, accErr := sdk.AccAddressFromBech32(trimmed); accErr == nil {
		return accAddr.String(), sdk.ValAddress(accAddr).String(), nil
	}

	if valAddr, valErr := sdk.ValAddressFromBech32(trimmed); valErr == nil {
		return sdk.AccAddress(valAddr).String(), valAddr.String(), nil
	}

	return "", "", fmt.Errorf("invalid validator address %q: provide account or valoper bech32", input)
}

func assignmentSnapshot(jobs []*types.ComputeJob, candidates map[string]struct{}) (assigned int, dkgBacked int) {
	for _, job := range jobs {
		if job == nil || len(job.Metadata) == 0 {
			continue
		}

		assignedValidators := parseAssignedValidators(job.Metadata[schedulerMetaAssignedTo])
		if !containsAnyAddress(assignedValidators, candidates) {
			continue
		}

		assigned++
		if strings.EqualFold(job.Metadata[schedulerMetaBeaconSource], dkgBeaconSource) {
			dkgBacked++
		}
	}

	return assigned, dkgBacked
}

func parseAssignedValidators(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	var jsonList []string
	if err := json.Unmarshal([]byte(trimmed), &jsonList); err == nil {
		out := make([]string, 0, len(jsonList))
		for _, item := range jsonList {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	}

	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func containsAnyAddress(assigned []string, candidates map[string]struct{}) bool {
	for _, addr := range assigned {
		if _, ok := candidates[addr]; ok {
			return true
		}
	}
	return false
}

// CmdQueryIsPCR0Registered creates a CLI query command for global PCR0 registry membership.
func CmdQueryIsPCR0Registered() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-pcr0-registered [pcr0-hex]",
		Short: "Query whether a PCR0 hash is globally trusted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}

			queryClient := types.NewQueryClient(clientCtx)
			res, err := queryClient.IsPCR0Registered(cmd.Context(), &types.QueryIsPCR0RegisteredRequest{
				Pcr0Hex: args[0],
			})
			if err != nil {
				return err
			}

			return clientCtx.PrintProto(res)
		},
	}

	flags.AddQueryFlagsToCmd(cmd)

	return cmd
}

func resolvePouwAPIBaseURL(clientCtx client.Context, cmd *cobra.Command) (string, error) {
	if cmd != nil {
		if configured, err := cmd.Flags().GetString(flagAPIURL); err == nil && strings.TrimSpace(configured) != "" {
			return normalizeAPIBaseURL(configured)
		}
	}
	if configured := strings.TrimSpace(os.Getenv(envAPIURL)); configured != "" {
		return normalizeAPIBaseURL(configured)
	}
	if derived := deriveAPIBaseURLFromNodeURI(strings.TrimSpace(clientCtx.NodeURI)); derived != "" {
		return normalizeAPIBaseURL(derived)
	}
	return normalizeAPIBaseURL(defaultAPIURL)
}

func deriveAPIBaseURLFromNodeURI(nodeURI string) string {
	if nodeURI == "" {
		return ""
	}
	parsed, err := url.Parse(nodeURI)
	if err != nil {
		return ""
	}

	host := parsed.Host
	scheme := parsed.Scheme
	if host == "" {
		host = parsed.Path
	}
	if host == "" {
		return ""
	}

	switch scheme {
	case "", "tcp", "ws":
		scheme = "http"
	case "wss":
		scheme = "https"
	case "http", "https":
	default:
		scheme = "http"
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			hostname = host
			port = ""
		} else {
			return ""
		}
	}
	if hostname == "" {
		hostname = host
	}
	switch port {
	case "", "26657", "36657":
		port = "1317"
	}

	return (&url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(hostname, port),
	}).String()
}

func normalizeAPIBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid API URL %q: %w", raw, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid API URL %q: include scheme and host", raw)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func fetchPouwModuleStatus(ctx context.Context, client *http.Client, apiBaseURL string) (*pouwkeeper.QueryModuleStatusResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/module-status"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw module status: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw module status response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw module status: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw module status: unexpected status %d", resp.StatusCode)
	}

	var status pouwkeeper.QueryModuleStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("decode pouw module status response: %w", err)
	}
	return &status, nil
}

type pouwTrustRegistryResponse struct {
	Configured bool                                           `json:"configured"`
	Status     *pouwkeeper.EnterpriseAuditTrustRegistryStatus `json:"status,omitempty"`
	Registry   *pouwkeeper.EnterpriseAuditTrustRegistry       `json:"registry,omitempty"`
}

type pouwTrustRegistryHistoryResponse struct {
	Records []pouwkeeper.AuditRecord `json:"records"`
	Total   int                      `json:"total"`
}

func fetchPouwTrustRegistry(ctx context.Context, client *http.Client, apiBaseURL string) (*pouwTrustRegistryResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/trust-registry"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw trust registry: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw trust registry response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw trust registry: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw trust registry: unexpected status %d", resp.StatusCode)
	}

	var registry pouwTrustRegistryResponse
	if err := json.Unmarshal(body, &registry); err != nil {
		return nil, fmt.Errorf("decode pouw trust registry response: %w", err)
	}
	return &registry, nil
}

func buildPouwTrustRegistryHistoryQueryParams(cmd *cobra.Command) (url.Values, error) {
	values := make(url.Values)
	if cmd == nil {
		return values, nil
	}

	if actor, err := cmd.Flags().GetString(flagActor); err != nil {
		return nil, err
	} else if actor = strings.TrimSpace(actor); actor != "" {
		values.Set("actor", actor)
	}
	if keywords, err := cmd.Flags().GetStringArray(flagKeyword); err != nil {
		return nil, err
	} else {
		for _, keyword := range keywords {
			if keyword = strings.TrimSpace(keyword); keyword != "" {
				values.Add("keyword", keyword)
			}
		}
	}
	if limit, err := cmd.Flags().GetInt(flagLimit); err != nil {
		return nil, err
	} else if limit > 0 {
		values.Set("limit", strconv.Itoa(limit))
	}
	if offset, err := cmd.Flags().GetInt(flagOffset); err != nil {
		return nil, err
	} else if offset > 0 {
		values.Set("offset", strconv.Itoa(offset))
	}
	return values, nil
}

func normalizePouwExportFormat(cmd *cobra.Command) (string, error) {
	if cmd == nil {
		return "json", nil
	}
	format, err := cmd.Flags().GetString(flagFormat)
	if err != nil {
		return "", err
	}
	return auditexport.NormalizePouwTrustComplianceFormat(format)
}

func buildPouwTrustComplianceQueryParams(cmd *cobra.Command) (url.Values, error) {
	values, err := buildPouwTrustRegistryHistoryQueryParams(cmd)
	if err != nil {
		return nil, err
	}
	format, err := normalizePouwExportFormat(cmd)
	if err != nil {
		return nil, err
	}
	values.Set("format", format)
	if cmd == nil {
		return values, nil
	}
	if packageOutput, err := cmd.Flags().GetBool(flagPackage); err != nil {
		return nil, err
	} else if packageOutput {
		values.Set("package", "true")
	}
	return values, nil
}

func buildPouwTrustComplianceAnchorQueryParams(cmd *cobra.Command) (url.Values, error) {
	values, err := buildPouwTrustRegistryHistoryQueryParams(cmd)
	if err != nil {
		return nil, err
	}
	if cmd == nil {
		return values, nil
	}

	if format, err := cmd.Flags().GetString(flagFormat); err != nil {
		return nil, err
	} else if format = strings.TrimSpace(format); format != "" {
		normalizedFormat, err := auditexport.NormalizePouwTrustComplianceFormat(format)
		if err != nil {
			return nil, err
		}
		values.Set("format", normalizedFormat)
	}
	if signer, err := cmd.Flags().GetString(flagSigner); err != nil {
		return nil, err
	} else if signer = strings.TrimSpace(signer); signer != "" {
		values.Set("signer", signer)
	}
	if signed, err := cmd.Flags().GetString(flagSigned); err != nil {
		return nil, err
	} else if signed = strings.TrimSpace(signed); signed != "" {
		switch strings.ToLower(signed) {
		case "1", "true", "yes", "on":
			values.Set("signed", "true")
		case "0", "false", "no", "off":
			values.Set("signed", "false")
		default:
			return nil, fmt.Errorf("invalid signed filter %q: use true or false", signed)
		}
	}
	if packageHash, err := cmd.Flags().GetString(flagPackageHash); err != nil {
		return nil, err
	} else if packageHash = strings.TrimSpace(packageHash); packageHash != "" {
		values.Set("package_hash", packageHash)
	}
	return values, nil
}

func buildPouwControlLedgerPackageAnchorQueryParams(cmd *cobra.Command) (url.Values, error) {
	values, err := buildPouwTrustRegistryHistoryQueryParams(cmd)
	if err != nil {
		return nil, err
	}
	if cmd == nil {
		return values, nil
	}

	if ledgerID, err := cmd.Flags().GetString(flagLedgerID); err != nil {
		return nil, err
	} else if ledgerID = strings.TrimSpace(ledgerID); ledgerID != "" {
		values.Set("ledger_id", ledgerID)
	}
	if signer, err := cmd.Flags().GetString(flagSigner); err != nil {
		return nil, err
	} else if signer = strings.TrimSpace(signer); signer != "" {
		values.Set("signer", signer)
	}
	if signed, err := cmd.Flags().GetString(flagSigned); err != nil {
		return nil, err
	} else if signed = strings.TrimSpace(signed); signed != "" {
		switch strings.ToLower(signed) {
		case "1", "true", "yes", "on":
			values.Set("signed", "true")
		case "0", "false", "no", "off":
			values.Set("signed", "false")
		default:
			return nil, fmt.Errorf("invalid signed filter %q: use true or false", signed)
		}
	}
	if packageHash, err := cmd.Flags().GetString(flagPackageHash); err != nil {
		return nil, err
	} else if packageHash = strings.TrimSpace(packageHash); packageHash != "" {
		values.Set("package_hash", packageHash)
	}
	return values, nil
}

func fetchPouwTrustRegistryHistory(ctx context.Context, client *http.Client, apiBaseURL string, params url.Values) (*pouwTrustRegistryHistoryResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/trust-registry/history"
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw trust registry history: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw trust registry history response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw trust registry history: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw trust registry history: unexpected status %d", resp.StatusCode)
	}

	var history pouwTrustRegistryHistoryResponse
	if err := json.Unmarshal(body, &history); err != nil {
		return nil, fmt.Errorf("decode pouw trust registry history response: %w", err)
	}
	return &history, nil
}

func fetchPouwTrustComplianceExport(ctx context.Context, client *http.Client, apiBaseURL string, params url.Values) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/trust-registry/compliance-export"
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw trust compliance export: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw trust compliance export response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw trust compliance export: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw trust compliance export: unexpected status %d", resp.StatusCode)
	}
	return body, nil
}

func fetchPouwTrustComplianceExportAnchors(ctx context.Context, client *http.Client, apiBaseURL string, params url.Values) (*auditexport.PouwTrustComplianceExportAnchorsResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/trust-registry/compliance-export/anchors"
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw trust compliance export anchors: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw trust compliance export anchors response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw trust compliance export anchors: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw trust compliance export anchors: unexpected status %d", resp.StatusCode)
	}

	var anchors auditexport.PouwTrustComplianceExportAnchorsResponse
	if err := json.Unmarshal(body, &anchors); err != nil {
		return nil, fmt.Errorf("decode pouw trust compliance export anchors response: %w", err)
	}
	return &anchors, nil
}

func fetchPouwControlLedgerPackageAnchors(ctx context.Context, client *http.Client, apiBaseURL string, params url.Values) (*audithttp.GetControlLedgerPackageAnchorsResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/control-ledger-packages/anchors"
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query pouw control ledger package anchors: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pouw control ledger package anchors response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return nil, fmt.Errorf("query pouw control ledger package anchors: %s", payload.Error)
		}
		return nil, fmt.Errorf("query pouw control ledger package anchors: unexpected status %d", resp.StatusCode)
	}

	var anchors audithttp.GetControlLedgerPackageAnchorsResponse
	if err := json.Unmarshal(body, &anchors); err != nil {
		return nil, fmt.Errorf("decode pouw control ledger package anchors response: %w", err)
	}
	return &anchors, nil
}

func verifyPouwTrustCompliancePackageRemote(ctx context.Context, client *http.Client, apiBaseURL string, payload []byte) (auditexport.PouwTrustCompliancePackageVerificationResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/trust-registry/compliance-export/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return auditexport.PouwTrustCompliancePackageVerificationResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return auditexport.PouwTrustCompliancePackageVerificationResponse{}, fmt.Errorf("verify pouw trust compliance package: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return auditexport.PouwTrustCompliancePackageVerificationResponse{}, fmt.Errorf("read pouw trust compliance package verification response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return auditexport.PouwTrustCompliancePackageVerificationResponse{}, fmt.Errorf("verify pouw trust compliance package: %s", payload.Error)
		}
		return auditexport.PouwTrustCompliancePackageVerificationResponse{}, fmt.Errorf("verify pouw trust compliance package: unexpected status %d", resp.StatusCode)
	}

	var verification auditexport.PouwTrustCompliancePackageVerificationResponse
	if err := json.Unmarshal(body, &verification); err != nil {
		return auditexport.PouwTrustCompliancePackageVerificationResponse{}, fmt.Errorf("decode pouw trust compliance package verification response: %w", err)
	}
	return verification, nil
}

func verifyPortableControlLedgerPackageRemote(ctx context.Context, client *http.Client, apiBaseURL string, payload []byte) (audithttp.VerifyPortableControlLedgerPackageResponse, error) {
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := strings.TrimRight(apiBaseURL, "/") + "/api/v1/pouw/control-ledger-packages/verify"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return audithttp.VerifyPortableControlLedgerPackageResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return audithttp.VerifyPortableControlLedgerPackageResponse{}, fmt.Errorf("verify portable control ledger package: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return audithttp.VerifyPortableControlLedgerPackageResponse{}, fmt.Errorf("read portable control ledger package verification response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Error) != "" {
			return audithttp.VerifyPortableControlLedgerPackageResponse{}, fmt.Errorf("verify portable control ledger package: %s", payload.Error)
		}
		return audithttp.VerifyPortableControlLedgerPackageResponse{}, fmt.Errorf("verify portable control ledger package: unexpected status %d", resp.StatusCode)
	}

	var verification audithttp.VerifyPortableControlLedgerPackageResponse
	if err := json.Unmarshal(body, &verification); err != nil {
		return audithttp.VerifyPortableControlLedgerPackageResponse{}, fmt.Errorf("decode portable control ledger package verification response: %w", err)
	}
	return verification, nil
}

func readPouwTrustCompliancePackageInput(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		payload, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read pouw trust compliance package from stdin: %w", err)
		}
		if len(payload) == 0 {
			return nil, fmt.Errorf("pouw trust compliance package input is empty")
		}
		return payload, nil
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pouw trust compliance package file %q: %w", path, err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("pouw trust compliance package file %q is empty", path)
	}
	return payload, nil
}

func readPortableControlLedgerPackageInput(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == "-" {
		payload, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read portable control ledger package from stdin: %w", err)
		}
		if len(payload) == 0 {
			return nil, fmt.Errorf("portable control ledger package input is empty")
		}
		return payload, nil
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read portable control ledger package file %q: %w", path, err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("portable control ledger package file %q is empty", path)
	}
	return payload, nil
}
