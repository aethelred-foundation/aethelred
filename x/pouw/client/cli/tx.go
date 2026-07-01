package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	sdkmath "cosmossdk.io/math"
	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/aethelred/aethelred/x/pouw/types"
)

const (
	flagTEEPlatforms      = "tee-platforms"
	flagZKMLSystems       = "zkml-systems"
	flagMaxConcurrentJobs = "max-concurrent-jobs"
	flagIsOnline          = "is-online"
	flagStakeAmount       = "amount"
	flagValidator         = "validator"
	flagModel             = "model"
	flagInput             = "input"
	flagProofType         = "proof-type"
	flagPurpose           = "purpose"
	flagModelID           = "model-id"
	flagModelName         = "name"
	flagModelDescription  = "description"
	flagModelVersion      = "version"
	flagModelArch         = "architecture"
	flagVerifyingKeyHash  = "verifying-key-hash"
	flagCircuitHash       = "circuit-hash"

	// CEAP confidentiality-policy flags for submit-job.
	flagConfBackends        = "conf-backends"
	flagConfMinVerification = "conf-min-verification"
	flagConfPlatforms       = "conf-platforms"
	flagConfRequireVendor   = "conf-require-vendor-root"
	flagConfResidency       = "conf-residency"

	stakeDisplayDenom = "aethel"
	stakeBaseDenom    = "uaethel"

	// 1 AETHEL = 1,000,000 uaethel.
	stakeBaseUnitsPerAETHEL int64 = 1_000_000
	// Hard minimum for April 1 testnet Sybil resistance.
	minStakeAETHEL int64 = 100_000
)

// CmdRegisterValidatorCapability creates a CLI command for registering validator capabilities.
func CmdRegisterValidatorCapability() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-validator-capability",
		Short: "Register validator compute capabilities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			teePlatforms, err := cmd.Flags().GetStringSlice(flagTEEPlatforms)
			if err != nil {
				return err
			}

			zkmlSystems, err := cmd.Flags().GetStringSlice(flagZKMLSystems)
			if err != nil {
				return err
			}

			maxConcurrentJobs, err := cmd.Flags().GetInt64(flagMaxConcurrentJobs)
			if err != nil {
				return err
			}

			isOnline, err := cmd.Flags().GetBool(flagIsOnline)
			if err != nil {
				return err
			}

			msg := &types.MsgRegisterValidatorCapability{
				Creator:           clientCtx.GetFromAddress().String(),
				TeePlatforms:      teePlatforms,
				ZkmlSystems:       zkmlSystems,
				MaxConcurrentJobs: maxConcurrentJobs,
				IsOnline:          isOnline,
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().StringSlice(flagTEEPlatforms, []string{}, "Comma-separated list of supported TEE platforms")
	cmd.Flags().StringSlice(flagZKMLSystems, []string{}, "Comma-separated list of supported zkML systems")
	cmd.Flags().Int64(flagMaxConcurrentJobs, 1, "Maximum concurrent jobs the validator can handle")
	cmd.Flags().Bool(flagIsOnline, true, "Whether the validator is currently online")
	_ = cmd.MarkFlagRequired(flagMaxConcurrentJobs)

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdStakeForPoUW creates a CLI command for staking the minimum required amount
// to participate in PoUW validator assignment.
func CmdStakeForPoUW() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stake",
		Short: "Stake for PoUW validator eligibility (minimum 100000aethel)",
		Long: "Delegate stake to a validator operator address for PoUW participation.\n" +
			"Accepted denoms: aethel, uaethel.\n" +
			"Minimum required amount is 100000aethel (100000000000uaethel).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			rawAmount, err := cmd.Flags().GetString(flagStakeAmount)
			if err != nil {
				return err
			}

			stakeCoin, err := parseStakeAmount(rawAmount)
			if err != nil {
				return err
			}
			if err := enforceMinimumStake(stakeCoin); err != nil {
				return err
			}

			validatorAddr, err := cmd.Flags().GetString(flagValidator)
			if err != nil {
				return err
			}
			if strings.TrimSpace(validatorAddr) == "" {
				validatorAddr = sdk.ValAddress(clientCtx.GetFromAddress()).String()
			}

			msg := stakingtypes.NewMsgDelegate(
				clientCtx.GetFromAddress().String(),
				validatorAddr,
				stakeCoin,
			)

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String(
		flagStakeAmount,
		fmt.Sprintf("%d%s", minStakeAETHEL, stakeDisplayDenom),
		"Stake amount (accepted denoms: aethel, uaethel)",
	)
	cmd.Flags().String(
		flagValidator,
		"",
		"Validator operator address (defaults to your valoper address)",
	)
	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdRegisterValidatorPCR0 creates a CLI command for explicitly registering a validator PCR0 hash.
func CmdRegisterValidatorPCR0() *cobra.Command {
	cmd := &cobra.Command{
		Use: "register-pcr0 [pcr0-hex]",
		Aliases: []string{
			"register-validator-pcr0",
		},
		Short: "Register AWS Nitro PCR0 measurement for the signing validator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			validator := clientCtx.GetFromAddress().String()
			msg := &types.MsgRegisterValidatorPCR0{
				Creator:          validator,
				ValidatorAddress: validator,
				Pcr0Hex:          args[0],
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdRegisterValidatorHybridKey registers the signing validator's hybrid
// (secp256k1 + ML-DSA) public key, used to verify its Digital Seal quorum
// signatures. The key is derived deterministically from the validator's
// consensus key and printed by the node at startup.
func CmdRegisterValidatorHybridKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "register-hybrid-key [hybrid-public-key-hex]",
		Aliases: []string{"register-validator-hybrid-key"},
		Short:   "Register this validator's hybrid (secp256k1 + ML-DSA) public key for Digital Seal quorum signing",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			pubKey, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(args[0]), "0x"))
			if err != nil {
				return fmt.Errorf("invalid hybrid public key hex: %w", err)
			}

			validator := clientCtx.GetFromAddress().String()
			msg := &types.MsgRegisterValidatorHybridKey{
				Creator:          validator,
				ValidatorAddress: validator,
				HybridPublicKey:  pubKey,
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// CmdSubmitJob creates a CLI command for submitting a Proof-of-Useful-Work job.
// The job declares a model, an input, and the proof system (TEE / zkML / hybrid)
// the network must use to verify the computation. Validators pick it up, run the
// work, and the result flows into a Digital Seal once verification succeeds.
func CmdSubmitJob() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit-job",
		Short: "Submit a Proof-of-Useful-Work job for TEE/zkML verification",
		Long: "Submit an AI compute job to the PoUW queue.\n\n" +
			"--model and --input each accept either a 32-byte hash as 64 hex chars\n" +
			"(optionally 0x-prefixed) or any other string, which is SHA-256 hashed to\n" +
			"32 bytes. --proof-type selects the verification path: tee | zkml | hybrid.\n\n" +
			"Example:\n" +
			"  aethelredd tx pouw submit-job \\\n" +
			"    --model resnet50-v1 --input sample-batch-0 \\\n" +
			"    --proof-type zkml --purpose \"demo inference\" \\\n" +
			"    --from validator --chain-id aethelred-testnet-1 --yes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			rawModel, err := cmd.Flags().GetString(flagModel)
			if err != nil {
				return err
			}
			modelHash, err := parseHash32(rawModel)
			if err != nil {
				return fmt.Errorf("invalid --model: %w", err)
			}

			rawInput, err := cmd.Flags().GetString(flagInput)
			if err != nil {
				return err
			}
			inputHash, err := parseHash32(rawInput)
			if err != nil {
				return fmt.Errorf("invalid --input: %w", err)
			}

			rawProofType, err := cmd.Flags().GetString(flagProofType)
			if err != nil {
				return err
			}
			proofType, err := parseProofType(rawProofType)
			if err != nil {
				return err
			}

			purpose, err := cmd.Flags().GetString(flagPurpose)
			if err != nil {
				return err
			}

			msg := types.NewMsgSubmitJob(
				clientCtx.GetFromAddress().String(),
				modelHash,
				inputHash,
				proofType,
				purpose,
			)

			// CEAP: attach a confidentiality policy if any --conf-* flag is set.
			policy, err := confidentialityPolicyFromFlags(cmd)
			if err != nil {
				return err
			}
			msg.ConfidentialityPolicy = policy

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String(flagModel, "", "Model: 32-byte hash (64 hex chars) or any string to SHA-256 hash")
	cmd.Flags().String(flagInput, "", "Input: 32-byte hash (64 hex chars) or any string to SHA-256 hash")
	cmd.Flags().String(flagProofType, "tee", "Verification proof type: tee | zkml | hybrid")
	cmd.Flags().String(flagPurpose, "", "Human-readable purpose for this job (required)")
	cmd.Flags().StringSlice(flagConfBackends, nil, "CEAP: allowed confidentiality backends (e.g. tee,fhe); empty = any")
	cmd.Flags().String(flagConfMinVerification, "", "CEAP: minimum verification method (tee-attested|freivalds|optimistic|reexec|zkml)")
	cmd.Flags().StringSlice(flagConfPlatforms, nil, "CEAP: allowed attesting platforms (e.g. amd-sev-snp,intel-tdx); empty = any")
	cmd.Flags().Bool(flagConfRequireVendor, false, "CEAP: require a production vendor root (reject test roots)")
	cmd.Flags().StringSlice(flagConfResidency, nil, "CEAP: allowed data-residency jurisdictions (e.g. EU,UK); empty = any")
	_ = cmd.MarkFlagRequired(flagModel)
	_ = cmd.MarkFlagRequired(flagInput)
	_ = cmd.MarkFlagRequired(flagPurpose)

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// confidentialityPolicyFromFlags builds a CEAP ConfidentialityPolicy from the
// --conf-* flags on submit-job. It returns nil when no confidentiality flag is
// set, so a job with no confidentiality requirement carries a nil policy (which
// is always satisfied). See docs/architecture/ADR-0003.
func confidentialityPolicyFromFlags(cmd *cobra.Command) (*types.ConfidentialityPolicy, error) {
	backends, err := cmd.Flags().GetStringSlice(flagConfBackends)
	if err != nil {
		return nil, err
	}
	minVer, err := cmd.Flags().GetString(flagConfMinVerification)
	if err != nil {
		return nil, err
	}
	platforms, err := cmd.Flags().GetStringSlice(flagConfPlatforms)
	if err != nil {
		return nil, err
	}
	requireVendor, err := cmd.Flags().GetBool(flagConfRequireVendor)
	if err != nil {
		return nil, err
	}
	residency, err := cmd.Flags().GetStringSlice(flagConfResidency)
	if err != nil {
		return nil, err
	}

	if len(backends) == 0 && minVer == "" && len(platforms) == 0 && !requireVendor && len(residency) == 0 {
		return nil, nil
	}
	return &types.ConfidentialityPolicy{
		AllowedBackends:   backends,
		MinVerification:   minVer,
		AllowedPlatforms:  platforms,
		RequireVendorRoot: requireVendor,
		DataResidency:     residency,
	}, nil
}

// CmdRegisterModel creates a CLI command for registering a model. A job can only
// be submitted against a model that has been registered (its model hash must be
// known to the chain), so this is the first step of the job lifecycle.
func CmdRegisterModel() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-model",
		Short: "Register a model so jobs can be submitted against it",
		Long: "Register a model by hash. --model accepts either a 32-byte hash as 64 hex\n" +
			"chars (optionally 0x-prefixed) or any string, which is SHA-256 hashed. Use the\n" +
			"same --model value here and in 'submit-job' so the hashes match.\n\n" +
			"Example:\n" +
			"  aethelredd tx pouw register-model \\\n" +
			"    --model resnet50-v1 --model-id resnet50 --name \"ResNet-50\" \\\n" +
			"    --from validator --chain-id aethelred-testnet-1 --yes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			rawModel, err := cmd.Flags().GetString(flagModel)
			if err != nil {
				return err
			}
			modelHash, err := parseHash32(rawModel)
			if err != nil {
				return fmt.Errorf("invalid --model: %w", err)
			}

			modelID, _ := cmd.Flags().GetString(flagModelID)
			name, _ := cmd.Flags().GetString(flagModelName)
			description, _ := cmd.Flags().GetString(flagModelDescription)
			version, _ := cmd.Flags().GetString(flagModelVersion)
			architecture, _ := cmd.Flags().GetString(flagModelArch)

			msg := types.NewMsgRegisterModel(
				clientCtx.GetFromAddress().String(),
				modelHash,
				modelID,
				name,
				description,
				version,
				architecture,
			)

			// zkML jobs require the model to carry a 32-byte verifying-key hash
			// (and optionally a circuit hash); each accepts a 64-hex value or any
			// string (SHA-256 hashed). Left unset, the model is TEE-only.
			if raw, _ := cmd.Flags().GetString(flagVerifyingKeyHash); strings.TrimSpace(raw) != "" {
				vkh, err := parseHash32(raw)
				if err != nil {
					return fmt.Errorf("invalid --verifying-key-hash: %w", err)
				}
				msg.VerifyingKeyHash = vkh
			}
			if raw, _ := cmd.Flags().GetString(flagCircuitHash); strings.TrimSpace(raw) != "" {
				ch, err := parseHash32(raw)
				if err != nil {
					return fmt.Errorf("invalid --circuit-hash: %w", err)
				}
				msg.CircuitHash = ch
			}

			if err := msg.ValidateBasic(); err != nil {
				return err
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String(flagModel, "", "Model: 32-byte hash (64 hex chars) or any string to SHA-256 hash")
	cmd.Flags().String(flagModelID, "", "Short model identifier (required)")
	cmd.Flags().String(flagModelName, "", "Human-readable model name (required)")
	cmd.Flags().String(flagModelDescription, "", "Model description")
	cmd.Flags().String(flagModelVersion, "v1", "Model version")
	cmd.Flags().String(flagModelArch, "", "Model architecture (e.g. transformer, cnn)")
	cmd.Flags().String(flagVerifyingKeyHash, "", "zkML verifying-key hash: 32-byte hash (64 hex) or string to SHA-256 (required for zkML jobs)")
	cmd.Flags().String(flagCircuitHash, "", "zkML circuit hash: 32-byte hash (64 hex) or string to SHA-256")
	_ = cmd.MarkFlagRequired(flagModel)
	_ = cmd.MarkFlagRequired(flagModelID)
	_ = cmd.MarkFlagRequired(flagModelName)

	flags.AddTxFlagsToCmd(cmd)

	return cmd
}

// parseHash32 returns a 32-byte hash from raw input. If raw is 64 hex chars
// (optionally 0x-prefixed) it is decoded directly; otherwise raw is SHA-256
// hashed. This lets callers pass a precomputed model/input digest or a plain
// identifier interchangeably.
func parseHash32(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("value is empty")
	}
	candidate := strings.TrimPrefix(trimmed, "0x")
	if len(candidate) == 64 {
		if decoded, err := hex.DecodeString(candidate); err == nil {
			return decoded, nil
		}
	}
	sum := sha256.Sum256([]byte(trimmed))
	return sum[:], nil
}

// parseProofType maps a user-friendly proof-type string to the enum value.
func parseProofType(raw string) (types.ProofType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tee":
		return types.ProofTypeTEE, nil
	case "zkml":
		return types.ProofTypeZKML, nil
	case "hybrid":
		return types.ProofTypeHybrid, nil
	default:
		return types.ProofType_PROOF_TYPE_UNSPECIFIED, fmt.Errorf(
			"invalid proof type %q (supported: tee, zkml, hybrid)", raw,
		)
	}
}

func minimumStakeUAETHEL() sdkmath.Int {
	return sdkmath.NewInt(minStakeAETHEL * stakeBaseUnitsPerAETHEL)
}

func parseStakeAmount(raw string) (sdk.Coin, error) {
	coin, err := sdk.ParseCoinNormalized(strings.TrimSpace(raw))
	if err != nil {
		return sdk.Coin{}, fmt.Errorf("invalid stake amount %q: %w", raw, err)
	}
	if !coin.IsPositive() {
		return sdk.Coin{}, fmt.Errorf("stake amount must be positive")
	}

	switch strings.ToLower(coin.Denom) {
	case stakeDisplayDenom:
		return sdk.NewCoin(stakeBaseDenom, coin.Amount.MulRaw(stakeBaseUnitsPerAETHEL)), nil
	case stakeBaseDenom:
		return coin, nil
	default:
		return sdk.Coin{}, fmt.Errorf(
			"unsupported stake denom %q (supported: %s, %s)",
			coin.Denom,
			stakeDisplayDenom,
			stakeBaseDenom,
		)
	}
}

func enforceMinimumStake(coin sdk.Coin) error {
	if coin.Denom != stakeBaseDenom {
		return fmt.Errorf("stake denom must be %s", stakeBaseDenom)
	}

	minimum := minimumStakeUAETHEL()
	if coin.Amount.LT(minimum) {
		return fmt.Errorf(
			"minimum stake not met: got %s%s, need at least %d%s (%s%s)",
			coin.Amount.String(),
			stakeBaseDenom,
			minStakeAETHEL,
			stakeDisplayDenom,
			minimum.String(),
			stakeBaseDenom,
		)
	}

	return nil
}
