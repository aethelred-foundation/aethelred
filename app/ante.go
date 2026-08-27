package app

import (
	"context"
	"fmt"

	"cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/x/auth/ante"

	evmrootante "github.com/cosmos/evm/ante"
	evmcosmosante "github.com/cosmos/evm/ante/cosmos"
	evmante "github.com/cosmos/evm/ante/evm"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

// HandlerOptions are the options required for constructing a default SDK AnteHandler
type HandlerOptions struct {
	ante.HandlerOptions
}

// ethereumTxExtensionURL is the extension option that marks a transaction as an
// EVM transaction (a wrapped MsgEthereumTx carrying an Ethereum signature).
const ethereumTxExtensionURL = "/cosmos.evm.vm.v1.ExtensionOptionsEthereumTx"

// NewAnteHandler returns the dual-route AnteHandler: transactions carrying the
// EVM extension option take the cosmos/evm mono EVM ante chain (Ethereum
// signature verification, EVM fee market); everything else takes the existing
// Aethelred cosmos chain (rate limiting, compute-job fees). The dispatch
// mirrors cosmos/evm's own ante router; unknown extension options fail closed.
func NewAnteHandler(app *AethelredApp) sdk.AnteHandler {
	cosmosHandler := newCosmosAnteHandler(app)
	return func(ctx sdk.Context, tx sdk.Tx, sim bool) (sdk.Context, error) {
		if txWithExtensions, ok := tx.(ante.HasExtensionOptionsTx); ok {
			if opts := txWithExtensions.GetExtensionOptions(); len(opts) > 0 {
				if opts[0].GetTypeUrl() == ethereumTxExtensionURL {
					return newEVMAnteHandler(app, ctx)(ctx, tx, sim)
				}
				return ctx, errors.Wrapf(sdkerrors.ErrUnknownExtensionOptions,
					"rejecting tx with unsupported extension option: %s", opts[0].GetTypeUrl())
			}
		}
		return cosmosHandler(ctx, tx, sim)
	}
}

// newCosmosAnteHandler is the pre-existing Aethelred cosmos ante chain plus the
// EVM-message rejection guard.
func newCosmosAnteHandler(app *AethelredApp) sdk.AnteHandler {
	return sdk.ChainAnteDecorators(
		ante.NewSetUpContextDecorator(),
		// Defense in depth: MsgEthereumTx MUST arrive via the EVM route above;
		// reject it on the cosmos route so EVM messages can never bypass
		// Ethereum signature verification by omitting the extension option.
		evmcosmosante.NewRejectMessagesDecorator(),
		NewRateLimitDecorator(app.rateLimiter),
		ante.NewExtensionOptionsDecorator(nil),
		ante.NewValidateBasicDecorator(),
		ante.NewTxTimeoutHeightDecorator(),
		ante.NewValidateMemoDecorator(app.AccountKeeper),
		ante.NewConsumeGasForTxSizeDecorator(app.AccountKeeper),
		ante.NewDeductFeeDecorator(app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, nil),
		ante.NewSetPubKeyDecorator(app.AccountKeeper),
		ante.NewValidateSigCountDecorator(app.AccountKeeper),
		// cosmos/evm's gas consumer, NOT the SDK default: Aethelred accounts
		// are eth_secp256k1, and the default consumer rejects that key type
		// ("unrecognized public key type") — which blocked every native
		// (bank/staking/gov) transaction from an EVM-keyed account. Found by
		// the wallet's live native-tx E2E. Falls through to SDK behavior for
		// all standard key types.
		ante.NewSigGasConsumeDecorator(app.AccountKeeper, evmrootante.SigVerificationGasConsumer),
		ante.NewSigVerificationDecorator(app.AccountKeeper, app.TxConfig().SignModeHandler()),
		ante.NewIncrementSequenceDecorator(app.AccountKeeper),
		// Custom Aethelred decorator: enforce compute job fees
		NewComputeJobFeeDecorator(app.PouwKeeper, app.BankKeeper),
	)
}

// newEVMAnteHandler builds the cosmos/evm mono EVM ante chain with the current
// block's module parameters (fetched per transaction, matching upstream).
func newEVMAnteHandler(app *AethelredApp, ctx sdk.Context) sdk.AnteHandler {
	evmParams := app.EVMKeeper.GetParams(ctx)
	feemarketParams := app.FeeMarketKeeper.GetParams(ctx)
	return sdk.ChainAnteDecorators(
		evmante.NewEVMMonoDecorator(
			app.AccountKeeper,
			app.FeeMarketKeeper,
			app.EVMKeeper,
			0, // MaxTxGasWanted: 0 = no per-tx gas-wanted cap
			&evmParams,
			&feemarketParams,
		),
	)
}

// ComputeJobFeeDecorator validates compute job transactions and enforces fee payment.
// This ensures that:
// 1. Compute job submissions include a valid model hash
// 2. The submitter pays at least the BaseJobFee defined in module params
// 3. Fees are collected into the pouw module account for later distribution
//
// Audit note [L-05]: Fees are collected during AnteHandle (before message execution).
// If the compute job message handler subsequently fails, the Cosmos SDK will revert
// all state changes including the fee transfer, so fees are NOT permanently collected
// for failed jobs. This is the standard Cosmos SDK ante-handler pattern.
type ComputeJobFeeDecorator struct {
	pouwKeeper pouwkeeper.Keeper
	bankKeeper BankKeeper
}

// BankKeeper defines the expected bank keeper interface for fee handling
type BankKeeper interface {
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SendCoinsFromAccountToModule(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error
}

// NewComputeJobFeeDecorator creates a new ComputeJobFeeDecorator
func NewComputeJobFeeDecorator(pouwKeeper pouwkeeper.Keeper, bankKeeper BankKeeper) ComputeJobFeeDecorator {
	return ComputeJobFeeDecorator{
		pouwKeeper: pouwKeeper,
		bankKeeper: bankKeeper,
	}
}

// AnteHandle implements the AnteDecorator interface.
// It validates compute job messages and enforces fee payment.
func (cjd ComputeJobFeeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	for _, msg := range tx.GetMsgs() {
		// SECURITY FIX C-01: Use concrete type assertion instead of interface assertion.
		// MsgSubmitJob does not implement GetRequestedBy()/GetFee(), so the previous
		// interface assertion silently skipped fee enforcement for all compute jobs.
		submitMsg, ok := msg.(*pouwtypes.MsgSubmitJob)
		if !ok {
			continue
		}

		// Validate model hash is present
		modelHash := submitMsg.GetModelHash()
		if len(modelHash) == 0 {
			return ctx, errors.Wrap(sdkerrors.ErrInvalidRequest, "compute job must include model hash")
		}

		// Validate model hash is 32 bytes (SHA-256)
		if len(modelHash) != 32 {
			return ctx, errors.Wrap(sdkerrors.ErrInvalidRequest, "model hash must be 32 bytes (SHA-256)")
		}

		// Get module params for fee validation
		params, err := cjd.pouwKeeper.GetParams(ctx)
		if err != nil || params == nil {
			return ctx, errors.Wrap(sdkerrors.ErrInvalidRequest, "failed to get module params")
		}

		// Parse the base job fee from params
		baseJobFee, err := sdk.ParseCoinNormalized(params.BaseJobFee)
		if err != nil {
			return ctx, errors.Wrap(sdkerrors.ErrInvalidRequest, fmt.Sprintf("invalid base job fee in params: %s", params.BaseJobFee))
		}

		if !simulate {
			// SECURITY FIX C-01: Use msg.Creator as fee payer (the transaction signer).
			// The base job fee from module params is always charged.
			senderAddr, err := sdk.AccAddressFromBech32(submitMsg.GetCreator())
			if err != nil {
				return ctx, errors.Wrap(sdkerrors.ErrInvalidAddress, "invalid creator address")
			}

			spendable := cjd.bankKeeper.SpendableCoins(ctx, senderAddr)
			if !spendable.IsAllGTE(sdk.NewCoins(baseJobFee)) {
				return ctx, errors.Wrap(
					sdkerrors.ErrInsufficientFunds,
					fmt.Sprintf("insufficient funds for compute job fee: need %s, have %s", baseJobFee, spendable),
				)
			}

			// Collect the fee into the pouw module account
			// This fee will be distributed to validators as rewards upon job completion
			if err := cjd.bankKeeper.SendCoinsFromAccountToModule(
				ctx, senderAddr, "pouw", sdk.NewCoins(baseJobFee),
			); err != nil {
				return ctx, errors.Wrap(sdkerrors.ErrInsufficientFunds, fmt.Sprintf("failed to collect compute job fee: %s", err))
			}

			ctx.Logger().Info("Compute job fee collected",
				"creator", submitMsg.GetCreator(),
				"fee", baseJobFee.String(),
			)
		}
	}

	return next(ctx, tx, simulate)
}
