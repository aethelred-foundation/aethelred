package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/server"

	cosmosevmserver "github.com/cosmos/evm/server"
	cosmosevmserverconfig "github.com/cosmos/evm/server/config"

	"github.com/aethelred/aethelred/app"
	"github.com/aethelred/aethelred/app/evmconfig"
)

// jsonrpc.go starts the EVM JSON-RPC HTTP server as a side service of the node
// start command (ADR-0001 Phase 1). It runs under the start command's
// cancellable context, sharing the node's client context — it does NOT replace
// the custom ABCI++/PoUW start logic or the consensus mempool.
//
// EVM transactions submitted via eth_sendRawTransaction broadcast through the
// standard CometBFT tx path (BroadcastTx → CheckTx → the dual-route ante → the
// PoUW PrepareProposal), so block inclusion needs no experimental EVM mempool;
// the mempool argument to StartJSONRPC is nil (the RPC backend guards it, so
// txpool_* returns empty rather than erroring).

// Flag keys for the JSON-RPC side service.
const (
	flagJSONRPCEnable  = "json-rpc.enable"
	flagJSONRPCAddress = "json-rpc.address"
	flagJSONRPCAPI     = "json-rpc.api"
)

// runningApp captures the concrete app the AppCreator built, so the PostSetup
// hook can hand it to the JSON-RPC server (for RegisterPendingTxListener). One
// node runs per process, so a package var is sufficient.
var runningApp *app.AethelredApp

// addJSONRPCStartFlags registers the JSON-RPC flags on the start command,
// preserving any existing module init flags.
func addJSONRPCStartFlags(base func(*cobra.Command)) func(*cobra.Command) {
	return func(cmd *cobra.Command) {
		if base != nil {
			base(cmd)
		}
		cmd.Flags().Bool(flagJSONRPCEnable, false, "Enable the EVM JSON-RPC HTTP server")
		cmd.Flags().String(flagJSONRPCAddress, cosmosevmserverconfig.DefaultJSONRPCAddress, "EVM JSON-RPC HTTP server listen address")
		cmd.Flags().StringSlice(flagJSONRPCAPI, cosmosevmserverconfig.GetDefaultAPINamespaces(), "EVM JSON-RPC namespaces to enable (eth,net,web3,...)")
	}
}

// startJSONRPCPostSetup is the PostSetup hook: if enabled, it starts the EVM
// JSON-RPC HTTP server under the start command's errgroup + context.
func startJSONRPCPostSetup(svrCtx *server.Context, clientCtx client.Context, ctx context.Context, g *errgroup.Group) error {
	if !svrCtx.Viper.GetBool(flagJSONRPCEnable) {
		return nil
	}
	if runningApp == nil {
		svrCtx.Logger.Error("JSON-RPC enabled but the Aethelred app was not captured; skipping")
		return nil
	}

	cfg := cosmosevmserverconfig.DefaultConfig()
	cfg.JSONRPC.Enable = true
	cfg.EVM.EVMChainID = evmconfig.EVMChainID

	// The net namespace (net_version) rebuilds its config from svrCtx.Viper
	// independently of the cfg above, so set the viper key too — otherwise
	// net_version reports the cosmos/evm default (262144) while eth_chainId
	// correctly reports 7332 from the in-state chain config.
	svrCtx.Viper.Set("evm.evm-chain-id", evmconfig.EVMChainID)
	if addr := svrCtx.Viper.GetString(flagJSONRPCAddress); addr != "" {
		cfg.JSONRPC.Address = addr
	}
	if apis := svrCtx.Viper.GetStringSlice(flagJSONRPCAPI); len(apis) > 0 {
		cfg.JSONRPC.API = apis
	}

	svrCtx.Logger.Info("Starting EVM JSON-RPC server",
		"address", cfg.JSONRPC.Address,
		"namespaces", cfg.JSONRPC.API,
	)

	// indexer and mempool are nil: this chain does not run the experimental EVM
	// tx indexer/mempool; the RPC backend guards both nils, so tx-by-hash and
	// txpool queries degrade gracefully while the read/call/broadcast path is
	// fully live.
	_, err := cosmosevmserver.StartJSONRPC(ctx, svrCtx, clientCtx, g, cfg, nil, runningApp, nil)
	return err
}
