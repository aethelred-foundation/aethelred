package app

import "github.com/ethereum/go-ethereum/common"

// jsonrpc.go satisfies the slice of the cosmos/evm JSON-RPC server contract the
// app must provide: AppWithPendingTxStream. The JSON-RPC HTTP server itself is
// started as a side service from the node start command's PostSetup hook (see
// cmd/aethelredd/cmd/root.go), sharing the node's client context — it does NOT
// replace the node's custom ABCI++/PoUW start logic or consensus mempool.

// RegisterPendingTxListener registers a listener for new pending EVM tx hashes;
// the JSON-RPC newPendingTransactions subscription registers one.
//
// Honest scope: this chain does not wire cosmos/evm's experimental EVM mempool
// into consensus (block inclusion flows through the standard CometBFT mempool +
// the custom PoUW PrepareProposal, and eth_sendRawTransaction broadcasts via
// the normal tx path). Listeners are therefore held but not currently fired, so
// the newPendingTransactions push subscription is inert — an honest degradation
// of one optional websocket feature, not a broken RPC. All request/response
// endpoints (eth_call, eth_chainId, eth_getBalance, eth_sendRawTransaction, …)
// are fully live.
func (app *AethelredApp) RegisterPendingTxListener(listener func(common.Hash)) {
	app.pendingTxListeners = append(app.pendingTxListeners, listener)
}

// PendingTxListeners exposes the registered listeners (test/observability).
func (app *AethelredApp) PendingTxListeners() []func(common.Hash) {
	return app.pendingTxListeners
}
