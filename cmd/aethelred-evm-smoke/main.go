// aethelred-evm-smoke drives the exact JSON-RPC path an EVM wallet uses
// against a running aethelredd node: chain-id check, balance read, EIP-1559
// transfer signing (chain-id 7332), eth_sendRawTransaction, and receipt
// polling. It is the wallet-adapter-path proof from the integration matrix
// (ADR-0001 Phase 0/1), runnable against any Aethelred EVM endpoint.
//
// Usage:
//
//	aethelred-evm-smoke -rpc http://127.0.0.1:8545 \
//	  -privkey <hex> -to 0x... -value-wei 1000000000000000000
//
// With no -privkey it generates a fresh key, prints its 0x address AND the
// bech32 (aethel1...) form to fund via `aethelredd tx bank send`, then waits
// for funding before sending the transfer.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/cosmos/cosmos-sdk/types/bech32"

	"github.com/aethelred/aethelred/app/evmconfig"
)

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "Aethelred EVM JSON-RPC endpoint")
	privHex := flag.String("privkey", "", "hex private key (no 0x); generated if empty")
	toHex := flag.String("to", "", "recipient 0x address (defaults to a fresh address)")
	valueWei := flag.String("value-wei", "1000000000000000000", "transfer value in wei (aaethel)")
	fundWait := flag.Duration("fund-wait", 120*time.Second, "how long to wait for the sender to be funded")
	flag.Parse()

	c := &rpcClient{url: *rpcURL}

	// 1. Chain identity: the wallet's first handshake.
	chainID := c.mustBig("eth_chainId")
	fmt.Printf("eth_chainId    : %d\n", chainID)
	if chainID.Uint64() != evmconfig.EVMChainID {
		fatalf("chain id mismatch: got %d, want %d", chainID, evmconfig.EVMChainID)
	}

	// 2. Sender key.
	key, err := parseOrGenerateKey(*privHex)
	if err != nil {
		fatalf("key: %v", err)
	}
	from := crypto.PubkeyToAddress(key.PublicKey)
	bech, err := bech32.ConvertAndEncode("aethel", from.Bytes())
	if err != nil {
		fatalf("bech32: %v", err)
	}
	fmt.Printf("sender 0x      : %s\n", from.Hex())
	fmt.Printf("sender bech32  : %s\n", bech)
	fmt.Printf("fund with      : aethelredd tx bank send validator %s 1000000000uaethel ...\n", bech)

	// 3. Wait for funding (the 6->18 decimal bridge: uaethel x 1e12 = aaethel).
	balance := waitForBalance(c, from, *fundWait)
	fmt.Printf("eth_getBalance : %s aaethel\n", balance)

	// 4. Build + sign the EIP-1559 transfer with the wallet-standard signer.
	to := common.HexToAddress(*toHex)
	if *toHex == "" {
		freshKey, _ := crypto.GenerateKey()
		to = crypto.PubkeyToAddress(freshKey.PublicKey)
	}
	value, ok := new(big.Int).SetString(*valueWei, 10)
	if !ok {
		fatalf("bad -value-wei %q", *valueWei)
	}
	nonce := c.mustBig("eth_getTransactionCount", from.Hex(), "pending").Uint64()
	gasPrice := c.mustBig("eth_gasPrice")
	tip := big.NewInt(1_000_000_000) // 1 gwei-equivalent tip
	feeCap := new(big.Int).Add(new(big.Int).Mul(gasPrice, big.NewInt(2)), tip)

	tx := gethtypes.NewTx(&gethtypes.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       21_000,
		To:        &to,
		Value:     value,
	})
	signed, err := gethtypes.SignTx(tx, gethtypes.LatestSignerForChainID(chainID), key)
	if err != nil {
		fatalf("sign: %v", err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		fatalf("encode: %v", err)
	}

	// 5. Broadcast exactly as a wallet does.
	var txHash string
	if err := c.call(&txHash, "eth_sendRawTransaction", fmt.Sprintf("0x%x", raw)); err != nil {
		fatalf("eth_sendRawTransaction: %v", err)
	}
	fmt.Printf("tx hash        : %s\n", txHash)

	// 6. Poll the receipt.
	receipt := waitForReceipt(c, txHash, 60*time.Second)
	status, _ := receipt["status"].(string)
	blockNum, _ := receipt["blockNumber"].(string)
	fmt.Printf("receipt        : status=%s block=%s\n", status, blockNum)
	if status != "0x1" {
		fatalf("transfer failed: receipt status %s", status)
	}

	// 7. Recipient balance reflects the transfer.
	recvBal := c.mustBig("eth_getBalance", to.Hex(), "latest")
	fmt.Printf("recipient bal  : %s aaethel (to %s)\n", recvBal, to.Hex())
	if recvBal.Cmp(value) < 0 {
		fatalf("recipient balance %s below transferred value %s", recvBal, value)
	}

	fmt.Println("EVM WALLET PATH OK: chain-id, funding bridge, EIP-1559 sign, broadcast, receipt, balance — all live.")
}

func parseOrGenerateKey(hexKey string) (*ecdsa.PrivateKey, error) {
	if hexKey == "" {
		return crypto.GenerateKey()
	}
	return crypto.HexToECDSA(hexKey)
}

func waitForBalance(c *rpcClient, addr common.Address, wait time.Duration) *big.Int {
	deadline := time.Now().Add(wait)
	for {
		bal := c.mustBig("eth_getBalance", addr.Hex(), "latest")
		if bal.Sign() > 0 {
			return bal
		}
		if time.Now().After(deadline) {
			fatalf("sender %s not funded within %s", addr.Hex(), wait)
		}
		time.Sleep(2 * time.Second)
	}
}

func waitForReceipt(c *rpcClient, txHash string, wait time.Duration) map[string]interface{} {
	deadline := time.Now().Add(wait)
	for {
		var receipt map[string]interface{}
		err := c.call(&receipt, "eth_getTransactionReceipt", txHash)
		if err == nil && receipt != nil {
			return receipt
		}
		if time.Now().After(deadline) {
			fatalf("no receipt for %s within %s (last err: %v)", txHash, wait, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// ── minimal JSON-RPC client ───────────────────────────────────────────────────

type rpcClient struct {
	url string
	id  int
}

func (c *rpcClient) call(result interface{}, method string, params ...interface{}) (callErr error) {
	c.id++
	if params == nil {
		params = []interface{}{}
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": c.id, "method": method, "params": params,
	})
	if err != nil {
		return err
	}
	resp, err := http.Post(c.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); callErr == nil && err != nil {
			callErr = fmt.Errorf("close rpc response body: %w", err)
		}
	}()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return fmt.Errorf("rpc %s: %d %s", method, envelope.Error.Code, envelope.Error.Message)
	}
	if result == nil || len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		if result != nil {
			return fmt.Errorf("rpc %s: null result", method)
		}
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

func (c *rpcClient) mustBig(method string, params ...interface{}) *big.Int {
	var hexVal string
	if err := c.call(&hexVal, method, params...); err != nil {
		fatalf("%s: %v", method, err)
	}
	v, ok := new(big.Int).SetString(hexVal, 0)
	if !ok {
		fatalf("%s: bad hex %q", method, hexVal)
	}
	return v
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
