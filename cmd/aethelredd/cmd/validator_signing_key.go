package cmd

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/app"
)

const (
	defaultPrivValidatorKeyFile = "config/priv_validator_key.json"
	maxPrivValidatorKeyFileSize = 64 * 1024
)

var (
	privValidatorKeyFileOptions = []string{
		"priv_validator_key_file",
		"priv-validator-key-file",
	}
	privValidatorListenAddrOptions = []string{
		"priv_validator_laddr",
		"priv-validator-laddr",
	}
)

type validatorSigningKeySetter interface {
	SetValidatorPrivateKey([]byte) error
}

// configureLocalValidatorSigningKey loads the local CometBFT file private
// validator key for application-level compact verification signatures.
//
// CometBFT's AppCreator cannot return an error, so newApp converts errors from
// this helper into a startup panic after closing the partially constructed app.
// Keeping parsing here error-returning avoids CometBFT's FilePV loaders, which
// terminate the process with os.Exit on malformed files.
func configureLocalValidatorSigningKey(
	setter validatorSigningKeySetter,
	appOpts servertypes.AppOptions,
) error {
	if setter == nil {
		return fmt.Errorf("validator signing-key setter is nil")
	}

	remoteSignerAddress := firstAppOption(appOpts, privValidatorListenAddrOptions...)
	if remoteSignerAddress != "" {
		return fmt.Errorf(
			"remote CometBFT private validator %q is not supported for compact verification signatures; "+
				"configure a local ed25519 priv_validator_key_file or a future remote application-signing integration",
			remoteSignerAddress,
		)
	}

	keyFile := resolvePrivValidatorKeyFile(appOpts)
	privateKey, found, err := loadLocalEd25519PrivValidatorKey(keyFile)
	if err != nil {
		return err
	}
	if !found {
		// A non-validator/full node may legitimately have no local private
		// validator key. CometBFT itself decides whether the node can validate.
		return nil
	}
	defer clear(privateKey)

	if err := setter.SetValidatorPrivateKey(privateKey); err != nil {
		return fmt.Errorf("configure compact verification signing key: %w", err)
	}
	return nil
}

func resolvePrivValidatorKeyFile(appOpts servertypes.AppOptions) string {
	home := strings.TrimSpace(firstAppOption(appOpts, flags.FlagHome))
	if home == "" {
		home = app.DefaultNodeHome
	}

	keyFile := firstAppOption(appOpts, privValidatorKeyFileOptions...)
	if keyFile == "" {
		keyFile = defaultPrivValidatorKeyFile
	}
	if filepath.IsAbs(keyFile) {
		return filepath.Clean(keyFile)
	}
	return filepath.Clean(filepath.Join(home, keyFile))
}

func firstAppOption(appOpts servertypes.AppOptions, keys ...string) string {
	if appOpts == nil {
		return ""
	}
	for _, key := range keys {
		value := strings.TrimSpace(cast.ToString(appOpts.Get(key)))
		if value != "" {
			return value
		}
	}
	return ""
}

// loadLocalEd25519PrivValidatorKey returns found=false for a missing file so
// non-validator nodes can start. Any existing but insecure or malformed key
// fails closed.
func loadLocalEd25519PrivValidatorKey(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect CometBFT private validator key %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("CometBFT private validator key %q must not be a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("CometBFT private validator key %q is not a regular file", path)
	}
	if err := validatePrivValidatorKeyPermissions(path, info.Mode()); err != nil {
		return nil, false, err
	}
	if info.Size() <= 0 || info.Size() > maxPrivValidatorKeyFileSize {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q has invalid size %d bytes",
			path,
			info.Size(),
		)
	}

	keyDirectory, keyName := filepath.Split(path)
	if keyDirectory == "" {
		keyDirectory = "."
	}
	root, err := os.OpenRoot(keyDirectory)
	if err != nil {
		return nil, false, fmt.Errorf(
			"open CometBFT private validator key directory %q: %w",
			keyDirectory,
			err,
		)
	}
	defer func() {
		_ = root.Close()
	}()

	file, err := root.Open(keyName)
	if err != nil {
		return nil, false, fmt.Errorf("open CometBFT private validator key %q: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat opened CometBFT private validator key %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, false, fmt.Errorf("CometBFT private validator key %q changed while opening it", path)
	}
	if err := validatePrivValidatorKeyPermissions(path, openedInfo.Mode()); err != nil {
		return nil, false, err
	}

	keyJSON, err := io.ReadAll(io.LimitReader(file, maxPrivValidatorKeyFileSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("read CometBFT private validator key %q: %w", path, err)
	}
	defer clear(keyJSON)
	if len(keyJSON) > maxPrivValidatorKeyFileSize {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q exceeds %d bytes",
			path,
			maxPrivValidatorKeyFileSize,
		)
	}

	var fileKey privval.FilePVKey
	if err := cmtjson.Unmarshal(keyJSON, &fileKey); err != nil {
		return nil, false, fmt.Errorf("parse CometBFT private validator key %q: %w", path, err)
	}

	privateKey, ok := fileKey.PrivKey.(cmted25519.PrivKey)
	if !ok {
		if fileKey.PrivKey == nil {
			return nil, false, fmt.Errorf("CometBFT private validator key %q has no private key", path)
		}
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q uses unsupported key type %T; compact verification signatures require ed25519",
			path,
			fileKey.PrivKey,
		)
	}
	defer clear(privateKey)
	if len(privateKey) != cmted25519.PrivateKeySize {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q has invalid ed25519 length %d",
			path,
			len(privateKey),
		)
	}

	derivedPrivateKey := stded25519.NewKeyFromSeed(privateKey[:stded25519.SeedSize])
	defer clear(derivedPrivateKey)
	if !bytes.Equal(derivedPrivateKey, privateKey) {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q has inconsistent ed25519 seed and public key bytes",
			path,
		)
	}

	derivedPublicKey := cmted25519.PrivKey(derivedPrivateKey).PubKey()
	filePublicKey, ok := fileKey.PubKey.(cmted25519.PubKey)
	if !ok || !bytes.Equal(filePublicKey.Bytes(), derivedPublicKey.Bytes()) {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q has a public key that does not match its private key",
			path,
		)
	}
	if len(fileKey.Address) == 0 || !bytes.Equal(fileKey.Address, derivedPublicKey.Address()) {
		return nil, false, fmt.Errorf(
			"CometBFT private validator key %q has an address that does not match its private key",
			path,
		)
	}

	return append([]byte(nil), privateKey...), true, nil
}

func validatePrivValidatorKeyPermissions(path string, mode os.FileMode) error {
	switch mode.Perm() {
	case 0o400, 0o600:
		return nil
	default:
		return fmt.Errorf(
			"CometBFT private validator key %q has insecure permissions %04o; expected 0400 or 0600",
			path,
			mode.Perm(),
		)
	}
}
