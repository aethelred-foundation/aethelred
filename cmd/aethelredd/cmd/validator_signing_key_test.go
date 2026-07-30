package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cmtcrypto "github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtsecp256k1 "github.com/cometbft/cometbft/crypto/secp256k1"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	"github.com/stretchr/testify/require"
)

type recordingValidatorSigningKeySetter struct {
	key   []byte
	calls int
	err   error
}

func (s *recordingValidatorSigningKeySetter) SetValidatorPrivateKey(key []byte) error {
	s.calls++
	s.key = append([]byte(nil), key...)
	return s.err
}

func TestResolvePrivValidatorKeyFile(t *testing.T) {
	home := t.TempDir()

	require.Equal(
		t,
		filepath.Join(home, defaultPrivValidatorKeyFile),
		resolvePrivValidatorKeyFile(sims.AppOptionsMap{flags.FlagHome: home}),
	)
	require.Equal(
		t,
		filepath.Join(home, "keys", "validator.json"),
		resolvePrivValidatorKeyFile(sims.AppOptionsMap{
			flags.FlagHome:            home,
			"priv_validator_key_file": "keys/validator.json",
		}),
	)

	absolutePath := filepath.Join(t.TempDir(), "validator.json")
	require.Equal(
		t,
		absolutePath,
		resolvePrivValidatorKeyFile(sims.AppOptionsMap{
			flags.FlagHome:            home,
			"priv_validator_key_file": absolutePath,
		}),
	)
}

func TestLoadLocalEd25519PrivValidatorKey(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			privateKey := cmted25519.GenPrivKey()
			path := writePrivValidatorKeyFile(t, privateKey, mode)

			loaded, found, err := loadLocalEd25519PrivValidatorKey(path)
			require.NoError(t, err)
			require.True(t, found)
			require.Equal(t, privateKey.Bytes(), loaded)
		})
	}
}

func TestLoadLocalEd25519PrivValidatorKeyMissingIsOptional(t *testing.T) {
	loaded, found, err := loadLocalEd25519PrivValidatorKey(
		filepath.Join(t.TempDir(), "missing.json"),
	)
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, loaded)
}

func TestLoadLocalEd25519PrivValidatorKeyRejectsInsecurePermissions(t *testing.T) {
	path := writePrivValidatorKeyFile(t, cmted25519.GenPrivKey(), 0o600)
	require.NoError(t, os.Chmod(path, 0o644))

	_, _, err := loadLocalEd25519PrivValidatorKey(path)
	require.ErrorContains(t, err, "insecure permissions")
}

func TestLoadLocalEd25519PrivValidatorKeyRejectsSymlink(t *testing.T) {
	target := writePrivValidatorKeyFile(t, cmted25519.GenPrivKey(), 0o600)
	link := filepath.Join(t.TempDir(), "priv_validator_key.json")
	require.NoError(t, os.Symlink(target, link))

	_, _, err := loadLocalEd25519PrivValidatorKey(link)
	require.ErrorContains(t, err, "must not be a symbolic link")
}

func TestLoadLocalEd25519PrivValidatorKeyRejectsWrongType(t *testing.T) {
	path := writePrivValidatorKeyFile(t, cmtsecp256k1.GenPrivKey(), 0o600)

	_, _, err := loadLocalEd25519PrivValidatorKey(path)
	require.ErrorContains(t, err, "require ed25519")
}

func TestLoadLocalEd25519PrivValidatorKeyRejectsMalformedAndInconsistentKeys(t *testing.T) {
	t.Run("malformed JSON", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "priv_validator_key.json")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))

		_, _, err := loadLocalEd25519PrivValidatorKey(path)
		require.ErrorContains(t, err, "parse CometBFT private validator key")
	})

	t.Run("invalid private key length", func(t *testing.T) {
		privateKey := cmted25519.GenPrivKey()
		path := writePrivValidatorKeyFile(t, privateKey, 0o600)
		pubKey := privateKey.PubKey()
		serialized := fmt.Sprintf(`{
  "address": "%s",
  "pub_key": {"type": "tendermint/PubKeyEd25519", "value": "%s"},
  "priv_key": {"type": "tendermint/PrivKeyEd25519", "value": "%s"}
}`,
			pubKey.Address(),
			base64.StdEncoding.EncodeToString(pubKey.Bytes()),
			base64.StdEncoding.EncodeToString(make([]byte, cmted25519.SeedSize)),
		)
		require.NoError(t, os.WriteFile(path, []byte(serialized), 0o600))

		_, _, err := loadLocalEd25519PrivValidatorKey(path)
		require.ErrorContains(t, err, "invalid ed25519 length")
	})

	t.Run("public key mismatch", func(t *testing.T) {
		privateKey := cmted25519.GenPrivKey()
		otherPrivateKey := cmted25519.GenPrivKey()
		path := filepath.Join(t.TempDir(), "priv_validator_key.json")
		fileKey := privval.FilePVKey{
			Address: privateKey.PubKey().Address(),
			PubKey:  otherPrivateKey.PubKey(),
			PrivKey: privateKey,
		}
		keyJSON, err := cmtjson.MarshalIndent(fileKey, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, keyJSON, 0o600))

		_, _, err = loadLocalEd25519PrivValidatorKey(path)
		require.ErrorContains(t, err, "public key that does not match")
	})
}

func TestConfigureLocalValidatorSigningKey(t *testing.T) {
	t.Run("configures existing local key", func(t *testing.T) {
		home := t.TempDir()
		privateKey := cmted25519.GenPrivKey()
		keyPath := filepath.Join(home, "custom", "validator.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(keyPath), 0o700))
		writePrivValidatorKeyFileAt(t, keyPath, privateKey, 0o600)
		setter := &recordingValidatorSigningKeySetter{}

		err := configureLocalValidatorSigningKey(setter, sims.AppOptionsMap{
			flags.FlagHome:            home,
			"priv_validator_key_file": filepath.Join("custom", "validator.json"),
		})
		require.NoError(t, err)
		require.Equal(t, 1, setter.calls)
		require.Equal(t, privateKey.Bytes(), setter.key)
	})

	t.Run("does not configure a missing optional key", func(t *testing.T) {
		setter := &recordingValidatorSigningKeySetter{}
		err := configureLocalValidatorSigningKey(setter, sims.AppOptionsMap{
			flags.FlagHome: t.TempDir(),
		})
		require.NoError(t, err)
		require.Zero(t, setter.calls)
	})

	t.Run("rejects remote private validator", func(t *testing.T) {
		setter := &recordingValidatorSigningKeySetter{}
		err := configureLocalValidatorSigningKey(setter, sims.AppOptionsMap{
			"priv_validator_laddr": "tcp://127.0.0.1:1234",
		})
		require.ErrorContains(t, err, "remote CometBFT private validator")
		require.ErrorContains(t, err, "not supported")
		require.Zero(t, setter.calls)
	})

	t.Run("propagates setter errors", func(t *testing.T) {
		home := t.TempDir()
		keyPath := filepath.Join(home, defaultPrivValidatorKeyFile)
		require.NoError(t, os.MkdirAll(filepath.Dir(keyPath), 0o700))
		writePrivValidatorKeyFileAt(t, keyPath, cmted25519.GenPrivKey(), 0o600)
		setter := &recordingValidatorSigningKeySetter{err: fmt.Errorf("rejected")}

		err := configureLocalValidatorSigningKey(setter, sims.AppOptionsMap{
			flags.FlagHome: home,
		})
		require.ErrorContains(t, err, "rejected")
		require.Equal(t, 1, setter.calls)
	})
}

func writePrivValidatorKeyFile(
	t *testing.T,
	privateKey cmtcrypto.PrivKey,
	mode os.FileMode,
) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "priv_validator_key.json")
	writePrivValidatorKeyFileAt(t, path, privateKey, mode)
	return path
}

func writePrivValidatorKeyFileAt(
	t *testing.T,
	path string,
	privateKey cmtcrypto.PrivKey,
	mode os.FileMode,
) {
	t.Helper()
	publicKey := privateKey.PubKey()
	fileKey := privval.FilePVKey{
		Address: publicKey.Address(),
		PubKey:  publicKey,
		PrivKey: privateKey,
	}
	keyJSON, err := cmtjson.MarshalIndent(fileKey, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, keyJSON, mode))
	require.NoError(t, os.Chmod(path, mode))
}
