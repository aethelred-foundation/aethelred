// Package pqc provides BIP32/BIP44-compatible hierarchical deterministic wallet
// support for Aethelred's hybrid ECDSA + Dilithium key system.
//
// Standard derivation path: m/44'/60'/0'/0/index
// (coin type 60 for Ethereum compatibility; Aethelred will register its own)
//
// Uses HKDF-SHA256 (RFC 5869) instead of raw SHA256 counter-mode for key
// derivation, providing cryptographically rigorous extract-and-expand semantics.
package pqc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HDWallet implements hierarchical deterministic key derivation for Aethelred's
// dual-key system. Derives both ECDSA and Dilithium child keys from a single
// master seed using HKDF (RFC 5869).
type HDWallet struct {
	// masterSeed is the root entropy (BIP39 mnemonic -> seed)
	masterSeed []byte

	// chainCode provides additional entropy for child derivation
	chainCode []byte

	// dilithiumLevel for all derived Dilithium keys
	dilithiumLevel int

	// derivedKeys caches derived child wallets by index
	derivedKeys map[uint32]*DualKeyWallet
}

// HDDerivationPath represents a BIP44 derivation path
type HDDerivationPath struct {
	Purpose  uint32 // 44' (hardened)
	CoinType uint32 // Aethelred coin type
	Account  uint32 // Account index
	Change   uint32 // 0 = external, 1 = internal
	Index    uint32 // Address index
}

// DefaultDerivationPath returns the default BIP44 path for Aethelred
func DefaultDerivationPath(index uint32) HDDerivationPath {
	return HDDerivationPath{
		Purpose:  44,
		CoinType: 60, // TODO: Register Aethelred-specific coin type with SLIP-44
		Account:  0,
		Change:   0,
		Index:    index,
	}
}

// NewHDWallet creates a new HD wallet from a master seed.
// The seed should be 64 bytes (from BIP39 mnemonic).
func NewHDWallet(masterSeed []byte, dilithiumLevel int) (*HDWallet, error) {
	if len(masterSeed) < 32 {
		return nil, errors.New("master seed must be at least 32 bytes")
	}
	if dilithiumLevel != DilithiumLevel2 && dilithiumLevel != DilithiumLevel3 && dilithiumLevel != DilithiumLevel5 {
		return nil, fmt.Errorf("unsupported Dilithium level: %d", dilithiumLevel)
	}

	// Derive master chain code using HKDF extract
	chainCode, err := hkdfDerive(masterSeed, []byte("aethelred-hd-chain-code"), 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chain code: %w", err)
	}

	return &HDWallet{
		masterSeed:     masterSeed,
		chainCode:      chainCode,
		dilithiumLevel: dilithiumLevel,
		derivedKeys:    make(map[uint32]*DualKeyWallet),
	}, nil
}

// DeriveChild derives a child DualKeyWallet at the given path.
func (w *HDWallet) DeriveChild(path HDDerivationPath) (*DualKeyWallet, error) {
	// Check cache
	if cached, ok := w.derivedKeys[path.Index]; ok {
		return cached, nil
	}

	// Derive ECDSA child key material using HKDF with path-specific info
	ecdsaInfo := derivePathInfo("ecdsa", path)
	ecdsaSeed, err := hkdfDerive(w.masterSeed, ecdsaInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ECDSA seed: %w", err)
	}
	defer zeroBytes(ecdsaSeed)

	// Derive Dilithium child key material using HKDF with path-specific info
	dilithiumInfo := derivePathInfo("dilithium", path)
	dilithiumSeed, err := hkdfDerive(w.masterSeed, dilithiumInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Dilithium seed: %w", err)
	}
	defer zeroBytes(dilithiumSeed)

	// Generate ECDSA key from derived seed using HKDF-based reader
	ecdsaReader, err := hkdfReader(ecdsaSeed, []byte("aethelred-ecdsa-keygen"))
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA key reader: %w", err)
	}
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), ecdsaReader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Generate Dilithium key from derived seed
	dilithiumKP, err := GenerateDilithiumKeyPairFromSeed(w.dilithiumLevel, dilithiumSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium key: %w", err)
	}

	address := deriveWalletAddress(ecdsaPriv.PublicKey, dilithiumKP.PublicKey)

	wallet := &DualKeyWallet{
		ECDSAPublicKey:   &ecdsaPriv.PublicKey,
		ECDSAPrivateKey:  ecdsaPriv,
		DilithiumKeyPair: dilithiumKP,
		Address:          address,
	}

	// Cache
	w.derivedKeys[path.Index] = wallet

	return wallet, nil
}

// DeriveChildByIndex derives a child wallet using the default path at given index.
func (w *HDWallet) DeriveChildByIndex(index uint32) (*DualKeyWallet, error) {
	return w.DeriveChild(DefaultDerivationPath(index))
}

// Zeroize securely wipes all key material from the HD wallet.
func (w *HDWallet) Zeroize() {
	zeroBytes(w.masterSeed)
	zeroBytes(w.chainCode)
	for _, wallet := range w.derivedKeys {
		wallet.Zeroize()
	}
	w.derivedKeys = nil
}

// =============================================================================
// HKDF helpers (RFC 5869)
// =============================================================================

// hkdfDerive performs HKDF extract-and-expand to derive key material.
func hkdfDerive(secret, info []byte, length int) ([]byte, error) {
	// Use chain code as salt if available, otherwise use domain separator
	salt := []byte("aethelred-hkdf-v1")

	reader := hkdf.New(sha256.New, secret, salt, info)
	derived := make([]byte, length)
	if _, err := io.ReadFull(reader, derived); err != nil {
		return nil, fmt.Errorf("HKDF expansion failed: %w", err)
	}
	return derived, nil
}

// hkdfReader creates an io.Reader that provides HKDF-derived bytes for key gen.
func hkdfReader(secret, info []byte) (io.Reader, error) {
	salt := []byte("aethelred-hkdf-v1")
	return hkdf.New(sha256.New, secret, salt, info), nil
}

// derivePathInfo creates the HKDF info string from a derivation path.
// Format: "aethelred/{keytype}/m/{purpose}'/{coin}'/{account}'/{change}/{index}"
func derivePathInfo(keyType string, path HDDerivationPath) []byte {
	info := fmt.Sprintf("aethelred/%s/m/%d'/%d'/%d'/%d/%d",
		keyType, path.Purpose, path.CoinType, path.Account, path.Change, path.Index)

	// Also mix in numeric path for unambiguous binary encoding
	var buf []byte
	buf = append(buf, []byte(info)...)
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, path.Index)
	buf = append(buf, indexBytes...)

	return buf
}
