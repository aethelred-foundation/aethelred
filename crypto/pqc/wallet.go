// Package pqc implements DualKeyWallet for composite ECDSA + Dilithium signatures
package pqc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/argon2"
)

// DualKeyWallet manages both classical ECDSA and post-quantum Dilithium keys
type DualKeyWallet struct {
	// Classical ECDSA key (secp256k1)
	ECDSAPublicKey  *ecdsa.PublicKey
	ECDSAPrivateKey *ecdsa.PrivateKey

	// Post-quantum Dilithium key
	DilithiumKeyPair *DilithiumKeyPair

	// Wallet address derived from both keys
	Address []byte
}

// CompositeSignature contains both classical and PQC signatures
type CompositeSignature struct {
	ECDSASignature     []byte
	DilithiumSignature *DilithiumSignature
	MessageHash        [32]byte
}

// SignatureScheme defines which signatures are required
type SignatureScheme int

const (
	// ECDSAOnly uses only classical ECDSA signature
	ECDSAOnly SignatureScheme = iota
	// DilithiumOnly uses only post-quantum Dilithium signature
	DilithiumOnly
	// CompositeScheme uses both ECDSA and Dilithium (recommended)
	CompositeScheme
)

// NewDualKeyWallet creates a new wallet with both ECDSA and Dilithium keys
func NewDualKeyWallet(dilithiumLevel int) (*DualKeyWallet, error) {
	// Generate ECDSA key pair (using P-256 as a stand-in for secp256k1)
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Generate Dilithium key pair
	dilithiumKP, err := GenerateDilithiumKeyPair(dilithiumLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium key: %w", err)
	}

	// Derive address from both public keys
	address := deriveWalletAddress(ecdsaPriv.PublicKey, dilithiumKP.PublicKey)

	return &DualKeyWallet{
		ECDSAPublicKey:   &ecdsaPriv.PublicKey,
		ECDSAPrivateKey:  ecdsaPriv,
		DilithiumKeyPair: dilithiumKP,
		Address:          address,
	}, nil
}

// NewDualKeyWalletFromSeed creates a wallet from deterministic seeds
func NewDualKeyWalletFromSeed(ecdsaSeed, dilithiumSeed []byte, dilithiumLevel int) (*DualKeyWallet, error) {
	if len(ecdsaSeed) < 32 {
		return nil, errors.New("ECDSA seed must be at least 32 bytes")
	}
	if len(dilithiumSeed) < 32 {
		return nil, errors.New("Dilithium seed must be at least 32 bytes")
	}

	// Generate ECDSA key from seed
	h := sha256.Sum256(ecdsaSeed)
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), &deterministicReader{seed: h[:]})
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key from seed: %w", err)
	}

	// Generate Dilithium key from seed
	dilithiumKP, err := GenerateDilithiumKeyPairFromSeed(dilithiumLevel, dilithiumSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium key from seed: %w", err)
	}

	address := deriveWalletAddress(ecdsaPriv.PublicKey, dilithiumKP.PublicKey)

	return &DualKeyWallet{
		ECDSAPublicKey:   &ecdsaPriv.PublicKey,
		ECDSAPrivateKey:  ecdsaPriv,
		DilithiumKeyPair: dilithiumKP,
		Address:          address,
	}, nil
}

// deterministicReader provides deterministic "random" bytes from a seed
type deterministicReader struct {
	seed    []byte
	counter int
}

func (r *deterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		h := sha256.New()
		h.Write(r.seed)
		_ = binary.Write(h, binary.BigEndian, int64(r.counter)) // writing to hash.Hash cannot fail
		sum := h.Sum(nil)
		p[i] = sum[0]
		r.counter++
	}
	return len(p), nil
}

// deriveWalletAddress derives address from both public keys
func deriveWalletAddress(ecdsaPub ecdsa.PublicKey, dilithiumPub []byte) []byte {
	h := sha256.New()
	h.Write([]byte("aethelred-dual-wallet"))
	h.Write(elliptic.Marshal(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)) //nolint:staticcheck // elliptic.Marshal is the only way to serialize ecdsa.PublicKey; ecdh migration requires API changes
	h.Write(dilithiumPub)
	return h.Sum(nil)[:20] // 20-byte address (160 bits)
}

// Sign creates a composite signature for a message
func (w *DualKeyWallet) Sign(message []byte, scheme SignatureScheme) (*CompositeSignature, error) {
	msgHash := sha256.Sum256(message)
	sig := &CompositeSignature{
		MessageHash: msgHash,
	}

	switch scheme {
	case ECDSAOnly:
		ecdsaSig, err := w.signECDSA(msgHash[:])
		if err != nil {
			return nil, err
		}
		sig.ECDSASignature = ecdsaSig

	case DilithiumOnly:
		dilithiumSig, err := w.DilithiumKeyPair.Sign(message)
		if err != nil {
			return nil, err
		}
		sig.DilithiumSignature = dilithiumSig

	case CompositeScheme:
		ecdsaSig, err := w.signECDSA(msgHash[:])
		if err != nil {
			return nil, err
		}
		sig.ECDSASignature = ecdsaSig

		dilithiumSig, err := w.DilithiumKeyPair.Sign(message)
		if err != nil {
			return nil, err
		}
		sig.DilithiumSignature = dilithiumSig

	default:
		return nil, errors.New("unsupported signature scheme")
	}

	return sig, nil
}

// signECDSA creates an ECDSA signature with canonical S normalization.
//
// SECURITY: Enforces low-S signatures (S <= N/2) to prevent signature
// malleability. Without this, an attacker can transform any valid signature
// (r, s) into another valid signature (r, N-s) for the same message, enabling
// transaction ID mutation attacks. This is equivalent to Bitcoin's BIP-62 and
// Ethereum's EIP-2.
func (w *DualKeyWallet) signECDSA(hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, w.ECDSAPrivateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// Enforce canonical (low-S) signature: if S > N/2, replace S with N - S.
	// Both (r, s) and (r, N-s) are mathematically valid ECDSA signatures,
	// so we normalize to the lower value to ensure a unique representation.
	curveOrder := w.ECDSAPrivateKey.Curve.Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1) // N/2
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	// Encode r || s in fixed 64-byte format
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return sig, nil
}

// Verify verifies a composite signature
func (w *DualKeyWallet) Verify(message []byte, sig *CompositeSignature, scheme SignatureScheme) (bool, error) {
	msgHash := sha256.Sum256(message)

	// Verify message hash matches using constant-time comparison
	if subtle.ConstantTimeCompare(msgHash[:], sig.MessageHash[:]) != 1 {
		return false, errors.New("message hash mismatch")
	}

	switch scheme {
	case ECDSAOnly:
		if sig.ECDSASignature == nil {
			return false, errors.New("missing ECDSA signature")
		}
		return w.verifyECDSA(msgHash[:], sig.ECDSASignature), nil

	case DilithiumOnly:
		if sig.DilithiumSignature == nil {
			return false, errors.New("missing Dilithium signature")
		}
		return sig.DilithiumSignature.Verify(w.DilithiumKeyPair.PublicKey, message)

	case CompositeScheme:
		if sig.ECDSASignature == nil || sig.DilithiumSignature == nil {
			return false, errors.New("missing signature component")
		}

		ecdsaValid := w.verifyECDSA(msgHash[:], sig.ECDSASignature)
		if !ecdsaValid {
			return false, nil
		}

		dilithiumValid, err := sig.DilithiumSignature.Verify(w.DilithiumKeyPair.PublicKey, message)
		if err != nil {
			return false, err
		}

		return dilithiumValid, nil

	default:
		return false, errors.New("unsupported signature scheme")
	}
}

// verifyECDSA verifies an ECDSA signature, rejecting non-canonical (high-S) signatures.
//
// SECURITY: Rejects signatures where S > N/2 to prevent signature malleability.
// All valid signatures produced by signECDSA() use canonical low-S form.
// Accepting both forms would allow transaction ID mutation.
func (w *DualKeyWallet) verifyECDSA(hash, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	// Reject non-canonical (high-S) signatures
	curveOrder := w.ECDSAPublicKey.Curve.Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		return false
	}

	return ecdsa.Verify(w.ECDSAPublicKey, hash, r, s)
}

// GetAddress returns the wallet address
func (w *DualKeyWallet) GetAddress() []byte {
	return w.Address
}

// GetAddressHex returns the wallet address as hex string
func (w *DualKeyWallet) GetAddressHex() string {
	return fmt.Sprintf("0x%x", w.Address)
}

// GetECDSAPublicKeyBytes returns the ECDSA public key bytes
func (w *DualKeyWallet) GetECDSAPublicKeyBytes() []byte {
	return elliptic.Marshal(w.ECDSAPublicKey.Curve, w.ECDSAPublicKey.X, w.ECDSAPublicKey.Y) //nolint:staticcheck // elliptic.Marshal is the only way to serialize ecdsa.PublicKey; ecdh migration requires API changes
}

// GetDilithiumPublicKeyBytes returns the Dilithium public key bytes
func (w *DualKeyWallet) GetDilithiumPublicKeyBytes() []byte {
	return w.DilithiumKeyPair.PublicKey
}

// serializePlaintext serializes the wallet key material into raw bytes.
// This is an internal method used only by SerializeEncrypted. The plaintext
// is immediately encrypted and wiped. Never expose this output directly.
func (w *DualKeyWallet) serializePlaintext() ([]byte, error) {
	ecdsaPrivBytes := w.ECDSAPrivateKey.D.Bytes()
	dilithiumBytes := w.DilithiumKeyPair.Serialize()

	// Format: ecdsaLen(4) + ecdsaPriv + dilithiumBytes
	data := make([]byte, 4+len(ecdsaPrivBytes)+len(dilithiumBytes))
	binary.BigEndian.PutUint32(data[:4], uint32(len(ecdsaPrivBytes)))
	copy(data[4:4+len(ecdsaPrivBytes)], ecdsaPrivBytes)
	copy(data[4+len(ecdsaPrivBytes):], dilithiumBytes)

	return data, nil
}

// DeserializeDualKeyWallet deserializes a wallet from bytes
func DeserializeDualKeyWallet(data []byte) (*DualKeyWallet, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short")
	}

	ecdsaLen := binary.BigEndian.Uint32(data[:4])
	if len(data) < int(4+ecdsaLen) {
		return nil, errors.New("data too short for ECDSA key")
	}

	ecdsaPrivBytes := data[4 : 4+ecdsaLen]
	dilithiumBytes := data[4+ecdsaLen:]

	// Reconstruct ECDSA key
	ecdsaPriv := new(ecdsa.PrivateKey)
	ecdsaPriv.PublicKey.Curve = elliptic.P256()
	ecdsaPriv.D = new(big.Int).SetBytes(ecdsaPrivBytes)
	ecdsaPriv.PublicKey.X, ecdsaPriv.PublicKey.Y = ecdsaPriv.PublicKey.Curve.ScalarBaseMult(ecdsaPrivBytes)

	// Reconstruct Dilithium key
	dilithiumKP, err := DeserializeDilithiumKeyPair(dilithiumBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Dilithium key: %w", err)
	}

	address := deriveWalletAddress(ecdsaPriv.PublicKey, dilithiumKP.PublicKey)

	return &DualKeyWallet{
		ECDSAPublicKey:   &ecdsaPriv.PublicKey,
		ECDSAPrivateKey:  ecdsaPriv,
		DilithiumKeyPair: dilithiumKP,
		Address:          address,
	}, nil
}

// SignTransaction signs a transaction with composite signature
func (w *DualKeyWallet) SignTransaction(txBytes []byte) (*CompositeSignature, error) {
	return w.Sign(txBytes, CompositeScheme)
}

// VerifyTransaction verifies a transaction signature
func VerifyTransactionSignature(
	ecdsaPubKey *ecdsa.PublicKey,
	dilithiumPubKey []byte,
	txBytes []byte,
	sig *CompositeSignature,
) (bool, error) {
	msgHash := sha256.Sum256(txBytes)

	// Verify message hash using constant-time comparison
	if subtle.ConstantTimeCompare(msgHash[:], sig.MessageHash[:]) != 1 {
		return false, errors.New("message hash mismatch")
	}

	// Verify ECDSA with canonical S enforcement
	if len(sig.ECDSASignature) == 64 {
		r := new(big.Int).SetBytes(sig.ECDSASignature[:32])
		s := new(big.Int).SetBytes(sig.ECDSASignature[32:])

		// Reject non-canonical (high-S) signatures
		curveOrder := ecdsaPubKey.Curve.Params().N
		halfOrder := new(big.Int).Rsh(curveOrder, 1)
		if s.Cmp(halfOrder) > 0 {
			return false, nil
		}

		if !ecdsa.Verify(ecdsaPubKey, msgHash[:], r, s) {
			return false, nil
		}
	}

	// Verify Dilithium
	if sig.DilithiumSignature != nil {
		valid, err := sig.DilithiumSignature.Verify(dilithiumPubKey, txBytes)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// =============================================================================
// Encrypted Key Storage (Critical Fix 3)
// =============================================================================

// Encrypted keystore constants
const (
	// keystoreVersion is the current encrypted keystore format version
	keystoreVersion byte = 0x01

	// Argon2id parameters (OWASP recommended for 2024+)
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32 // AES-256
	argon2SaltLen = 16
)

// SerializeEncrypted serializes the wallet with AES-256-GCM encryption.
//
// The passphrase is stretched via Argon2id to derive a 256-bit AES key.
// The plaintext key material is authenticated and encrypted, preventing both
// unauthorized reading and undetected tampering.
//
// Wire format:
//
//	[version: 1][salt: 16][nonce: 12][ciphertext+tag: variable]
func (w *DualKeyWallet) SerializeEncrypted(passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}

	// Serialize plaintext key material (internal only, immediately encrypted)
	plaintext, err := w.serializePlaintext()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize wallet: %w", err)
	}
	defer zeroBytes(plaintext) // Wipe plaintext from memory after encryption

	// Generate random salt for Argon2id
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key via Argon2id
	key := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(key)

	// Encrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Pack: version(1) + salt(16) + nonce(12) + ciphertext
	result := make([]byte, 0, 1+argon2SaltLen+len(nonce)+len(ciphertext))
	result = append(result, keystoreVersion)
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DeserializeEncryptedDualKeyWallet decrypts and deserializes a wallet.
//
// Returns an error if the passphrase is wrong (GCM authentication failure)
// or the data has been tampered with.
func DeserializeEncryptedDualKeyWallet(data, passphrase []byte) (*DualKeyWallet, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase must not be empty")
	}

	// Minimum size: version(1) + salt(16) + nonce(12) + tag(16) = 45
	if len(data) < 45 {
		return nil, errors.New("encrypted keystore data too short")
	}

	version := data[0]
	if version != keystoreVersion {
		return nil, fmt.Errorf("unsupported keystore version: %d", version)
	}

	salt := data[1 : 1+argon2SaltLen]

	// Derive decryption key via Argon2id with same parameters
	key := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonceStart := 1 + argon2SaltLen
	if len(data) < nonceStart+nonceSize {
		return nil, errors.New("encrypted keystore data too short for nonce")
	}

	nonce := data[nonceStart : nonceStart+nonceSize]
	ciphertext := data[nonceStart+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase or tampered data): %w", err)
	}
	defer zeroBytes(plaintext)

	return DeserializeDualKeyWallet(plaintext)
}

// Zeroize securely wipes all private key material from memory.
// Call this when the wallet is no longer needed.
func (w *DualKeyWallet) Zeroize() {
	if w.ECDSAPrivateKey != nil && w.ECDSAPrivateKey.D != nil {
		// Overwrite the big.Int's internal bytes
		w.ECDSAPrivateKey.D.SetUint64(0)
		w.ECDSAPrivateKey = nil
	}
	if w.DilithiumKeyPair != nil {
		zeroBytes(w.DilithiumKeyPair.PrivateKey)
		w.DilithiumKeyPair.PrivateKey = nil
	}
}

// zeroBytes overwrites a byte slice with zeros
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
