// Package crypto provides cryptographic utilities.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256 computes the SHA-256 hash.
func SHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// SHA256Hex computes the SHA-256 hash and returns it as a hex string.
func SHA256Hex(data []byte) string {
	return hex.EncodeToString(SHA256(data))
}

// ToHex converts bytes to hex string.
func ToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// FromHex converts hex string to bytes.
func FromHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
