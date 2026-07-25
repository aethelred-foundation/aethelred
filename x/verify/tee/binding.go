package tee

import (
	"crypto/sha256"
	"encoding/binary"
)

const attestationBindingDomain = "aethelred_tee_output_binding_v1:"

// ComputeAttestationUserData binds an enclave output to one chain height.
// The returned digest is the exact value that must be placed inside the
// hardware-signed attestation document.
func ComputeAttestationUserData(outputHash []byte, blockHeight int64, chainID string) []byte {
	h := sha256.New()
	h.Write([]byte(attestationBindingDomain))
	h.Write(outputHash)
	var height [8]byte
	// #nosec G115 -- consensus heights use their canonical two's-complement LE64 representation.
	binary.LittleEndian.PutUint64(height[:], uint64(blockHeight))
	h.Write(height[:])
	h.Write([]byte(chainID))
	return h.Sum(nil)
}
