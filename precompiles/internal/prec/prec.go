// Package prec holds the shared, audited glue for Aethelred's precompiled
// contracts (ISeal 0x0900, IVerify 0x0901, IPoUW 0x0902): typed ABI-argument
// extraction and byte-encoding helpers. One implementation, one set of tests —
// three precompiles inherit identical, reviewable input-validation semantics.
package prec

import "fmt"

// StringArg extracts args[i] as a string with a named error.
func StringArg(args []interface{}, i int, name string) (string, error) {
	if i >= len(args) {
		return "", fmt.Errorf("missing argument %s", name)
	}
	s, ok := args[i].(string)
	if !ok {
		return "", fmt.Errorf("argument %s is not a string", name)
	}
	return s, nil
}

// StringSliceArg extracts args[i] as a []string with a named error.
func StringSliceArg(args []interface{}, i int, name string) ([]string, error) {
	if i >= len(args) {
		return nil, fmt.Errorf("missing argument %s", name)
	}
	s, ok := args[i].([]string)
	if !ok {
		return nil, fmt.Errorf("argument %s is not a string[]", name)
	}
	return s, nil
}

// BoolArg extracts args[i] as a bool with a named error.
func BoolArg(args []interface{}, i int, name string) (bool, error) {
	if i >= len(args) {
		return false, fmt.Errorf("missing argument %s", name)
	}
	b, ok := args[i].(bool)
	if !ok {
		return false, fmt.Errorf("argument %s is not a bool", name)
	}
	return b, nil
}

// Bytes32Arg extracts args[i] as a [32]byte (Solidity bytes32) with a named
// error, returned as a byte slice for keeper lookups.
func Bytes32Arg(args []interface{}, i int, name string) ([]byte, error) {
	if i >= len(args) {
		return nil, fmt.Errorf("missing argument %s", name)
	}
	b, ok := args[i].([32]byte)
	if !ok {
		return nil, fmt.Errorf("argument %s is not bytes32", name)
	}
	out := make([]byte, 32)
	copy(out, b[:])
	return out, nil
}

// ToBytes32 copies a hash/commitment into a fixed 32-byte word (zero-padded;
// on-chain commitments are sha256, exactly 32 bytes).
func ToBytes32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

// NonNilBytes maps nil to an empty slice so ABI packing never sees nil.
func NonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
