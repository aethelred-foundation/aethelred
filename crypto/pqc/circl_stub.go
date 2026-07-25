//go:build !pqc_circl

package pqc

// The untagged backend deliberately contains no cryptographic substitutes.
// Public entry points may use the test-only simulated implementation only while
// PQCModeSimulated is active; production and hybrid modes route here and fail.

func circlAvailableImpl() bool {
	return false
}

func generateCirclDilithiumReal(int) (*CirclDilithiumKeyPair, error) {
	return nil, circlRequiredError()
}

func signCirclDilithiumReal(*CirclDilithiumKeyPair, []byte) (*DilithiumSignature, error) {
	return nil, circlRequiredError()
}

func verifyCirclDilithiumReal([]byte, []byte, *DilithiumSignature) (bool, error) {
	return false, circlRequiredError()
}

func generateCirclKyberReal(int) (*CirclKyberKeyPair, error) {
	return nil, circlRequiredError()
}

func encapsulateCirclKyberReal(int, []byte) ([]byte, *KyberCiphertext, error) {
	return nil, nil, circlRequiredError()
}

func decapsulateCirclKyberReal(*CirclKyberKeyPair, *KyberCiphertext) ([]byte, error) {
	return nil, circlRequiredError()
}
