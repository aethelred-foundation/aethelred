package confidential

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// fhe.go implements a REAL fully-homomorphic-encryption backend over the CKKS
// scheme (Lattigo v6). The client encrypts its input under its own secret key;
// the engine evaluates a registered linear model (y = W·x + b) directly on the
// ciphertext and returns an encrypted result. The evaluating operator NEVER
// holds the secret key, so DataSealed = true is a genuine cryptographic claim,
// not an assertion of trust.
//
// Honest scope (see LinearModel): affine inference at depth 1 — one
// ciphertext×plaintext multiply, one rescale, one rotation inner-sum per output
// row. Deep networks under FHE are frontier and are not claimed. FHE alone
// proves confidentiality, not correctness, so the attestation reports
// Verification = none; a policy that also demands zkML/Freivalds needs a
// verification layer on top.
//
// Parameters: LogN = 13 (ring degree 8192, 4096 slots), LogQP = 55+45+61 = 161
// ≤ 218, the homomorphicencryption.org 128-bit bound for N = 8192 — a genuine
// 128-bit-secure parameter set, not a toy ring.

// fheParametersLiteral is the fixed CKKS parameter set for the engine. Both the
// client and the engine derive their parameters from this literal, so the
// ciphertext format is unambiguous.
func fheParametersLiteral() ckks.ParametersLiteral {
	return ckks.ParametersLiteral{
		LogN:            13,
		Q:               []uint64{0x80000000080001, 0x2000000a0001}, // 55 + 45 bits: depth-1 circuit
		P:               []uint64{0x1fffffffffe00001},               // 61-bit key-switching modulus
		LogDefaultScale: 45,
	}
}

// fheParamsHash commits to the exact CKKS parameter set (ring degree, moduli,
// scale). Folded into the attestation measurement so a verifier knows the
// security level the computation ran at.
func fheParamsHash(p ckks.Parameters) []byte {
	h := sha256.New()
	h.Write([]byte("ceap/fhe-params/v1;"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(p.LogN()))
	h.Write(buf[:])
	for _, q := range p.Q() {
		binary.BigEndian.PutUint64(buf[:], q)
		h.Write(buf[:])
	}
	for _, pp := range p.P() {
		binary.BigEndian.PutUint64(buf[:], pp)
		h.Write(buf[:])
	}
	binary.BigEndian.PutUint64(buf[:], uint64(p.LogDefaultScale()))
	h.Write(buf[:])
	return h.Sum(nil)
}

// ── Client side ───────────────────────────────────────────────────────────────

// FHEClient holds the data owner's key material. The secret key never leaves
// the client; the engine receives only the public evaluation keys.
type FHEClient struct {
	params    ckks.Parameters
	sk        *rlwe.SecretKey
	encoder   *ckks.Encoder
	encryptor *rlwe.Encryptor
	decryptor *rlwe.Decryptor
	evk       *rlwe.MemEvaluationKeySet
}

// NewFHEClient generates fresh CKKS key material: a secret key (kept), and the
// Galois keys the engine needs for rotation inner-sums (shared). maxDim bounds
// the input dimension the Galois keys support.
func NewFHEClient(maxDim int) (*FHEClient, error) {
	if maxDim < 1 {
		return nil, fmt.Errorf("fhe: maxDim must be >= 1, got %d", maxDim)
	}
	params, err := ckks.NewParametersFromLiteral(fheParametersLiteral())
	if err != nil {
		return nil, fmt.Errorf("fhe: parameters: %w", err)
	}
	if maxDim+1 > params.MaxSlots() {
		return nil, fmt.Errorf("fhe: maxDim %d exceeds slot capacity %d", maxDim, params.MaxSlots()-1)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	// Galois keys for the inner-sum over maxDim+1 slots (+1 for the homogeneous
	// bias coordinate).
	galEls := rlwe.GaloisElementsForInnerSum(params, 1, maxDim+1)
	gks := kgen.GenGaloisKeysNew(galEls, sk)
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)

	return &FHEClient{
		params:    params,
		sk:        sk,
		encoder:   ckks.NewEncoder(params),
		encryptor: rlwe.NewEncryptor(params, sk),
		decryptor: rlwe.NewDecryptor(params, sk),
		evk:       evk,
	}, nil
}

// EvaluationKeys returns the public key material the engine needs (Galois keys
// only — no secret key, no decryption capability).
func (c *FHEClient) EvaluationKeys() *rlwe.MemEvaluationKeySet { return c.evk }

// Encrypt encodes and encrypts an input vector. The homogeneous coordinate 1.0
// is appended automatically so the engine can fold the model bias into the
// weight row (affine as linear).
func (c *FHEClient) Encrypt(x []float64) (EncryptedInput, error) {
	if len(x) == 0 {
		return nil, fmt.Errorf("fhe: empty input vector")
	}
	if len(x)+1 > c.params.MaxSlots() {
		return nil, fmt.Errorf("fhe: input dimension %d exceeds slot capacity", len(x))
	}
	values := make([]float64, len(x)+1)
	copy(values, x)
	values[len(x)] = 1.0 // homogeneous coordinate for the bias

	pt := ckks.NewPlaintext(c.params, c.params.MaxLevel())
	if err := c.encoder.Encode(values, pt); err != nil {
		return nil, fmt.Errorf("fhe: encode: %w", err)
	}
	ct, err := c.encryptor.EncryptNew(pt)
	if err != nil {
		return nil, fmt.Errorf("fhe: encrypt: %w", err)
	}
	data, err := ct.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("fhe: marshal ciphertext: %w", err)
	}
	return EncryptedInput(data), nil
}

// Decrypt recovers the model outputs from the engine's encrypted result: one
// ciphertext per output row, the row's value in slot 0.
func (c *FHEClient) Decrypt(out Output) ([]float64, error) {
	cts, err := readCiphertextFrames(out.Plaintext, out.OutputCommitment)
	if err != nil {
		return nil, err
	}
	results := make([]float64, len(cts))
	values := make([]float64, c.params.MaxSlots())
	for i, ct := range cts {
		pt := c.decryptor.DecryptNew(ct)
		if err := c.encoder.Decode(pt, values); err != nil {
			return nil, fmt.Errorf("fhe: decode output %d: %w", i, err)
		}
		results[i] = values[0]
	}
	return results, nil
}

// ── Engine (server side) ──────────────────────────────────────────────────────

// FHEEngine evaluates registered linear models homomorphically. It holds only
// public material: CKKS parameters, the client's evaluation (Galois) keys, and
// the model weights. It cannot decrypt anything.
type FHEEngine struct {
	params    ckks.Parameters
	encoder   *ckks.Encoder
	evaluator *ckks.Evaluator
	models    map[string]LinearModel
}

// NewFHEEngine builds an engine from the client's public evaluation keys.
func NewFHEEngine(evk rlwe.EvaluationKeySet) (*FHEEngine, error) {
	params, err := ckks.NewParametersFromLiteral(fheParametersLiteral())
	if err != nil {
		return nil, fmt.Errorf("fhe: parameters: %w", err)
	}
	if evk == nil {
		return nil, fmt.Errorf("fhe: evaluation keys required (Galois keys for inner-sum)")
	}
	return &FHEEngine{
		params:    params,
		encoder:   ckks.NewEncoder(params),
		evaluator: ckks.NewEvaluator(params, evk),
		models:    make(map[string]LinearModel),
	}, nil
}

// RegisterModel adds a linear model the engine may execute. The model is
// validated and its canonical hash becomes the commitment checked against
// ModelRef at execution time.
func (e *FHEEngine) RegisterModel(m LinearModel) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.InputDim()+1 > e.params.MaxSlots() {
		return fmt.Errorf("fhe: model %q input dimension %d exceeds slot capacity", m.ID, m.InputDim())
	}
	e.models[m.ID] = m
	return nil
}

// Evaluate runs y = W·x + b homomorphically. Per output row: encode the weight
// row (with the bias in the homogeneous slot), multiply into the ciphertext,
// rescale, and rotation-sum the first n+1 slots so slot 0 carries the affine
// output. The result is one ciphertext per row — still encrypted under the
// client's key.
func (e *FHEEngine) Evaluate(in EncryptedInput, ref ModelRef) ([]byte, []byte, error) {
	model, err := checkModelRef(e.models, ref)
	if err != nil {
		return nil, nil, err
	}

	ct, err := safeUnmarshalCiphertext(in)
	if err != nil {
		return nil, nil, fmt.Errorf("fhe: unmarshal input ciphertext: %w", err)
	}

	n := model.InputDim()
	var out []byte
	rowValues := make([]float64, n+1)
	for i, row := range model.Weights {
		copy(rowValues, row)
		rowValues[n] = model.Bias[i] // bias rides the homogeneous 1.0 slot

		pt := ckks.NewPlaintext(e.params, ct.Level())
		if err := e.encoder.Encode(rowValues, pt); err != nil {
			return nil, nil, fmt.Errorf("fhe: encode weight row %d: %w", i, err)
		}

		// ct × pt stays degree 1 — no relinearization key needed.
		prod, err := e.evaluator.MulNew(ct, pt)
		if err != nil {
			return nil, nil, fmt.Errorf("fhe: multiply row %d: %w", i, err)
		}
		if err := e.evaluator.Rescale(prod, prod); err != nil {
			return nil, nil, fmt.Errorf("fhe: rescale row %d: %w", i, err)
		}

		// Rotation inner-sum: slot 0 of sum accumulates slots 0..n.
		sum := prod.CopyNew()
		if err := e.evaluator.PartialTracesSum(prod, 1, n+1, sum); err != nil {
			return nil, nil, fmt.Errorf("fhe: inner sum row %d: %w", i, err)
		}

		data, err := sum.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("fhe: marshal output row %d: %w", i, err)
		}
		out = appendFrame(out, data)
	}

	measurement := fheMeasurement(e.params, model)
	return out, measurement, nil
}

// fheMeasurement is the attestation measurement for an FHE execution: the hash
// of the exact parameter set and the exact model weights (the proto documents
// this field as "launch/firmware measurement or FHE circuit/param hash").
func fheMeasurement(params ckks.Parameters, model LinearModel) []byte {
	h := sha256.New()
	h.Write([]byte("ceap/fhe-measurement/v1;"))
	h.Write(fheParamsHash(params))
	h.Write(model.Hash())
	return h.Sum(nil)
}

// ── Backend adapter ───────────────────────────────────────────────────────────

// fheBackend adapts FHEEngine to the ConfidentialBackend interface.
type fheBackend struct {
	engine       *FHEEngine
	jurisdiction Jurisdiction
	worker       string
}

// NewFHEBackendWithEngine builds the operational FHE backend. jurisdiction and
// worker identify the deployment for the attestation (config-pinned facts, not
// hardware claims).
func NewFHEBackendWithEngine(engine *FHEEngine, jurisdiction Jurisdiction, worker string) (ConfidentialBackend, error) {
	if engine == nil {
		return nil, fmt.Errorf("fhe: engine required")
	}
	return &fheBackend{engine: engine, jurisdiction: jurisdiction, worker: worker}, nil
}

func (f *fheBackend) Kind() Backend    { return BackendFHE }
func (f *fheBackend) Available() error { return nil }

// SatisfiesPlatform: FHE is a cryptographic boundary, not a hardware one — it
// attests no platform. Policies that pin platforms cannot be satisfied by FHE
// (fail closed), which is the honest answer.
func (f *fheBackend) SatisfiesPlatform(Platform) bool { return false }

func (f *fheBackend) Prepare(_ context.Context, _ ConfidentialityPolicy) (Session, error) {
	return noopSession{}, nil
}

func (f *fheBackend) Execute(_ context.Context, _ Session, in EncryptedInput, ref ModelRef) (Output, ConfidentialityAttestation, error) {
	resultBytes, measurement, err := f.engine.Evaluate(in, ref)
	if err != nil {
		return Output{}, ConfidentialityAttestation{}, err
	}
	commitment := sha256.Sum256(resultBytes)
	out := Output{
		OutputCommitment: commitment[:],
		// Plaintext here carries the ENCRYPTED result frames back to the caller —
		// the engine cannot produce plaintext; only the key-holding client can.
		Plaintext: resultBytes,
	}
	att := ConfidentialityAttestation{
		Backend: BackendFHE,
		// FHE proves confidentiality, not correctness. No verification method is
		// claimed; layering zkML/Freivalds on top raises this honestly.
		Verification: VerificationNone,
		Platform:     "", // no hardware attestation — cryptographic boundary only
		Measurement:  measurement,
		TrustBasis:   "", // no silicon root involved; policies requiring one fail closed
		Jurisdiction: f.jurisdiction,
		// Genuine claim: the engine holds no secret key; the input and output are
		// ciphertexts end-to-end on this side of the boundary.
		DataSealed: true,
		Worker:     f.worker,
	}
	return out, att, nil
}

// ── ciphertext framing ────────────────────────────────────────────────────────

// safeUnmarshalCiphertext deserializes an untrusted ciphertext blob. Lattigo's
// UnmarshalBinary PANICS on malformed input (e.g. makeslice out of range), so a
// network-facing worker must recover — an adversarial EncryptedInput must be an
// error, never a crash.
func safeUnmarshalCiphertext(data []byte) (ct *rlwe.Ciphertext, err error) {
	defer func() {
		if r := recover(); r != nil {
			ct, err = nil, fmt.Errorf("malformed ciphertext: %v", r)
		}
	}()
	ct = new(rlwe.Ciphertext)
	if uErr := ct.UnmarshalBinary(data); uErr != nil {
		return nil, uErr
	}
	return ct, nil
}

// appendFrame length-prefixes a blob (uint32 big-endian) onto dst.
func appendFrame(dst, data []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(data)))
	dst = append(dst, l[:]...)
	return append(dst, data...)
}

// readCiphertextFrames parses length-prefixed ciphertexts and verifies the
// bundle against the output commitment — the client checks it decrypts exactly
// what was committed on-chain.
func readCiphertextFrames(data []byte, commitment []byte) ([]*rlwe.Ciphertext, error) {
	if len(commitment) > 0 {
		sum := sha256.Sum256(data)
		if !bytesEqual(sum[:], commitment) {
			return nil, fmt.Errorf("fhe: output does not match commitment")
		}
	}
	var cts []*rlwe.Ciphertext
	for off := 0; off < len(data); {
		if off+4 > len(data) {
			return nil, fmt.Errorf("fhe: truncated frame header at offset %d", off)
		}
		l := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+l > len(data) {
			return nil, fmt.Errorf("fhe: truncated frame at offset %d", off)
		}
		ct, err := safeUnmarshalCiphertext(data[off : off+l])
		if err != nil {
			return nil, fmt.Errorf("fhe: unmarshal frame: %w", err)
		}
		cts = append(cts, ct)
		off += l
	}
	if len(cts) == 0 {
		return nil, fmt.Errorf("fhe: no ciphertext frames in output")
	}
	return cts, nil
}
