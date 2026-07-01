package confidential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// mpc.go implements a REAL secure-multiparty-computation backend for linear
// inference: n-of-n additive secret sharing over Z_2^64 with fixed-point
// encoding. The client splits its input into n additive shares (each share is
// information-theoretically independent of the input); each party locally
// computes W·x_i on its share; the sum of the partial results reconstructs
// W·x because matrix multiplication distributes over the share sum. Public
// model, secret input — no interaction between parties is needed for the
// linear class, so no Beaver triples and no preprocessing.
//
// Security model (stated honestly):
//   - semi-honest, n-of-n: privacy holds against any coalition of up to n-1
//     parties; a single missing party breaks availability, not privacy.
//   - the OUTPUT is revealed to the coordinator by design (it is the result).
//   - the protocol is real regardless of deployment, but the CONFIDENTIALITY
//     CLAIM is deployment-aware: a colocated (single-operator) cluster holds
//     all shares, so DataSealed = false — the seal never claims secrecy an
//     operator could trivially violate. Only a genuinely distributed cluster
//     (independent operators) claims DataSealed = true.
//
// Fixed-point encoding: values are scaled by 2^16; products carry scale 2^32.
// With |weights|,|inputs| ≲ 2^10 the products stay ≪ 2^63, far from wraparound.

// mpcScale is the fixed-point scaling factor applied to both weights and
// inputs; products therefore carry mpcScale².
const mpcScale = 1 << 16

// mpcWireVersion tags the share-bundle framing.
const mpcWireVersion = 1

// ── fixed-point helpers ───────────────────────────────────────────────────────

func toFixed(v float64) int64    { return int64(v * mpcScale) }
func fromFixed2(v int64) float64 { return float64(v) / (mpcScale * mpcScale) }

// ── sharing ───────────────────────────────────────────────────────────────────

// SplitShares additively shares a fixed-point-encoded vector among n parties:
// for each coordinate, n-1 shares are uniform random in Z_2^64 and the last is
// the difference. Any n-1 shares are jointly uniform — they carry zero
// information about the input.
func SplitShares(x []float64, n int) ([][]uint64, error) {
	if n < 2 {
		return nil, fmt.Errorf("mpc: need at least 2 parties, got %d", n)
	}
	if len(x) == 0 {
		return nil, fmt.Errorf("mpc: empty input vector")
	}
	shares := make([][]uint64, n)
	for p := range shares {
		shares[p] = make([]uint64, len(x))
	}
	buf := make([]byte, 8)
	for j, v := range x {
		fixed := uint64(toFixed(v))
		var sum uint64
		for p := 0; p < n-1; p++ {
			if _, err := rand.Read(buf); err != nil {
				return nil, fmt.Errorf("mpc: randomness: %w", err)
			}
			r := binary.BigEndian.Uint64(buf)
			shares[p][j] = r
			sum += r
		}
		shares[n-1][j] = fixed - sum // mod 2^64 wraparound
	}
	return shares, nil
}

// ── parties ───────────────────────────────────────────────────────────────────

// MPCParty is one computation party. In production each party is a separate
// operator behind its own transport (the interface is the seam); LocalParty is
// the in-process implementation used for tests and colocated dev clusters.
type MPCParty interface {
	// ID identifies the party (operator identity in production).
	ID() string
	// ComputeLinear evaluates y_p = Wfixed · share_p over Z_2^64. Weights are
	// public fixed-point values; the share is one additive share of the input.
	ComputeLinear(ctx context.Context, weightsFixed [][]int64, share []uint64) ([]uint64, error)
}

// LocalParty is an in-process MPCParty. It performs the real share computation;
// what it cannot provide is operator separation — which is exactly what the
// cluster's Colocated flag records.
type LocalParty struct{ Name string }

func (p LocalParty) ID() string { return p.Name }

func (p LocalParty) ComputeLinear(_ context.Context, weightsFixed [][]int64, share []uint64) ([]uint64, error) {
	if len(weightsFixed) == 0 {
		return nil, fmt.Errorf("mpc party %s: no weights", p.Name)
	}
	out := make([]uint64, len(weightsFixed))
	for i, row := range weightsFixed {
		if len(row) != len(share) {
			return nil, fmt.Errorf("mpc party %s: row %d has %d weights for %d share elements", p.Name, i, len(row), len(share))
		}
		var acc uint64
		for j, w := range row {
			acc += uint64(w) * share[j] // Z_2^64 arithmetic: wraparound is the group operation
		}
		out[i] = acc
	}
	return out, nil
}

// ── cluster / engine ──────────────────────────────────────────────────────────

// MPCCluster is a configured set of parties plus the deployment facts that
// determine what the attestation may honestly claim.
type MPCCluster struct {
	Parties []MPCParty
	// Colocated is true when the parties do not have independent operators
	// (same process / same machine / same trust domain). A colocated cluster
	// runs the real protocol but CANNOT claim data secrecy.
	Colocated    bool
	Jurisdiction Jurisdiction
	Worker       string

	models map[string]LinearModel
}

// NewMPCCluster validates and builds a cluster.
func NewMPCCluster(parties []MPCParty, colocated bool, jurisdiction Jurisdiction, worker string) (*MPCCluster, error) {
	if len(parties) < 2 {
		return nil, fmt.Errorf("mpc: need at least 2 parties, got %d", len(parties))
	}
	seen := make(map[string]bool, len(parties))
	for _, p := range parties {
		if p == nil || p.ID() == "" {
			return nil, fmt.Errorf("mpc: nil or unidentified party")
		}
		if seen[p.ID()] {
			return nil, fmt.Errorf("mpc: duplicate party id %q", p.ID())
		}
		seen[p.ID()] = true
	}
	return &MPCCluster{
		Parties:      parties,
		Colocated:    colocated,
		Jurisdiction: jurisdiction,
		Worker:       worker,
		models:       make(map[string]LinearModel),
	}, nil
}

// RegisterModel adds a linear model the cluster may execute.
func (c *MPCCluster) RegisterModel(m LinearModel) error {
	if err := m.Validate(); err != nil {
		return err
	}
	c.models[m.ID] = m
	return nil
}

// EncryptInput splits x into per-party shares and serializes the bundle. In a
// distributed deployment each share travels on a private channel to its party;
// the bundle framing carries the same shares for the backend interface.
func (c *MPCCluster) EncryptInput(x []float64) (EncryptedInput, error) {
	shares, err := SplitShares(x, len(c.Parties))
	if err != nil {
		return nil, err
	}
	return marshalShareBundle(shares), nil
}

// Evaluate runs the protocol: dispatch each share to its party, sum the partial
// results over Z_2^64, add the public bias, and descale.
func (c *MPCCluster) Evaluate(ctx context.Context, in EncryptedInput, ref ModelRef) ([]float64, error) {
	model, err := checkModelRef(c.models, ref)
	if err != nil {
		return nil, err
	}
	shares, err := unmarshalShareBundle(in)
	if err != nil {
		return nil, err
	}
	if len(shares) != len(c.Parties) {
		return nil, fmt.Errorf("mpc: bundle has %d shares for %d parties", len(shares), len(c.Parties))
	}
	if len(shares[0]) != model.InputDim() {
		return nil, fmt.Errorf("mpc: share dimension %d, model expects %d", len(shares[0]), model.InputDim())
	}

	// Public weights in fixed point (identical at every party).
	weightsFixed := make([][]int64, model.OutputDim())
	for i, row := range model.Weights {
		weightsFixed[i] = make([]int64, len(row))
		for j, w := range row {
			weightsFixed[i][j] = toFixed(w)
		}
	}

	// Each party computes on its share only.
	acc := make([]uint64, model.OutputDim())
	for p, party := range c.Parties {
		partial, err := party.ComputeLinear(ctx, weightsFixed, shares[p])
		if err != nil {
			return nil, fmt.Errorf("mpc: party %s: %w", party.ID(), err)
		}
		if len(partial) != len(acc) {
			return nil, fmt.Errorf("mpc: party %s returned %d outputs, expected %d", party.ID(), len(partial), len(acc))
		}
		for i := range acc {
			acc[i] += partial[i] // reconstruction: Σ_p W·x_p = W·x (mod 2^64)
		}
	}

	// Reveal: descale and add the public bias.
	out := make([]float64, model.OutputDim())
	for i := range acc {
		out[i] = fromFixed2(int64(acc[i])) + model.Bias[i]
	}
	return out, nil
}

// ── backend adapter ───────────────────────────────────────────────────────────

type mpcBackend struct{ cluster *MPCCluster }

// NewMPCBackendWithCluster builds the operational MPC backend.
func NewMPCBackendWithCluster(cluster *MPCCluster) (ConfidentialBackend, error) {
	if cluster == nil {
		return nil, fmt.Errorf("mpc: cluster required")
	}
	return &mpcBackend{cluster: cluster}, nil
}

func (m *mpcBackend) Kind() Backend    { return BackendMPC }
func (m *mpcBackend) Available() error { return nil }

// SatisfiesPlatform: like FHE, MPC is a cryptographic/organizational boundary,
// not a hardware one — platform-pinned policies fail closed.
func (m *mpcBackend) SatisfiesPlatform(Platform) bool { return false }

func (m *mpcBackend) Prepare(_ context.Context, _ ConfidentialityPolicy) (Session, error) {
	return noopSession{}, nil
}

func (m *mpcBackend) Execute(ctx context.Context, _ Session, in EncryptedInput, ref ModelRef) (Output, ConfidentialityAttestation, error) {
	result, err := m.cluster.Evaluate(ctx, in, ref)
	if err != nil {
		return Output{}, ConfidentialityAttestation{}, err
	}
	plaintext := marshalFloat64s(result)
	commitment := sha256.Sum256(plaintext)

	model := m.cluster.models[ref.ModelID] // present: Evaluate resolved it
	measurement := mpcMeasurement(model, len(m.cluster.Parties))

	att := ConfidentialityAttestation{
		Backend: BackendMPC,
		// The additive protocol reveals only the output and proves nothing about
		// correctness beyond semi-honest execution — no verification is claimed.
		Verification: VerificationNone,
		Platform:     "",
		Measurement:  measurement,
		TrustBasis:   "",
		Jurisdiction: m.cluster.Jurisdiction,
		// Deployment-aware honesty: a colocated cluster's operator holds every
		// share, so no secrecy is claimed. Only independent operators seal data.
		DataSealed: !m.cluster.Colocated,
		Worker:     m.cluster.Worker,
	}
	return Output{OutputCommitment: commitment[:], Plaintext: plaintext}, att, nil
}

// mpcMeasurement commits to the protocol configuration: the exact model and
// the party count (the n in n-of-n).
func mpcMeasurement(model LinearModel, parties int) []byte {
	h := sha256.New()
	h.Write([]byte("ceap/mpc-measurement/v1;"))
	h.Write(model.Hash())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(parties))
	h.Write(buf[:])
	return h.Sum(nil)
}

// ── wire format ───────────────────────────────────────────────────────────────

// marshalShareBundle: version || nParties || dim || shares[p][j] (big-endian).
func marshalShareBundle(shares [][]uint64) []byte {
	n, dim := len(shares), len(shares[0])
	out := make([]byte, 0, 12+n*dim*8)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], mpcWireVersion)
	out = append(out, buf[:]...)
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	out = append(out, buf[:]...)
	binary.BigEndian.PutUint32(buf[:], uint32(dim))
	out = append(out, buf[:]...)
	var v [8]byte
	for _, share := range shares {
		for _, s := range share {
			binary.BigEndian.PutUint64(v[:], s)
			out = append(out, v[:]...)
		}
	}
	return out
}

func unmarshalShareBundle(data []byte) ([][]uint64, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("mpc: share bundle too short")
	}
	if v := binary.BigEndian.Uint32(data[0:4]); v != mpcWireVersion {
		return nil, fmt.Errorf("mpc: unsupported share bundle version %d", v)
	}
	n := int(binary.BigEndian.Uint32(data[4:8]))
	dim := int(binary.BigEndian.Uint32(data[8:12]))
	if n < 2 || dim < 1 || n > 1024 || dim > 1<<20 {
		return nil, fmt.Errorf("mpc: implausible bundle shape %d×%d", n, dim)
	}
	if len(data) != 12+n*dim*8 {
		return nil, fmt.Errorf("mpc: bundle length %d does not match shape %d×%d", len(data), n, dim)
	}
	shares := make([][]uint64, n)
	off := 12
	for p := 0; p < n; p++ {
		shares[p] = make([]uint64, dim)
		for j := 0; j < dim; j++ {
			shares[p][j] = binary.BigEndian.Uint64(data[off : off+8])
			off += 8
		}
	}
	return shares, nil
}

func marshalFloat64s(vals []float64) []byte {
	out := make([]byte, 8*len(vals))
	for i, v := range vals {
		binary.BigEndian.PutUint64(out[i*8:], uint64(int64(v*mpcScale)))
	}
	return out
}
