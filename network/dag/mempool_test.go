package dag

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func testPeer(id string) peer.ID {
	return peer.ID(id)
}

func TestDAGMempool_AddTransactionAndCreateVertex(t *testing.T) {
	cfg := DefaultDAGConfig()
	cfg.MaxTxsPerVertex = 1

	mp := NewDAGMempool(testPeer("local-validator"), 4, cfg)
	if err := mp.AddTransaction(nil); err == nil {
		t.Fatalf("expected empty transaction to be rejected")
	}

	if err := mp.AddTransaction([]byte("tx-1")); err != nil {
		t.Fatalf("unexpected add tx error: %v", err)
	}
	if err := mp.AddTransaction([]byte("tx-2")); err != nil {
		t.Fatalf("unexpected add tx error: %v", err)
	}

	v, err := mp.CreateVertex(context.Background())
	if err != nil {
		t.Fatalf("unexpected create vertex error: %v", err)
	}
	if v.Round != 0 {
		t.Fatalf("expected round 0, got %d", v.Round)
	}
	if v.Author != testPeer("local-validator") {
		t.Fatalf("unexpected author: %s", v.Author)
	}
	if len(v.Transactions) != 1 {
		t.Fatalf("expected one transaction in vertex, got %d", len(v.Transactions))
	}
	if mp.PendingTxCount() != 1 {
		t.Fatalf("expected one pending tx remaining, got %d", mp.PendingTxCount())
	}
	if _, ok := mp.GetVertex(v.ID); !ok {
		t.Fatalf("created vertex not found in mempool")
	}
}

func TestDAGMempool_CreateVertexRequiresStrongLinksAfterRoundZero(t *testing.T) {
	cfg := DefaultDAGConfig()
	cfg.MinStrongLinks = 1

	mp := NewDAGMempool(testPeer("local-validator"), 4, cfg)
	mp.AdvanceRound() // move to round 1 without any certified round-0 vertices

	if _, err := mp.CreateVertex(context.Background()); err == nil {
		t.Fatalf("expected insufficient strong links error")
	}
}

func TestDAGMempool_AddVertexValidatesIDAndLinks(t *testing.T) {
	mp := NewDAGMempool(testPeer("local-validator"), 4, DefaultDAGConfig())

	// Seed round-0 vertex so round-1 strong link validation can pass.
	base := &Vertex{
		Round:        0,
		Author:       testPeer("local-validator"),
		Transactions: [][]byte{[]byte("seed")},
		Timestamp:    time.Unix(100, 0).UTC(),
	}
	base.ID = mp.calculateVertexID(base)
	mp.addVertex(base)

	remote := &Vertex{
		Round:        1,
		Author:       testPeer("remote-validator"),
		Transactions: [][]byte{[]byte("remote")},
		StrongLinks:  []VertexID{base.ID},
		Timestamp:    time.Unix(101, 0).UTC(),
	}
	remote.ID = mp.calculateVertexID(remote)

	if err := mp.AddVertex(remote); err != nil {
		t.Fatalf("expected valid remote vertex, got error: %v", err)
	}

	bad := *remote
	bad.ID = VertexID{}
	if err := mp.AddVertex(&bad); err == nil {
		t.Fatalf("expected vertex ID mismatch error")
	}
}

func TestDAGMempool_AddCertificateEnforcesQuorum(t *testing.T) {
	mp := NewDAGMempool(testPeer("local-validator"), 4, DefaultDAGConfig()) // quorum=3

	v := &Vertex{
		Round:        0,
		Author:       testPeer("local-validator"),
		Transactions: [][]byte{[]byte("tx")},
		Timestamp:    time.Unix(200, 0).UTC(),
	}
	v.ID = mp.calculateVertexID(v)
	mp.addVertex(v)

	insufficient := &Certificate{
		VertexID: v.ID,
		Round:    0,
		Signatures: map[peer.ID][]byte{
			testPeer("v1"): []byte("sig1"),
			testPeer("v2"): []byte("sig2"),
		},
		Timestamp: time.Unix(201, 0).UTC(),
	}
	if err := mp.AddCertificate(insufficient); err == nil {
		t.Fatalf("expected insufficient signatures error")
	}

	valid := &Certificate{
		VertexID: v.ID,
		Round:    0,
		Signatures: map[peer.ID][]byte{
			testPeer("v1"): []byte("sig1"),
			testPeer("v2"): []byte("sig2"),
			testPeer("v3"): []byte("sig3"),
		},
		Timestamp: time.Unix(202, 0).UTC(),
	}
	if err := mp.AddCertificate(valid); err != nil {
		t.Fatalf("expected certificate to be accepted, got %v", err)
	}
	if _, ok := mp.GetCertificate(v.ID); !ok {
		t.Fatalf("certificate not stored")
	}
}

func TestDAGMempool_AdvanceRoundGarbageCollectsOldRounds(t *testing.T) {
	cfg := DefaultDAGConfig()
	cfg.RetentionRounds = 1

	mp := NewDAGMempool(testPeer("local-validator"), 4, cfg)

	v0 := &Vertex{
		Round:        0,
		Author:       testPeer("local-validator"),
		Transactions: [][]byte{[]byte("r0")},
		Timestamp:    time.Unix(300, 0).UTC(),
	}
	v0.ID = mp.calculateVertexID(v0)
	mp.addVertex(v0)
	mp.certificates[v0.ID] = &Certificate{VertexID: v0.ID, Round: 0}

	v1 := &Vertex{
		Round:        1,
		Author:       testPeer("local-validator"),
		Transactions: [][]byte{[]byte("r1")},
		StrongLinks:  []VertexID{v0.ID},
		Timestamp:    time.Unix(301, 0).UTC(),
	}
	v1.ID = mp.calculateVertexID(v1)
	mp.addVertex(v1)

	mp.AdvanceRound() // current=1
	mp.AdvanceRound() // current=2, gc cutoff=1 => round 0 pruned

	if _, exists := mp.GetVertex(v0.ID); exists {
		t.Fatalf("expected round-0 vertex to be garbage collected")
	}
	if _, exists := mp.GetCertificate(v0.ID); exists {
		t.Fatalf("expected round-0 certificate to be garbage collected")
	}
	if _, exists := mp.GetVertex(v1.ID); !exists {
		t.Fatalf("expected round-1 vertex to remain")
	}
}

func TestDAGMempool_OrderTransactionsCausal(t *testing.T) {
	mp := NewDAGMempool(testPeer("local-validator"), 4, DefaultDAGConfig())

	ancestor := &Vertex{
		Round:        0,
		Author:       testPeer("v0"),
		Transactions: [][]byte{[]byte("a1"), []byte("a2")},
		Timestamp:    time.Unix(400, 0).UTC(),
	}
	ancestor.ID = mp.calculateVertexID(ancestor)
	mp.addVertex(ancestor)

	leader := &Vertex{
		Round:        1,
		Author:       testPeer("v1"),
		Transactions: [][]byte{[]byte("b1")},
		StrongLinks:  []VertexID{ancestor.ID},
		Timestamp:    time.Unix(401, 0).UTC(),
	}
	leader.ID = mp.calculateVertexID(leader)
	mp.addVertex(leader)

	ordered := mp.OrderTransactions(leader)
	if len(ordered) != 3 {
		t.Fatalf("expected 3 ordered txs, got %d", len(ordered))
	}
	if string(ordered[0]) != "a1" || string(ordered[1]) != "a2" || string(ordered[2]) != "b1" {
		t.Fatalf("unexpected causal ordering: %q %q %q", ordered[0], ordered[1], ordered[2])
	}
}
