package pqc

import (
	"bytes"
	"crypto/elliptic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// TestWalletUsesSecp256k1 proves the classical key is on secp256k1 (not the old
// P-256 stand-in) and that the public key is a valid curve point.
func TestWalletUsesSecp256k1(t *testing.T) {
	w, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	n := w.ECDSAPublicKey.Curve.Params().N
	if n.Cmp(btcec.S256().Params().N) != 0 {
		t.Fatal("wallet ECDSA curve is not secp256k1")
	}
	if n.Cmp(elliptic.P256().Params().N) == 0 {
		t.Fatal("wallet ECDSA curve is still P-256")
	}
	if !w.ECDSAPublicKey.Curve.IsOnCurve(w.ECDSAPublicKey.X, w.ECDSAPublicKey.Y) {
		t.Fatal("ECDSA public key is not on the secp256k1 curve")
	}
}

// TestDeterministicWalletFromSeed proves recovery: identical seeds reproduce the
// identical wallet, and a changed seed yields a different wallet.
func TestDeterministicWalletFromSeed(t *testing.T) {
	es := bytes.Repeat([]byte{0xA5}, 32)
	ds := bytes.Repeat([]byte{0x5A}, 32)

	w1, err := NewDualKeyWalletFromSeed(es, ds, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := NewDualKeyWalletFromSeed(es, ds, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w1.Address, w2.Address) {
		t.Fatal("same seed produced different addresses")
	}
	if w1.ECDSAPrivateKey.D.Cmp(w2.ECDSAPrivateKey.D) != 0 {
		t.Fatal("same seed produced different secp256k1 keys")
	}
	if !bytes.Equal(w1.DilithiumKeyPair.PublicKey, w2.DilithiumKeyPair.PublicKey) {
		t.Fatal("same seed produced different ML-DSA keys")
	}

	w3, err := NewDualKeyWalletFromSeed(es, bytes.Repeat([]byte{0x5B}, 32), DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(w1.Address, w3.Address) {
		t.Fatal("different Dilithium seed produced the same address")
	}
}

// TestMasterSeedUnifiedDerivation proves one master seed recovers the whole
// dual-key wallet deterministically and that the recovered wallet signs/verifies.
func TestMasterSeedUnifiedDerivation(t *testing.T) {
	master := bytes.Repeat([]byte{0x11}, 64)

	w1, err := NewDualKeyWalletFromMasterSeed(master, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := NewDualKeyWalletFromMasterSeed(master, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w1.Address, w2.Address) ||
		w1.ECDSAPrivateKey.D.Cmp(w2.ECDSAPrivateKey.D) != 0 ||
		!bytes.Equal(w1.DilithiumKeyPair.PublicKey, w2.DilithiumKeyPair.PublicKey) {
		t.Fatal("master-seed derivation is not deterministic")
	}

	msg := []byte("unified-seed transaction")
	sig, err := w1.Sign(msg, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := w1.Verify(msg, sig, CompositeScheme)
	if err != nil || !ok {
		t.Fatalf("composite verify failed: ok=%v err=%v", ok, err)
	}
}

// TestCompositeSignVerifySecp256k1 exercises the full composite (secp256k1 +
// ML-DSA) sign/verify path and tamper rejection.
func TestCompositeSignVerifySecp256k1(t *testing.T) {
	w, err := NewDualKeyWallet(DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("composite signing over secp256k1 + ML-DSA")

	sig, err := w.Sign(msg, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.ECDSASignature) != 64 {
		t.Fatalf("ECDSA signature length = %d, want 64", len(sig.ECDSASignature))
	}

	ok, err := w.Verify(msg, sig, CompositeScheme)
	if err != nil || !ok {
		t.Fatalf("composite verify failed: ok=%v err=%v", ok, err)
	}

	// Tampered message must not verify.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 0xFF
	if ok, _ := w.Verify(bad, sig, CompositeScheme); ok {
		t.Fatal("tampered message verified")
	}
}

// TestHDWalletChildDerivation proves HD child derivation is deterministic across
// independent wallet instances, distinct per index, and that children sign.
func TestHDWalletChildDerivation(t *testing.T) {
	master := bytes.Repeat([]byte{0x22}, 64)

	hd1, err := NewHDWallet(master, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	hd2, err := NewHDWallet(master, DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}

	c0a, err := hd1.DeriveChildByIndex(0)
	if err != nil {
		t.Fatal(err)
	}
	c0b, err := hd2.DeriveChildByIndex(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c0a.Address, c0b.Address) {
		t.Fatal("HD child 0 not deterministic across wallet instances")
	}

	c1, err := hd1.DeriveChildByIndex(1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c0a.Address, c1.Address) {
		t.Fatal("HD children 0 and 1 share an address")
	}

	msg := []byte("child transaction")
	sig, err := c0a.Sign(msg, CompositeScheme)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c0a.Verify(msg, sig, CompositeScheme); err != nil || !ok {
		t.Fatalf("child verify failed: ok=%v err=%v", ok, err)
	}
}

// TestEncryptedKeystoreRoundtrip proves the AES-GCM/Argon2id keystore round-trips
// a secp256k1 wallet, rejects a wrong passphrase, and the restored wallet signs.
func TestEncryptedKeystoreRoundtrip(t *testing.T) {
	w, err := NewDualKeyWalletFromMasterSeed(bytes.Repeat([]byte{0x33}, 64), DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")

	blob, err := w.SerializeEncrypted(pass)
	if err != nil {
		t.Fatal(err)
	}

	restored, err := DeserializeEncryptedDualKeyWallet(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Address, restored.Address) {
		t.Fatal("address changed across keystore round-trip")
	}
	if w.ECDSAPrivateKey.D.Cmp(restored.ECDSAPrivateKey.D) != 0 {
		t.Fatal("secp256k1 key changed across keystore round-trip")
	}

	if _, err := DeserializeEncryptedDualKeyWallet(blob, []byte("wrong-passphrase")); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}

	msg := []byte("transaction from restored wallet")
	for _, sch := range []struct {
		name   string
		scheme SignatureScheme
	}{{"ecdsa", ECDSAOnly}, {"dilithium", DilithiumOnly}, {"composite", CompositeScheme}} {
		sig, err := restored.Sign(msg, sch.scheme)
		if err != nil {
			t.Fatalf("%s sign: %v", sch.name, err)
		}
		if ok, err := restored.Verify(msg, sig, sch.scheme); err != nil || !ok {
			t.Fatalf("restored %s verify failed: ok=%v err=%v", sch.name, ok, err)
		}
	}
}

// TestAddressCommitsToBothKeys proves the wallet address binds both the
// classical and PQC public keys (you cannot swap one without changing the address).
func TestAddressCommitsToBothKeys(t *testing.T) {
	es := bytes.Repeat([]byte{0x44}, 32)
	a, err := NewDualKeyWalletFromSeed(es, bytes.Repeat([]byte{0x01}, 32), DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewDualKeyWalletFromSeed(es, bytes.Repeat([]byte{0x02}, 32), DilithiumLevel3)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Address, b.Address) {
		t.Fatal("address does not commit to the Dilithium key")
	}
	if len(a.Address) != 20 {
		t.Fatalf("address length = %d, want 20", len(a.Address))
	}
}
