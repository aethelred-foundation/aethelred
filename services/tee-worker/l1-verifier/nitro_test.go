package tee

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
)

func TestVerifySimulatedNitroAttestationRejectsTampering(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	doc := &NitroAttestationDocument{
		ModuleID:  "nitro-simulated",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
			1: []byte("pcr1"),
		},
		UserData: []byte("output-hash"),
		Nonce:    []byte("nonce"),
	}
	doc.Signature = SignSimulatedNitroAttestation(doc, key)

	if err := VerifySimulatedNitroAttestation(doc, key); err != nil {
		t.Fatalf("expected valid simulated attestation, got %v", err)
	}

	doc.UserData = []byte("tampered")
	if err := VerifySimulatedNitroAttestation(doc, key); err == nil {
		t.Fatalf("expected tampered simulated attestation to fail verification")
	}
}

func TestNitroServiceVerifyAttestationRejectsUnsignedSimulation(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		AllowSimulated:            true,
		AttestationDocumentMaxAge: 5 * time.Minute,
		SimulatedAttestationKey:   []byte("0123456789abcdef0123456789abcdef"),
	})

	doc := &NitroAttestationDocument{
		ModuleID:  "nitro-simulated",
		Timestamp: time.Now().UTC(),
		Digest:    "SHA384",
		PCRs: map[int][]byte{
			0: []byte("pcr0"),
		},
		UserData: []byte("output-hash"),
		Nonce:    []byte("nonce"),
	}

	result, err := service.VerifyAttestation(context.Background(), doc)
	if err != nil {
		t.Fatalf("expected simulated verification result, got error %v", err)
	}
	if result.Valid {
		t.Fatalf("expected unsigned simulated attestation to be rejected")
	}
}

func TestNitroServiceEncryptForEnclaveSimulatedUsesAuthenticatedEncryption(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		AllowSimulated:          true,
		SimulatedAttestationKey: []byte("0123456789abcdef0123456789abcdef"),
	})

	plaintext := []byte("confidential inference input")
	ciphertext, err := service.EncryptForEnclave(plaintext)
	if err != nil {
		t.Fatalf("expected simulated encryption success, got %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("ciphertext must differ from plaintext")
	}
	if bytes.Equal(ciphertext, []byte(base64.StdEncoding.EncodeToString(plaintext))) {
		t.Fatalf("ciphertext must not be a base64 wrapper")
	}

	key, err := service.simulatedNitroEncryptionKey()
	if err != nil {
		t.Fatalf("expected simulated encryption key, got %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("expected AES cipher, got %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("expected AEAD, got %v", err)
	}
	if len(ciphertext) <= gcm.NonceSize() {
		t.Fatalf("ciphertext too short: %d", len(ciphertext))
	}
	opened, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], []byte("aethelred:nitro:simulated:v1"))
	if err != nil {
		t.Fatalf("expected decrypt success, got %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypted plaintext mismatch")
	}
}

func TestNitroServiceEncryptForEnclaveFailsClosedWithoutEnclaveKey(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		ExecutorEndpoint: "https://tee.example",
	})

	_, err := service.EncryptForEnclave([]byte("confidential inference input"))
	if err == nil {
		t.Fatalf("expected remote encryption without enclave key to fail")
	}
	if !strings.Contains(err.Error(), "attested enclave public key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNitroServiceCallRemoteExecutorRejectsInvalidEndpoint(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		ExecutorEndpoint: "https://169.254.169.254",
	})

	_, err := service.callRemoteExecutor(context.Background(), &EnclaveExecutionRequest{
		RequestID: "req-1",
	})
	if err == nil {
		t.Fatal("expected invalid executor endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid executor endpoint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNitroServiceCallRemoteAttestationVerifierRejectsInvalidEndpoint(t *testing.T) {
	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		AttestationVerifierEndpoint: "https://169.254.169.254",
	})

	_, err := service.callRemoteAttestationVerifier(context.Background(), &NitroAttestationDocument{})
	if err == nil {
		t.Fatal("expected invalid attestation verifier endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid attestation verifier endpoint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNitroServiceRemoteCallsUseBearerTokenWhenConfigured(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer nitro-secret" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/execute":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req-1","success":true,"output_hash":"AQ==","execution_time_ms":1}`))
		case "/verify":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verified":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	service := NewNitroEnclaveService(log.NewNopLogger(), NitroConfig{
		ExecutorEndpoint:            server.URL,
		AttestationVerifierEndpoint: server.URL,
		APIToken:                    "nitro-secret",
		RequestTimeout:              time.Second,
	})

	_, err := service.callRemoteExecutor(context.Background(), &EnclaveExecutionRequest{RequestID: "req-1"})
	if err != nil {
		t.Fatalf("expected authenticated executor call to succeed, got %v", err)
	}

	verified, err := service.callRemoteAttestationVerifier(context.Background(), &NitroAttestationDocument{})
	if err != nil {
		t.Fatalf("expected authenticated verifier call to succeed, got %v", err)
	}
	if !verified {
		t.Fatal("expected authenticated verifier call to return verified=true")
	}
}
