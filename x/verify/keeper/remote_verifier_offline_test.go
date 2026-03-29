package keeper

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aethelred/aethelred/internal/circuitbreaker"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func withHTTPClientStub(t *testing.T, fn roundTripFunc) {
	t.Helper()
	old := secureHTTPClientProvider
	secureHTTPClientProvider = func() *http.Client {
		return &http.Client{Transport: fn}
	}
	t.Cleanup(func() { secureHTTPClientProvider = old })
}

func TestRemoteVerifierOffline_ZKPaths(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "POST", req.Method)
		require.True(t, strings.HasSuffix(req.URL.Path, "/verify"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":true}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRemoteVerifierOffline_ZKErrorsAndBreaker(t *testing.T) {
	t.Run("invalid endpoint rejected before HTTP", func(t *testing.T) {
		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "ftp://example.com", sampleZKProof(), sampleVerifyingKey())
		require.Error(t, err)
		require.False(t, ok)
		require.Contains(t, err.Error(), "invalid verifier endpoint")
	})

	t.Run("circuit open blocks request", func(t *testing.T) {
		k := Keeper{
			zkVerifierBreaker: circuitbreaker.New("zk", 1, time.Hour),
		}
		k.zkVerifierBreaker.RecordFailure()
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "circuit open")
		require.False(t, ok)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader(`bad request`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "status 400")
		require.False(t, ok)
	})

	t.Run("decode failure", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{bad-json`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "decode")
		require.False(t, ok)
	})

	t.Run("explicit verifier error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"verified":false,"error":"invalid proof"}`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "verification failed")
		require.False(t, ok)
	})

	t.Run("transport error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network down")
		})

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.ErrorContains(t, err, "request failed")
		require.False(t, ok)
	})
}

func TestRemoteVerifierOffline_AttestationPaths(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "POST", req.Method)
		require.True(t, strings.HasSuffix(req.URL.Path, "/verify"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":true}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
	require.NoError(t, err)
	require.True(t, ok)
}

// ---------------------------------------------------------------------------
// TEE Attestation: success & failure (dedicated tests)
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_TEEAttestationSuccess(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		require.Equal(t, "POST", req.Method)
		require.True(t, strings.HasSuffix(req.URL.Path, "/verify"))
		require.Equal(t, "application/json", req.Header.Get("Content-Type"))
		require.Equal(t, "Aethelred-Verifier/1.0", req.Header.Get("User-Agent"))

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":true}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{
		attestationVerifierBreaker: circuitbreaker.New("attestation", 5, time.Hour),
	}
	ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRemoteVerifierOffline_TEEAttestationFailure(t *testing.T) {
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"verified":false,"error":"enclave measurement mismatch"}`)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
	require.Error(t, err)
	require.False(t, ok)
	require.ErrorContains(t, err, "attestation verification failed")
	require.ErrorContains(t, err, "enclave measurement mismatch")
}

// ---------------------------------------------------------------------------
// TEE Attestation: circuit breaker integration
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_TEEBreakerIntegration(t *testing.T) {
	// Use a breaker with threshold of 3 failures before opening.
	const threshold = 3

	callCount := 0
	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		callCount++
		return nil, fmt.Errorf("connection refused")
	})

	k := Keeper{
		attestationVerifierBreaker: circuitbreaker.New("attestation-integration", int64(threshold), time.Hour),
	}

	// First `threshold` calls should hit the transport and record failures.
	for i := 0; i < threshold; i++ {
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.Error(t, err)
		require.False(t, ok)
		require.ErrorContains(t, err, "request failed")
	}
	require.Equal(t, threshold, callCount, "expected %d HTTP calls before breaker opens", threshold)

	// After threshold failures the breaker should be open — the next call
	// must be rejected without making an HTTP request.
	ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
	require.Error(t, err)
	require.False(t, ok)
	require.ErrorContains(t, err, "circuit open")
	require.Equal(t, threshold, callCount, "HTTP call should not have been made while breaker is open")
}

// ---------------------------------------------------------------------------
// ZK verifier: response too large
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_ZKResponseTooLarge(t *testing.T) {
	// Build a response body that exceeds maxResponseSize (10 MB).
	// The limitedReader truncates the body, so json.Decode will see an
	// incomplete JSON payload and return a decode error.
	oversized := `{"verified":true,"padding":"` + strings.Repeat("A", int(maxResponseSize)+1024) + `"}`

	withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(oversized)),
			Header:     make(http.Header),
		}, nil
	})

	k := Keeper{}
	ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
	require.Error(t, err)
	require.False(t, ok)
	// The truncated body produces a decode error.
	require.ErrorContains(t, err, "decode")
}

// ---------------------------------------------------------------------------
// ZK verifier: malformed JSON (dedicated test)
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_ZKMalformedJSON(t *testing.T) {
	bodies := []string{
		`not json at all`,
		`{"verified": }`,
		`<html>error</html>`,
		``,
	}

	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			})

			k := Keeper{}
			ok, err := k.callRemoteZKVerifier(context.Background(), "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
			require.Error(t, err)
			require.False(t, ok)
			require.ErrorContains(t, err, "decode")
		})
	}
}

// ---------------------------------------------------------------------------
// ZK verifier: context timeout / cancellation
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_ZKTimeout(t *testing.T) {
	t.Run("context cancelled before request", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return nil, req.Context().Err()
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(ctx, "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("context deadline exceeded during request", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			// Simulate the HTTP client returning a deadline error.
			return nil, context.DeadlineExceeded
		})

		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()

		k := Keeper{}
		ok, err := k.callRemoteZKVerifier(ctx, "https://verifier.example", sampleZKProof(), sampleVerifyingKey())
		require.Error(t, err)
		require.False(t, ok)
		require.ErrorContains(t, err, "request failed")
	})
}

// ---------------------------------------------------------------------------
// TEE attestation: SSRF / endpoint validation
// ---------------------------------------------------------------------------

func TestRemoteVerifierOffline_TEEEndpointValidation(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  string
	}{
		{
			name:     "ftp scheme rejected",
			endpoint: "ftp://verifier.example",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "plain http non-localhost rejected",
			endpoint: "http://verifier.example",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "private IP 10.x rejected",
			endpoint: "https://10.0.0.1",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "private IP 192.168.x rejected",
			endpoint: "https://192.168.1.1",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "private IP 172.16.x rejected",
			endpoint: "https://172.16.0.1",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "link-local 169.254.x rejected",
			endpoint: "https://169.254.169.254",
			wantErr:  "invalid attestation endpoint",
		},
		{
			name:     "empty scheme rejected",
			endpoint: "://missing-scheme",
			wantErr:  "invalid attestation endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := Keeper{}
			ok, err := k.callRemoteAttestationVerifier(context.Background(), tt.endpoint, sampleTEEAttestation())
			require.Error(t, err)
			require.False(t, ok)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestRemoteVerifierOffline_AttestationErrorsAndBreaker(t *testing.T) {
	t.Run("invalid endpoint rejected before HTTP", func(t *testing.T) {
		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "ftp://example.com", sampleTEEAttestation())
		require.Error(t, err)
		require.False(t, ok)
		require.Contains(t, err.Error(), "invalid attestation endpoint")
	})

	t.Run("circuit open blocks request", func(t *testing.T) {
		k := Keeper{
			attestationVerifierBreaker: circuitbreaker.New("attestation", 1, time.Hour),
		}
		k.attestationVerifierBreaker.RecordFailure()
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "circuit open")
		require.False(t, ok)
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body:       io.NopCloser(strings.NewReader(`unauthorized`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "status 401")
		require.False(t, ok)
	})

	t.Run("decode failure", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{bad-json`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "decode")
		require.False(t, ok)
	})

	t.Run("explicit verifier error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"verified":false,"error":"invalid quote"}`)),
				Header:     make(http.Header),
			}, nil
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "verification failed")
		require.False(t, ok)
	})

	t.Run("transport error", func(t *testing.T) {
		withHTTPClientStub(t, func(req *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("network down")
		})

		k := Keeper{}
		ok, err := k.callRemoteAttestationVerifier(context.Background(), "https://attestation.example", sampleTEEAttestation())
		require.ErrorContains(t, err, "request failed")
		require.False(t, ok)
	})
}

