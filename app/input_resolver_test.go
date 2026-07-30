package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
)

type verificationInputClientFunc func(*http.Request) (*http.Response, error)

func (f verificationInputClientFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAuthenticatedInputResolverHTTPSValid(t *testing.T) {
	t.Parallel()

	input := []byte("authenticated model input")
	expectedHash := sha256.Sum256(input)
	called := false
	client := verificationInputClientFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.Method != http.MethodGet {
			t.Fatalf("expected GET request, got %s", req.Method)
		}
		if req.URL.String() != "https://inputs.example.com/jobs/job-1.bin?version=2" {
			t.Fatalf("unexpected request URL: %s", req.URL)
		}
		if _, ok := req.Context().Deadline(); !ok {
			t.Fatal("expected resolver request context to have a deadline")
		}
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(input)),
			ContentLength: int64(len(input)),
		}, nil
	})

	resolver, err := newAuthenticatedInputResolver(client, time.Second, 1024)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	got, err := resolver.Resolve(
		context.Background(),
		"https://inputs.example.com/jobs/job-1.bin?version=2",
		expectedHash[:],
	)
	if err != nil {
		t.Fatalf("resolve input: %v", err)
	}
	if !called {
		t.Fatal("expected HTTP client to be called")
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("resolved bytes mismatch: got %q want %q", got, input)
	}
}

func TestAuthenticatedInputResolverDataURIValid(t *testing.T) {
	t.Parallel()

	input := []byte(`{"score":0.99}`)
	expectedHash := sha256.Sum256(input)
	client := verificationInputClientFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("data URI must not use the network")
		return nil, nil
	})
	resolver, err := newAuthenticatedInputResolver(client, time.Second, 1024)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	inputURI := pouwtypes.InlineInputDataURIPrefix + base64.StdEncoding.EncodeToString(input)
	got, err := resolver.Resolve(context.Background(), inputURI, expectedHash[:])
	if err != nil {
		t.Fatalf("resolve data URI: %v", err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("resolved bytes mismatch: got %q want %q", got, input)
	}
}

func TestAuthenticatedInputResolverRejectsHashMismatch(t *testing.T) {
	t.Parallel()

	input := []byte("content from endpoint")
	wrongHash := sha256.Sum256([]byte("different content"))
	client := verificationInputClientFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(input)),
		}, nil
	})
	resolver, err := newAuthenticatedInputResolver(client, time.Second, 1024)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), "https://inputs.example.com/input.bin", wrongHash[:])
	if !errors.Is(err, errVerificationInputHashMismatch) {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
}

func TestAuthenticatedInputResolverRejectsOversizeResponse(t *testing.T) {
	t.Parallel()

	const maxBytes = int64(16)
	input := []byte(strings.Repeat("x", int(maxBytes)+1))
	expectedHash := sha256.Sum256(input)
	client := verificationInputClientFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Body:          io.NopCloser(bytes.NewReader(input)),
			ContentLength: -1,
		}, nil
	})
	resolver, err := newAuthenticatedInputResolver(client, time.Second, maxBytes)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), "https://inputs.example.com/input.bin", expectedHash[:])
	if !errors.Is(err, errVerificationInputTooLarge) {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestAuthenticatedInputResolverBlocksUnsafeEndpoints(t *testing.T) {
	t.Parallel()

	endpoints := []string{
		"http://inputs.example.com/input.bin",
		"https://localhost/input.bin",
		"https://127.0.0.1/input.bin",
		"https://[::1]/input.bin",
		"https://10.0.0.1/input.bin",
		"https://169.254.169.254/latest/meta-data",
		"https://metadata.google.internal/computeMetadata/v1/",
		"file:///etc/passwd",
	}
	expectedHash := make([]byte, sha256.Size)

	for _, endpoint := range endpoints {
		endpoint := endpoint
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			called := false
			client := verificationInputClientFunc(func(*http.Request) (*http.Response, error) {
				called = true
				return nil, errors.New("must not be called")
			})
			resolver, err := newAuthenticatedInputResolver(client, time.Second, 1024)
			if err != nil {
				t.Fatalf("create resolver: %v", err)
			}

			_, err = resolver.Resolve(context.Background(), endpoint, expectedHash)
			if !errors.Is(err, errVerificationInputUnsafe) {
				t.Fatalf("expected unsafe-endpoint error for %q, got %v", endpoint, err)
			}
			if called {
				t.Fatalf("HTTP client called for blocked endpoint %q", endpoint)
			}
		})
	}
}

func TestAuthenticatedInputResolverEnforcesTimeout(t *testing.T) {
	t.Parallel()

	client := verificationInputClientFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	resolver, err := newAuthenticatedInputResolver(client, 25*time.Millisecond, 1024)
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}

	_, err = resolver.Resolve(
		context.Background(),
		"https://inputs.example.com/input.bin",
		make([]byte, sha256.Size),
	)
	if !errors.Is(err, errVerificationInputFetch) {
		t.Fatalf("expected fetch timeout error, got %v", err)
	}
}
