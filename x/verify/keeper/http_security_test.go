package keeper

import (
	"io"
	"strings"
	"testing"
)

func TestValidateEndpointURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		endpoint  string
		shouldErr bool
	}{
		{name: "valid https", endpoint: "https://93.184.216.34/v1/verify", shouldErr: false},
		{name: "localhost http allowed", endpoint: "http://localhost:8080/verify", shouldErr: false},
		{name: "loopback http allowed", endpoint: "http://127.0.0.1:8080/verify", shouldErr: false},
		{name: "remote http blocked", endpoint: "http://example.com/verify", shouldErr: true},
		{name: "invalid scheme blocked", endpoint: "ftp://example.com/data", shouldErr: true},
		{name: "private ip blocked", endpoint: "https://10.0.0.2/verify", shouldErr: true},
		{name: "metadata host blocked", endpoint: "https://169.254.169.254/latest/meta-data", shouldErr: true},
		{name: "invalid url blocked", endpoint: "://bad-url", shouldErr: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateEndpointURL(tc.endpoint)
			if tc.shouldErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

func TestLimitedReader(t *testing.T) {
	t.Parallel()

	reader := strings.NewReader("abcdefghijklmnopqrstuvwxyz")
	limited := limitedReader(reader, 5)
	data, err := io.ReadAll(limited)
	if err != nil {
		t.Fatalf("failed to read limited reader: %v", err)
	}
	if string(data) != "abcde" {
		t.Fatalf("expected abcde, got %q", string(data))
	}
}

func TestSecureHTTPClientConfig(t *testing.T) {
	t.Parallel()

	client, err := secureHTTPClient()
	if err != nil {
		t.Fatalf("failed to create secure HTTP client: %v", err)
	}
	if client.Timeout != httpClientTimeout {
		t.Fatalf("unexpected client timeout: got %s want %s", client.Timeout, httpClientTimeout)
	}
	if client.Transport == nil {
		t.Fatal("expected secure transport")
	}
}
