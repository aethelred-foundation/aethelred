package httputil

import "testing"

func TestValidateEndpointURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		endpoint  string
		shouldErr bool
	}{
		{name: "valid https", endpoint: "https://verifier.example.com/v1/verify", shouldErr: false},
		{name: "localhost http allowed", endpoint: "http://localhost:8080/verify", shouldErr: false},
		{name: "loopback ipv4 http allowed", endpoint: "http://127.0.0.1:8080/verify", shouldErr: false},
		{name: "loopback ipv6 http allowed", endpoint: "http://[::1]:8080/verify", shouldErr: false},
		{name: "remote http blocked", endpoint: "http://example.com/verify", shouldErr: true},
		{name: "invalid scheme blocked", endpoint: "ftp://example.com/data", shouldErr: true},
		{name: "private ipv4 blocked", endpoint: "https://10.0.0.2/verify", shouldErr: true},
		{name: "metadata host blocked", endpoint: "https://169.254.169.254/latest/meta-data", shouldErr: true},
		{name: "non-local loopback ipv4 blocked", endpoint: "https://127.0.0.2/verify", shouldErr: true},
		{name: "loopback ipv6 blocked unless explicit local dev host", endpoint: "https://[::ffff:127.0.0.1]/verify", shouldErr: true},
		{name: "private ipv6 blocked", endpoint: "https://[fd00::1]/verify", shouldErr: true},
		{name: "unspecified ipv4 blocked", endpoint: "https://0.0.0.0/verify", shouldErr: true},
		{name: "invalid url blocked", endpoint: "://bad-url", shouldErr: true},
		{name: "missing host blocked", endpoint: "https:///verify", shouldErr: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateEndpointURL(tc.endpoint)
			if tc.shouldErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.shouldErr && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
