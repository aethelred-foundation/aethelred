package httputil

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
)

type stubResolver struct {
	addresses map[string][]net.IPAddr
	err       error
}

func (r stubResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.addresses[host], nil
}

type recordingDialer struct {
	address string
	called  bool
	peer    net.Conn
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.called = true
	d.address = address
	client, server := net.Pipe()
	d.peer = server
	return client, nil
}

func TestValidateEndpointURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		endpoint  string
		shouldErr bool
	}{
		{name: "valid https literal", endpoint: "https://93.184.216.34/v1/verify", shouldErr: false},
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
		{name: "carrier grade NAT blocked", endpoint: "https://100.100.100.200/verify", shouldErr: true},
		{name: "benchmark network blocked", endpoint: "https://198.18.0.1/verify", shouldErr: true},
		{name: "documentation ipv4 blocked", endpoint: "https://203.0.113.10/verify", shouldErr: true},
		{name: "reserved ipv4 blocked", endpoint: "https://240.0.0.1/verify", shouldErr: true},
		{name: "documentation ipv6 blocked", endpoint: "https://[2001:db8::1]/verify", shouldErr: true},
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

func TestValidateEndpointURLDNSFailsClosed(t *testing.T) {
	t.Parallel()

	err := validateEndpointURL(
		context.Background(),
		"https://missing.example/verify",
		stubResolver{err: errors.New("NXDOMAIN")},
	)
	if err == nil {
		t.Fatal("expected DNS resolution failure to reject endpoint")
	}
}

func TestValidateEndpointURLStructureDefersDNSResolution(t *testing.T) {
	t.Parallel()

	const endpoint = "https://temporarily-unresolvable.example/verify"
	if err := ValidateEndpointURLStructure(endpoint); err != nil {
		t.Fatalf("structurally valid endpoint should not depend on DNS: %v", err)
	}
	if err := validateEndpointURL(
		context.Background(),
		endpoint,
		stubResolver{err: errors.New("temporary DNS failure")},
	); err == nil {
		t.Fatal("full request-time validation must still fail closed on DNS errors")
	}
}

func TestValidateEndpointURLRejectsUnsafeDNSAnswers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		host      string
		addresses []net.IPAddr
	}{
		{
			name: "private address",
			host: "private.example",
			addresses: []net.IPAddr{
				{IP: net.ParseIP("10.0.0.2")},
			},
		},
		{
			name: "mixed public and private addresses",
			host: "mixed.example",
			addresses: []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("192.168.1.2")},
			},
		},
		{
			name: "localhost resolving publicly",
			host: "localhost",
			addresses: []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := stubResolver{addresses: map[string][]net.IPAddr{tc.host: tc.addresses}}
			err := validateEndpointURL(context.Background(), "https://"+tc.host+"/verify", resolver)
			if err == nil {
				t.Fatal("expected unsafe DNS result to reject endpoint")
			}
		})
	}
}

func TestValidateEndpointURLAllowsPublicDNSAndLoopbackLocalhost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		endpoint  string
		host      string
		addresses []net.IPAddr
	}{
		{
			name:     "public service",
			endpoint: "https://service.example/verify",
			host:     "service.example",
			addresses: []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
			},
		},
		{
			name:     "explicit localhost",
			endpoint: "http://localhost:8080/verify",
			host:     "localhost",
			addresses: []net.IPAddr{
				{IP: net.ParseIP("127.0.0.1")},
				{IP: net.ParseIP("::1")},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := stubResolver{addresses: map[string][]net.IPAddr{tc.host: tc.addresses}}
			if err := validateEndpointURL(context.Background(), tc.endpoint, resolver); err != nil {
				t.Fatalf("expected safe DNS result, got %v", err)
			}
		})
	}
}

func TestSecureDialContextPinsValidatedAddress(t *testing.T) {
	t.Parallel()

	resolver := stubResolver{addresses: map[string][]net.IPAddr{
		"service.example": {{IP: net.ParseIP("93.184.216.34")}},
	}}
	dialer := &recordingDialer{}
	conn, err := secureDialContext(resolver, dialer)(
		context.Background(),
		"tcp",
		"service.example:443",
	)
	if err != nil {
		t.Fatalf("secure dial failed: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = dialer.peer.Close()
	})
	if got, want := dialer.address, "93.184.216.34:443"; got != want {
		t.Fatalf("dialed %q, want pinned address %q", got, want)
	}
}

func TestSecureDialContextRejectsPrivateAddressBeforeDial(t *testing.T) {
	t.Parallel()

	resolver := stubResolver{addresses: map[string][]net.IPAddr{
		"service.example": {{IP: net.ParseIP("10.0.0.2")}},
	}}
	dialer := &recordingDialer{}
	_, err := secureDialContext(resolver, dialer)(
		context.Background(),
		"tcp",
		"service.example:443",
	)
	if err == nil {
		t.Fatal("expected private DNS address to be rejected")
	}
	if dialer.called {
		t.Fatal("network dial occurred before address validation")
	}
}

func TestNewSecureClientDisablesRedirectsAndProxy(t *testing.T) {
	t.Parallel()

	baseTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialTLS: func(_, _ string) (net.Conn, error) {
			return nil, errors.New("legacy TLS dialer must never run")
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
	}
	client, err := newSecureClient(
		&http.Client{Transport: baseTransport},
		stubResolver{addresses: map[string][]net.IPAddr{}},
		&recordingDialer{},
	)
	if err != nil {
		t.Fatalf("failed to create secure client: %v", err)
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected redirect policy")
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy returned %v, want %v", err, http.ErrUseLastResponse)
	}
	secureTransport, ok := client.Transport.(*validatingTransport)
	if !ok {
		t.Fatalf("expected validating transport, got %T", client.Transport)
	}
	if secureTransport.transport.Proxy != nil {
		t.Fatal("expected environment proxy support to be disabled")
	}
	//nolint:staticcheck // The security regression test must inspect the deprecated bypass hook.
	if secureTransport.transport.DialTLS != nil {
		t.Fatal("expected legacy TLS dialer to be disabled")
	}
	if secureTransport.transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("expected TLS 1.2 minimum")
	}
}

func TestNewSecureClientRejectsDisabledCertificateVerification(t *testing.T) {
	t.Parallel()

	insecureTLS := &tls.Config{
		// #nosec G402 -- the test proves this deliberately unsafe setting is rejected.
		InsecureSkipVerify: true,
	}
	_, err := newSecureClient(
		&http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS}},
		stubResolver{addresses: map[string][]net.IPAddr{}},
		&recordingDialer{},
	)
	if err == nil {
		t.Fatal("expected insecure TLS configuration to be rejected")
	}
}
