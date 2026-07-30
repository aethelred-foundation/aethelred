// Package httputil provides shared HTTP security utilities for the verify module.
// SECURITY: Extracted from keeper/http_security.go so that tee, ezkl, and app
// packages can reuse endpoint validation and bounded reads without circular imports.
package httputil

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// MaxErrorBodySize is the maximum size for reading HTTP error response bodies (4 KB).
// Matches the pattern used in keeper/remote_verifier.go.
const MaxErrorBodySize int64 = 4096

const (
	dnsLookupTimeout = 5 * time.Second
	dialTimeout      = 10 * time.Second
	dialKeepAlive    = 30 * time.Second
)

// blockedHosts are specific hostnames to block (cloud metadata endpoints).
var blockedHosts = []string{
	"metadata.google.internal",
	"169.254.169.254", // AWS/GCP metadata
	"metadata.azure.com",
}

// blockedNetworkPrefixes contains special-use ranges that net.IP's convenience
// predicates intentionally classify as global unicast in some cases. None is a
// valid public production service destination; several (notably RFC 6598 CGNAT)
// are used by cloud providers for internal control-plane services.
var blockedNetworkPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// ValidateEndpointURL validates that an endpoint URL is safe to call.
// SECURITY: Prevents SSRF attacks by validating URL structure, blocking private
// IP ranges, cloud metadata endpoints, and resolving DNS to catch hostname-based bypasses.
func ValidateEndpointURL(endpoint string) error {
	return validateEndpointURL(context.Background(), endpoint, net.DefaultResolver)
}

// ValidateEndpointURLStructure validates stable URL properties without
// resolving DNS. Use this during long-lived object construction when a
// transient DNS failure must not become a process-lifetime error.
//
// NewSecureClient still performs full fail-closed DNS and IP validation at
// request and dial time.
func ValidateEndpointURLStructure(endpoint string) error {
	_, err := validateEndpointURLStructure(endpoint)
	return err
}

// NewSecureClient clones an HTTP client and installs an SSRF-resistant transport.
//
// The transport disables environment proxies and redirects, resolves every hostname
// itself, validates all returned addresses, and dials the validated IP literal. This
// closes the DNS rebinding window between URL validation and the network connection.
func NewSecureClient(base *http.Client) (*http.Client, error) {
	return newSecureClient(
		base,
		net.DefaultResolver,
		&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive},
	)
}

func validateEndpointURL(ctx context.Context, endpoint string, resolver ipResolver) error {
	host, err := validateEndpointURLStructure(endpoint)
	if err != nil {
		return err
	}

	_, err = resolveAndValidateHost(ctx, host, resolver)
	return err
}

func validateEndpointURLStructure(endpoint string) (string, error) {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint URL: %w", err)
	}

	host := normalizeHost(parsedURL.Hostname())
	if host == "" {
		return "", fmt.Errorf("endpoint host is required")
	}
	if parsedURL.User != nil {
		return "", fmt.Errorf("endpoint credentials are not allowed")
	}

	// Only allow HTTPS in production (HTTP only for localhost in dev).
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" {
			if !isExplicitLocalDevHost(host) {
				return "", fmt.Errorf("HTTP endpoints only allowed for localhost, use HTTPS for remote endpoints")
			}
		} else {
			return "", fmt.Errorf("unsupported URL scheme: %s (only https allowed)", parsedURL.Scheme)
		}
	}

	if err := validateHost(host); err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		if isExplicitLocalDevHost(host) {
			if !ip.IsLoopback() {
				return "", fmt.Errorf("local development endpoint %s is not loopback", host)
			}
			return host, nil
		}
		if err := validateIP(ip); err != nil {
			return "", fmt.Errorf("endpoint IP %s is not allowed: %w", host, err)
		}
	}

	return host, nil
}

// validateHost checks a host string against explicitly blocked hosts.
func validateHost(host string) error {
	for _, blocked := range blockedHosts {
		if host == blocked {
			return fmt.Errorf("access to cloud metadata endpoints is blocked: %s", host)
		}
	}
	return nil
}

func isExplicitLocalDevHost(host string) bool {
	switch normalizeHost(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func resolveAndValidateHost(ctx context.Context, host string, resolver ipResolver) ([]net.IPAddr, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("endpoint host is required")
	}
	if err := validateHost(host); err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if isExplicitLocalDevHost(host) {
			if !ip.IsLoopback() {
				return nil, fmt.Errorf("local development endpoint %s is not loopback", host)
			}
			return []net.IPAddr{{IP: ip}}, nil
		}
		if err := validateIP(ip); err != nil {
			return nil, fmt.Errorf("endpoint IP %s is not allowed: %w", host, err)
		}
		return []net.IPAddr{{IP: ip}}, nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, dnsLookupTimeout)
	defer cancel()
	ips, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve endpoint host %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("endpoint host %s resolved to no addresses", host)
	}

	if host == "localhost" {
		for _, addr := range ips {
			if addr.IP == nil || !addr.IP.IsLoopback() {
				return nil, fmt.Errorf("localhost resolved to non-loopback IP %s", addr.IP)
			}
		}
		return ips, nil
	}

	for _, addr := range ips {
		if err := validateIP(addr.IP); err != nil {
			return nil, fmt.Errorf("hostname %s resolves to blocked IP %s: %w", host, addr.IP, err)
		}
	}
	return ips, nil
}

func validateIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}
	if ip.IsLoopback() {
		return fmt.Errorf("loopback IP is not allowed")
	}
	if ip.IsPrivate() {
		return fmt.Errorf("private IP is not allowed")
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("link-local IP is not allowed")
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified IP is not allowed")
	}
	if ip.IsMulticast() {
		return fmt.Errorf("multicast IP is not allowed")
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("invalid IP address")
	}
	addr = addr.Unmap()
	for _, prefix := range blockedNetworkPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("special-use IP is not allowed")
		}
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Errorf("non-global IP is not allowed")
	}
	return nil
}

type validatingTransport struct {
	transport *http.Transport
	resolver  ipResolver
}

func (t *validatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("HTTP request URL is required")
	}
	if err := validateEndpointURL(req.Context(), req.URL.String(), t.resolver); err != nil {
		return nil, fmt.Errorf("unsafe outbound HTTP endpoint: %w", err)
	}
	return t.transport.RoundTrip(req)
}

func (t *validatingTransport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

func newSecureClient(base *http.Client, resolver ipResolver, dialer contextDialer) (*http.Client, error) {
	if resolver == nil {
		return nil, fmt.Errorf("DNS resolver is required")
	}
	if dialer == nil {
		return nil, fmt.Errorf("network dialer is required")
	}

	if base == nil {
		base = &http.Client{}
	}
	client := *base

	var transport *http.Transport
	switch configured := base.Transport.(type) {
	case nil:
		defaultTransport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("default HTTP transport has unexpected type %T", http.DefaultTransport)
		}
		transport = defaultTransport.Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, fmt.Errorf("secure HTTP client requires *http.Transport, got %T", base.Transport)
	}

	// A proxy can resolve or redirect the destination outside this process, so
	// direct connections are required for the address validation guarantees.
	transport.Proxy = nil
	//nolint:staticcheck // Clearing the deprecated hook is required so a caller-supplied DialTLS cannot bypass DNS pinning.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.DialContext = secureDialContext(resolver, dialer)
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.InsecureSkipVerify {
			return nil, fmt.Errorf("secure HTTP client cannot disable TLS certificate verification")
		}
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	client.Transport = &validatingTransport{transport: transport, resolver: resolver}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client, nil
}

func secureDialContext(resolver ipResolver, dialer contextDialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid outbound address %q: %w", address, err)
		}

		addresses, err := resolveAndValidateHost(ctx, host, resolver)
		if err != nil {
			return nil, err
		}

		var lastErr error
		for _, addr := range addresses {
			if addr.IP == nil {
				continue
			}
			target := net.JoinHostPort(addr.IP.String(), port)
			conn, dialErr := dialer.DialContext(ctx, network, target)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("host resolved to no usable addresses")
		}
		return nil, fmt.Errorf("failed to dial validated endpoint %s: %w", host, lastErr)
	}
}

// LimitedReader wraps an io.Reader with a size limit.
// SECURITY: Prevents memory exhaustion from large responses.
func LimitedReader(r io.Reader, maxBytes int64) io.Reader {
	return io.LimitReader(r, maxBytes)
}
