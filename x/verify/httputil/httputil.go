// Package httputil provides shared HTTP security utilities for the verify module.
// SECURITY: Extracted from keeper/http_security.go so that tee, ezkl, and app
// packages can reuse endpoint validation and bounded reads without circular imports.
package httputil

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
)

// MaxErrorBodySize is the maximum size for reading HTTP error response bodies (4 KB).
// Matches the pattern used in keeper/remote_verifier.go.
const MaxErrorBodySize int64 = 4096

// blockedPrefixes are private/internal IP prefixes to block for SSRF prevention.
var blockedPrefixes = []string{
	"10.", "172.16.", "172.17.", "172.18.", "172.19.",
	"172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
	"172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
	"172.30.", "172.31.", "192.168.", "169.254.",
}

// blockedHosts are specific hostnames to block (cloud metadata endpoints).
var blockedHosts = []string{
	"metadata.google.internal",
	"169.254.169.254", // AWS/GCP metadata
	"metadata.azure.com",
}

// ValidateEndpointURL validates that an endpoint URL is safe to call.
// SECURITY: Prevents SSRF attacks by validating URL structure, blocking private
// IP ranges, cloud metadata endpoints, and resolving DNS to catch hostname-based bypasses.
func ValidateEndpointURL(endpoint string) error {
	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Only allow HTTPS in production (HTTP only for localhost in dev).
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" {
			host := parsedURL.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return fmt.Errorf("HTTP endpoints only allowed for localhost, use HTTPS for remote endpoints")
			}
		} else {
			return fmt.Errorf("unsupported URL scheme: %s (only https allowed)", parsedURL.Scheme)
		}
	}

	// Block internal/private IP ranges to prevent SSRF.
	host := parsedURL.Hostname()
	if err := validateHost(host); err != nil {
		return err
	}

	// SECURITY FIX M-03: Resolve hostname to IP addresses and validate resolved IPs.
	// This prevents DNS-based SSRF bypasses where a hostname resolves to a private IP.
	// Skip DNS resolution for literal IP addresses and localhost (already validated above).
	// If DNS resolution fails, allow the request (the HTTP client will fail with a clear
	// error anyway); only block when resolution SUCCEEDS and returns a private/blocked IP.
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
					return fmt.Errorf("hostname %s resolves to non-routable IP %s", host, ip.String())
				}
				// Also check resolved IPs against blocked prefixes
				ipStr := ip.String()
				if err := validateHost(ipStr); err != nil {
					return fmt.Errorf("hostname %s resolves to blocked IP %s", host, ipStr)
				}
			}
		}
		// If DNS lookup fails, allow the request through - the actual HTTP call
		// will fail with a network error, which is a safer failure mode.
	}

	return nil
}

// validateHost checks a host string against blocked prefixes and hosts.
func validateHost(host string) error {
	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(host, prefix) {
			return fmt.Errorf("internal IP addresses are not allowed: %s", host)
		}
	}
	for _, blocked := range blockedHosts {
		if host == blocked {
			return fmt.Errorf("access to cloud metadata endpoints is blocked: %s", host)
		}
	}
	return nil
}

// LimitedReader wraps an io.Reader with a size limit.
// SECURITY: Prevents memory exhaustion from large responses.
func LimitedReader(r io.Reader, maxBytes int64) io.Reader {
	return io.LimitReader(r, maxBytes)
}
