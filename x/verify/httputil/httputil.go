// Package httputil provides shared HTTP security utilities for the verify module.
// SECURITY: Extracted from keeper/http_security.go so that tee, ezkl, and app
// packages can reuse endpoint validation and bounded reads without circular imports.
package httputil

import (
	"fmt"
	"io"
	"net"
	"net/url"
)

// MaxErrorBodySize is the maximum size for reading HTTP error response bodies (4 KB).
// Matches the pattern used in keeper/remote_verifier.go.
const MaxErrorBodySize int64 = 4096

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

	host := parsedURL.Hostname()
	if host == "" {
		return fmt.Errorf("endpoint host is required")
	}

	// Only allow HTTPS in production (HTTP only for localhost in dev).
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" {
			if !isExplicitLocalDevHost(host) {
				return fmt.Errorf("HTTP endpoints only allowed for localhost, use HTTPS for remote endpoints")
			}
		} else {
			return fmt.Errorf("unsupported URL scheme: %s (only https allowed)", parsedURL.Scheme)
		}
	}

	// Block known-bad metadata endpoints and reserved hosts first.
	if err := validateHost(host); err != nil {
		return err
	}

	// Validate literal IPs directly so loopback/private IPv4 and IPv6 addresses
	// cannot bypass protection by skipping DNS resolution.
	if ip := net.ParseIP(host); ip != nil {
		if isExplicitLocalDevHost(host) {
			return nil
		}
		if err := validateIP(ip); err != nil {
			return fmt.Errorf("endpoint IP %s is not allowed: %w", host, err)
		}
		return nil
	}

	if isExplicitLocalDevHost(host) {
		return nil
	}

	// SECURITY FIX M-03: Resolve hostname to IP addresses and validate resolved IPs.
	// This prevents DNS-based SSRF bypasses where a hostname resolves to a private IP.
	// Skip DNS resolution for literal IP addresses and localhost (already validated above).
	// If DNS resolution fails, allow the request (the HTTP client will fail with a clear
	// error anyway); only block when resolution SUCCEEDS and returns a private/blocked IP.
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if err := validateIP(ip); err != nil {
				return fmt.Errorf("hostname %s resolves to blocked IP %s: %w", host, ip.String(), err)
			}
		}
	}
	// If DNS lookup fails, allow the request through - the actual HTTP call
	// will fail with a network error, which is a safer failure mode.

	return nil
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
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
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
	return nil
}

// LimitedReader wraps an io.Reader with a size limit.
// SECURITY: Prevents memory exhaustion from large responses.
func LimitedReader(r io.Reader, maxBytes int64) io.Reader {
	return io.LimitReader(r, maxBytes)
}
