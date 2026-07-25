package types

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	verifyhttputil "github.com/aethelred/aethelred/x/verify/httputil"
)

const (
	// MaxInputDataURILength bounds transaction and state growth. Inline data is
	// intentionally limited to small inputs; larger inputs must use HTTPS.
	MaxInputDataURILength = 4096

	// InlineInputDataURIPrefix is the only accepted inline input encoding.
	InlineInputDataURIPrefix = "data:application/octet-stream;base64,"
)

// ValidateInputDataURI performs deterministic admission checks only. It never
// resolves DNS or opens a network connection; DNS/IP validation is repeated by
// the validator-local secure transport immediately before an HTTPS fetch.
func ValidateInputDataURI(inputURI string) error {
	if inputURI == "" {
		return fmt.Errorf("input data URI cannot be empty")
	}
	if inputURI != strings.TrimSpace(inputURI) {
		return fmt.Errorf("input data URI cannot contain surrounding whitespace")
	}
	if len(inputURI) > MaxInputDataURILength {
		return fmt.Errorf("input data URI exceeds %d bytes", MaxInputDataURILength)
	}

	if strings.HasPrefix(inputURI, "data:") {
		return validateInlineInputDataURI(inputURI)
	}

	parsed, err := url.Parse(inputURI)
	if err != nil {
		return fmt.Errorf("input data URI is malformed")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("input data URI must use HTTPS or the approved inline data format")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("input data URI fragments are not allowed")
	}
	if err := verifyhttputil.ValidateEndpointURLStructure(inputURI); err != nil {
		return fmt.Errorf("input data URI endpoint is not allowed: %w", err)
	}

	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return fmt.Errorf("input data URI local endpoints are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return fmt.Errorf("input data URI local endpoints are not allowed")
	}
	return nil
}

func validateInlineInputDataURI(inputURI string) error {
	if !strings.HasPrefix(inputURI, InlineInputDataURIPrefix) {
		return fmt.Errorf("inline input must use application/octet-stream with base64 encoding")
	}

	encoded := strings.TrimPrefix(inputURI, InlineInputDataURIPrefix)
	if encoded == "" {
		return fmt.Errorf("inline input cannot be empty")
	}
	if strings.ContainsAny(encoded, " \t\r\n") {
		return fmt.Errorf("inline input base64 cannot contain whitespace")
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(encoded); err != nil {
		return fmt.Errorf("inline input contains malformed base64")
	}
	return nil
}
