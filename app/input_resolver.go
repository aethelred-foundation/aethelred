package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	verifyhttputil "github.com/aethelred/aethelred/x/verify/httputil"
)

const (
	defaultVerificationInputMaxBytes int64 = 8 << 20
	defaultVerificationInputTimeout        = 3 * time.Second
	maxVerificationInputLimit        int64 = 1 << 30
)

var (
	errVerificationInputInvalid      = errors.New("invalid verification input")
	errVerificationInputUnsafe       = errors.New("unsafe verification input endpoint")
	errVerificationInputFetch        = errors.New("verification input fetch failed")
	errVerificationInputTooLarge     = errors.New("verification input exceeds size limit")
	errVerificationInputHashMismatch = errors.New("verification input hash mismatch")
)

type verificationInputResolver interface {
	Resolve(context.Context, string, []byte) ([]byte, error)
}

type verificationInputHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// authenticatedInputResolver resolves model inputs only for ExtendVote. Remote
// bytes remain untrusted until their SHA-256 digest matches the commitment that
// was recorded in the job.
type authenticatedInputResolver struct {
	client   verificationInputHTTPClient
	timeout  time.Duration
	maxBytes int64
}

func newVerificationInputResolver() (verificationInputResolver, error) {
	client, err := verifyhttputil.NewSecureClient(&http.Client{
		Timeout: defaultVerificationInputTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create secure verification input client: %w", err)
	}

	return newAuthenticatedInputResolver(
		client,
		defaultVerificationInputTimeout,
		defaultVerificationInputMaxBytes,
	)
}

func newAuthenticatedInputResolver(
	client verificationInputHTTPClient,
	timeout time.Duration,
	maxBytes int64,
) (*authenticatedInputResolver, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: HTTP client is required", errVerificationInputInvalid)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("%w: timeout must be positive", errVerificationInputInvalid)
	}
	if maxBytes <= 0 || maxBytes > maxVerificationInputLimit {
		return nil, fmt.Errorf("%w: invalid size limit", errVerificationInputInvalid)
	}

	return &authenticatedInputResolver{
		client:   client,
		timeout:  timeout,
		maxBytes: maxBytes,
	}, nil
}

func (app *AethelredApp) initVerificationInputResolver() {
	resolver, err := newVerificationInputResolver()
	if err != nil {
		panic(fmt.Sprintf("FATAL: verification input resolver initialization failed: %v", err))
	}
	app.inputResolver = resolver
}

func (r *authenticatedInputResolver) Resolve(
	ctx context.Context,
	inputURI string,
	expectedHash []byte,
) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", errVerificationInputInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: request context is unavailable", errVerificationInputFetch)
	}
	if len(expectedHash) != sha256.Size {
		return nil, fmt.Errorf("%w: expected SHA-256 digest must be %d bytes", errVerificationInputInvalid, sha256.Size)
	}
	if err := pouwtypes.ValidateInputDataURI(inputURI); err != nil {
		policyErr := errVerificationInputInvalid
		if !strings.HasPrefix(inputURI, "data:") {
			policyErr = errVerificationInputUnsafe
		}
		return nil, fmt.Errorf("%w: URI admission policy rejected input", policyErr)
	}

	var (
		data []byte
		err  error
	)
	switch {
	case strings.HasPrefix(inputURI, "data:"):
		data, err = r.resolveDataURI(inputURI)
	default:
		data, err = r.resolveHTTPS(ctx, inputURI)
	}
	if err != nil {
		return nil, err
	}

	actualHash := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(actualHash[:], expectedHash) != 1 {
		return nil, errVerificationInputHashMismatch
	}
	return data, nil
}

func (r *authenticatedInputResolver) resolveDataURI(inputURI string) ([]byte, error) {
	if !strings.HasPrefix(inputURI, pouwtypes.InlineInputDataURIPrefix) {
		return nil, fmt.Errorf(
			"%w: only application/octet-stream base64 data URIs are allowed",
			errVerificationInputInvalid,
		)
	}

	encoded := strings.TrimPrefix(inputURI, pouwtypes.InlineInputDataURIPrefix)
	if strings.ContainsAny(encoded, " \t\r\n") {
		return nil, fmt.Errorf("%w: base64 data must not contain whitespace", errVerificationInputInvalid)
	}
	if len(encoded) > base64.StdEncoding.EncodedLen(int(r.maxBytes)) {
		return nil, errVerificationInputTooLarge
	}

	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed base64 data", errVerificationInputInvalid)
	}
	if int64(len(data)) > r.maxBytes {
		return nil, errVerificationInputTooLarge
	}
	return data, nil
}

func (r *authenticatedInputResolver) resolveHTTPS(ctx context.Context, inputURI string) ([]byte, error) {
	parsed, err := url.Parse(inputURI)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed URL", errVerificationInputInvalid)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: only HTTPS endpoints are allowed", errVerificationInputUnsafe)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: URL fragments are not allowed", errVerificationInputInvalid)
	}
	if err := verifyhttputil.ValidateEndpointURLStructure(inputURI); err != nil {
		return nil, fmt.Errorf("%w: endpoint policy rejected URL", errVerificationInputUnsafe)
	}

	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" {
		return nil, fmt.Errorf("%w: local endpoints are not allowed", errVerificationInputUnsafe)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, fmt.Errorf("%w: local endpoints are not allowed", errVerificationInputUnsafe)
	}

	requestCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, inputURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: could not construct request", errVerificationInputInvalid)
	}
	req.Header.Set("Accept", "application/octet-stream")

	resp, err := r.client.Do(req)
	if err != nil {
		// Do not include the underlying error because net/http errors can repeat
		// signed URLs (including their credentials) in validator logs or votes.
		return nil, errVerificationInputFetch
	}
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("%w: empty HTTP response", errVerificationInputFetch)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected HTTP status %d", errVerificationInputFetch, resp.StatusCode)
	}
	if resp.ContentLength > r.maxBytes {
		return nil, errVerificationInputTooLarge
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, r.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: response body read failed", errVerificationInputFetch)
	}
	if int64(len(data)) > r.maxBytes {
		return nil, errVerificationInputTooLarge
	}
	return data, nil
}
