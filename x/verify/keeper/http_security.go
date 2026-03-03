package keeper

import (
	"io"
	"net/http"
	"time"

	"crypto/tls"

	"github.com/aethelred/aethelred/internal/httpclient"
	"github.com/aethelred/aethelred/x/verify/httputil"
)

const (
	// httpClientTimeout is the maximum duration for HTTP requests.
	httpClientTimeout = 30 * time.Second
	// maxResponseSize is the maximum size of HTTP responses (10 MB).
	maxResponseSize = 10 * 1024 * 1024
	// maxIdleConns is the maximum number of idle connections.
	maxIdleConns = 10
	// idleConnTimeout is the timeout for idle connections.
	idleConnTimeout = 90 * time.Second
)

// secureHTTPClient creates an HTTP client with proper security configuration.
// SECURITY: Prevents DoS attacks via hanging connections and large responses.
func secureHTTPClient() *http.Client {
	return httpclient.NewPooledClient(httpclient.PoolConfig{
		Timeout:             httpClientTimeout,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: maxIdleConns,
		IdleConnTimeout:     idleConnTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		MinTLSVersion:       tls.VersionTLS12,
	})
}

// secureHTTPClientProvider is a test seam for remote verifier HTTP calls.
// Production code should not override this.
var secureHTTPClientProvider = secureHTTPClient

// validateEndpointURL validates that an endpoint URL is safe to call.
// SECURITY: Delegates to shared httputil.ValidateEndpointURL which includes
// DNS resolution to prevent hostname-based SSRF bypasses (M-03 fix).
func validateEndpointURL(endpoint string) error {
	return httputil.ValidateEndpointURL(endpoint)
}

// limitedReader wraps an io.Reader with a size limit.
// SECURITY: Prevents memory exhaustion from large responses.
func limitedReader(r io.Reader, maxBytes int64) io.Reader {
	return httputil.LimitedReader(r, maxBytes)
}
