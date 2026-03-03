package httpclient

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"
)

func TestNewPooledClient_Defaults(t *testing.T) {
	t.Parallel()
	client := NewPooledClient(PoolConfig{})
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.Timeout != defaultTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultTimeout, client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected TLS 1.2, got 0x%04x", transport.TLSClientConfig.MinVersion)
	}
}

func TestNewPooledClient_CustomTimeout(t *testing.T) {
	t.Parallel()
	client := NewPooledClient(PoolConfig{
		Timeout: 5 * time.Second,
	})
	if client.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", client.Timeout)
	}
}

func TestNewPooledClient_AllCustom(t *testing.T) {
	t.Parallel()
	cfg := PoolConfig{
		Timeout:               10 * time.Second,
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       20,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MinTLSVersion:         tls.VersionTLS13,
	}
	client := NewPooledClient(cfg)
	if client == nil {
		t.Fatal("client is nil")
	}
	if client.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", client.Timeout)
	}
}

func TestNewPooledClient_ZeroValues_UseDefaults(t *testing.T) {
	t.Parallel()
	// All zero values should use defaults
	cfg := PoolConfig{
		Timeout:             0,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     0,
		TLSHandshakeTimeout: 0,
		ExpectContinueTimeout: 0,
		MinTLSVersion:       0,
	}
	client := NewPooledClient(cfg)
	if client.Timeout != defaultTimeout {
		t.Errorf("expected default timeout, got %v", client.Timeout)
	}
}

func TestNewPooledClient_NegativeValues_UseDefaults(t *testing.T) {
	t.Parallel()
	cfg := PoolConfig{
		Timeout:             -1,
		MaxIdleConns:        -1,
		MaxIdleConnsPerHost: -1,
		IdleConnTimeout:     -1,
		TLSHandshakeTimeout: -1,
		ExpectContinueTimeout: -1,
	}
	client := NewPooledClient(cfg)
	if client.Timeout != defaultTimeout {
		t.Errorf("expected default timeout for negative, got %v", client.Timeout)
	}
}

func TestDefaultConstants(t *testing.T) {
	t.Parallel()
	if defaultTimeout != 30*time.Second {
		t.Errorf("expected 30s default timeout, got %v", defaultTimeout)
	}
	if defaultMaxIdleConns != 100 {
		t.Errorf("expected 100 default max idle conns, got %d", defaultMaxIdleConns)
	}
	if defaultMaxIdleConnsPerHost != 20 {
		t.Errorf("expected 20 default max idle per host, got %d", defaultMaxIdleConnsPerHost)
	}
	if defaultIdleConnTimeout != 90*time.Second {
		t.Errorf("expected 90s default idle conn timeout, got %v", defaultIdleConnTimeout)
	}
	if defaultTLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected 10s default TLS handshake timeout, got %v", defaultTLSHandshakeTimeout)
	}
}
