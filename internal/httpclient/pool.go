package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// PoolConfig configures pooled HTTP clients for outbound service calls.
type PoolConfig struct {
	Timeout               time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	DisableCompression    bool
	ForceAttemptHTTP2     bool
	MinTLSVersion         uint16
}

const (
	defaultTimeout             = 30 * time.Second
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 20
	defaultIdleConnTimeout     = 90 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultExpectContinue      = 1 * time.Second
	defaultDialTimeout         = 10 * time.Second
	defaultDialKeepAlive       = 30 * time.Second
)

// NewPooledClient returns an http.Client with sane pooling defaults.
func NewPooledClient(cfg PoolConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = defaultMaxIdleConns
	}

	maxIdlePerHost := cfg.MaxIdleConnsPerHost
	if maxIdlePerHost <= 0 {
		maxIdlePerHost = defaultMaxIdleConnsPerHost
	}

	idleTimeout := cfg.IdleConnTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleConnTimeout
	}

	tlsTimeout := cfg.TLSHandshakeTimeout
	if tlsTimeout <= 0 {
		tlsTimeout = defaultTLSHandshakeTimeout
	}

	expectContinue := cfg.ExpectContinueTimeout
	if expectContinue <= 0 {
		expectContinue = defaultExpectContinue
	}

	minTLS := cfg.MinTLSVersion
	if minTLS == 0 {
		minTLS = tls.VersionTLS12
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: defaultDialTimeout, KeepAlive: defaultDialKeepAlive}).DialContext,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdlePerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       idleTimeout,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: expectContinue,
		DisableCompression:    cfg.DisableCompression,
		ForceAttemptHTTP2:     cfg.ForceAttemptHTTP2,
		TLSClientConfig: &tls.Config{
			MinVersion: minTLS,
		},
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
