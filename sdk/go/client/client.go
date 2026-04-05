// Package client provides the main Aethelred SDK client.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aethelred/sdk-go/jobs"
	"github.com/aethelred/sdk-go/models"
	"github.com/aethelred/sdk-go/seals"
	"github.com/aethelred/sdk-go/types"
	"github.com/aethelred/sdk-go/validators"
	"github.com/aethelred/sdk-go/verification"
)

// Network represents an Aethelred network.
type Network string

const (
	Mainnet Network = "mainnet"
	Testnet Network = "testnet"
	Devnet  Network = "devnet"
	Local   Network = "local"
)

// NetworkConfig returns the configuration for a network.
func (n Network) Config() NetworkConfig {
	switch n {
	case Mainnet:
		return NetworkConfig{
			RPCURL:  "https://rpc.mainnet.aethelred.io",
			ChainID: "aethelred-mainnet-1",
		}
	case Testnet:
		return NetworkConfig{
			RPCURL:  "https://rpc.testnet.aethelred.io",
			ChainID: "aethelred-testnet-1",
		}
	case Devnet:
		return NetworkConfig{
			RPCURL:  "https://rpc.devnet.aethelred.io",
			ChainID: "aethelred-devnet-1",
		}
	case Local:
		return NetworkConfig{
			RPCURL:  "http://127.0.0.1:26657",
			ChainID: "aethelred-local",
		}
	default:
		return Mainnet.Config()
	}
}

// NetworkConfig holds network configuration.
type NetworkConfig struct {
	RPCURL  string
	ChainID string
}

// Config holds client configuration.
type Config struct {
	Network         Network
	RPCURL          string
	ChainID         string
	APIKey          string
	Timeout         time.Duration
	MaxRetries      int
	HTTPClient      *http.Client
	HTTPTransport   *http.Transport
	ConnectionPool  *ConnectionPoolConfig
	CustomTransport Transport
}

// ConnectionPoolConfig controls HTTP connection pooling for the default HTTP transport.
type ConnectionPoolConfig struct {
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration
}

// TransportRequest is the protocol-agnostic request shape used by pluggable transports.
type TransportRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// TransportResponse is the protocol-agnostic response shape used by pluggable transports.
type TransportResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// Transport abstracts request execution so callers can swap in gRPC-backed transports.
type Transport interface {
	Do(ctx context.Context, req *TransportRequest) (*TransportResponse, error)
}

// DefaultConfig returns a default configuration.
func DefaultConfig() Config {
	return Config{
		Network:    Mainnet,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}
}

// Client is the main Aethelred SDK client.
type Client struct {
	config     Config
	httpClient *http.Client
	transport  Transport

	Jobs         *jobs.Module
	Seals        *seals.Module
	Models       *models.Module
	Validators   *validators.Module
	Verification *verification.Module
}

// NewClient creates a new Aethelred client.
func NewClient(network Network, opts ...Option) (*Client, error) {
	config := DefaultConfig()
	config.Network = network

	for _, opt := range opts {
		opt(&config)
	}

	networkConfig := network.Config()
	if config.RPCURL == "" {
		config.RPCURL = networkConfig.RPCURL
	}
	if config.ChainID == "" {
		config.ChainID = networkConfig.ChainID
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpTransport := config.HTTPTransport
		if httpTransport == nil {
			if base, ok := http.DefaultTransport.(*http.Transport); ok {
				httpTransport = base.Clone()
			} else {
				httpTransport = &http.Transport{}
			}
		}
		if config.ConnectionPool != nil {
			pool := config.ConnectionPool
			if pool.MaxIdleConns > 0 {
				httpTransport.MaxIdleConns = pool.MaxIdleConns
			}
			if pool.MaxIdleConnsPerHost > 0 {
				httpTransport.MaxIdleConnsPerHost = pool.MaxIdleConnsPerHost
			}
			if pool.MaxConnsPerHost > 0 {
				httpTransport.MaxConnsPerHost = pool.MaxConnsPerHost
			}
			if pool.IdleConnTimeout > 0 {
				httpTransport.IdleConnTimeout = pool.IdleConnTimeout
			}
		}
		httpClient = &http.Client{
			Timeout:   config.Timeout,
			Transport: httpTransport,
		}
	} else if httpClient.Timeout == 0 {
		httpClient.Timeout = config.Timeout
	}

	transport := config.CustomTransport
	if transport == nil {
		transport = &httpTransportAdapter{client: httpClient}
	}

	c := &Client{
		config:     config,
		httpClient: httpClient,
		transport:  transport,
	}

	// Initialize modules
	c.Jobs = jobs.NewModule(c)
	c.Seals = seals.NewModule(c)
	c.Models = models.NewModule(c)
	c.Validators = validators.NewModule(c)
	c.Verification = verification.NewModule(c)

	return c, nil
}

// Option is a client configuration option.
type Option func(*Config)

// WithAPIKey sets the API key.
func WithAPIKey(apiKey string) Option {
	return func(c *Config) { c.APIKey = apiKey }
}

// WithTimeout sets the timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) { c.Timeout = timeout }
}

// WithRPCURL sets a custom RPC URL.
func WithRPCURL(url string) Option {
	return func(c *Config) { c.RPCURL = url }
}

// WithHTTPClient injects a custom *http.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Config) { c.HTTPClient = httpClient }
}

// WithHTTPTransport sets the net/http transport used by the default HTTP client.
func WithHTTPTransport(transport *http.Transport) Option {
	return func(c *Config) { c.HTTPTransport = transport }
}

// WithConnectionPool configures HTTP connection pooling for the default HTTP transport.
func WithConnectionPool(pool ConnectionPoolConfig) Option {
	return func(c *Config) { c.ConnectionPool = &pool }
}

// WithTransport sets a custom pluggable transport implementation.
func WithTransport(transport Transport) Option {
	return func(c *Config) { c.CustomTransport = transport }
}

// WithGRPCTransport is an alias for WithTransport for semantic clarity.
func WithGRPCTransport(transport Transport) Option {
	return WithTransport(transport)
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, path string, result interface{}) error {
	return c.request(ctx, http.MethodGet, path, nil, result)
}

// Post performs a POST request.
func (c *Client) Post(ctx context.Context, path string, body, result interface{}) error {
	return c.request(ctx, http.MethodPost, path, body, result)
}

func (c *Client) request(ctx context.Context, method, path string, body, result interface{}) error {
	url := c.config.RPCURL + path

	var bodyBytes []byte
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyBytes = data
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aethelred-sdk-go/1.0.0")
	if c.config.APIKey != "" {
		req.Header.Set("X-API-Key", c.config.APIKey)
	}

	resp, err := c.transport.Do(ctx, &TransportRequest{
		Method:  method,
		URL:     url,
		Headers: req.Header.Clone(),
		Body:    bodyBytes,
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode == 429 {
		return types.ErrRateLimited
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(resp.Body))
	}

	if result != nil {
		if err := json.Unmarshal(resp.Body, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// GetNodeInfo returns information about the connected node.
func (c *Client) GetNodeInfo(ctx context.Context) (*types.NodeInfo, error) {
	var resp struct {
		DefaultNodeInfo types.NodeInfo `json:"default_node_info"`
	}
	if err := c.Get(ctx, "/cosmos/base/tendermint/v1beta1/node_info", &resp); err != nil {
		return nil, err
	}
	return &resp.DefaultNodeInfo, nil
}

// HealthCheck checks if the node is healthy.
func (c *Client) HealthCheck(ctx context.Context) bool {
	_, err := c.GetNodeInfo(ctx)
	return err == nil
}

// RPCURL returns the RPC URL.
func (c *Client) RPCURL() string { return c.config.RPCURL }

// ChainID returns the chain ID.
func (c *Client) ChainID() string { return c.config.ChainID }

type httpTransportAdapter struct {
	client *http.Client
}

func (t *httpTransportAdapter) Do(ctx context.Context, req *TransportRequest) (*TransportResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	httpReq.Header = req.Headers.Clone()

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &TransportResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       body,
	}, nil
}
