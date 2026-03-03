package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdktypes "github.com/aethelred/sdk-go/types"
	"github.com/stretchr/testify/require"
)

func TestNewClient_ResolvesDefaultsAndModules(t *testing.T) {
	t.Parallel()

	c, err := NewClient(Local)
	require.NoError(t, err)

	require.Equal(t, "http://127.0.0.1:26657", c.RPCURL())
	require.Equal(t, "aethelred-local", c.ChainID())
	require.NotNil(t, c.Jobs)
	require.NotNil(t, c.Seals)
	require.NotNil(t, c.Models)
	require.NotNil(t, c.Validators)
	require.NotNil(t, c.Verification)
}

func TestClientGet_AddsHeadersAndDecodesJSON(t *testing.T) {
	t.Parallel()

	var gotAPIKey string
	var gotUserAgent string
	var gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		gotUserAgent = r.Header.Get("User-Agent")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL), WithAPIKey("test-key"), WithTimeout(2*time.Second))
	require.NoError(t, err)

	var resp map[string]string
	err = c.Get(context.Background(), "/ping", &resp)
	require.NoError(t, err)
	require.Equal(t, "/ping", gotPath)
	require.Equal(t, "test-key", gotAPIKey)
	require.Equal(t, "aethelred-sdk-go/1.0.0", gotUserAgent)
	require.Equal(t, "true", resp["ok"])
}

func TestClientGet_RateLimitMapsToTypedError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	err = c.Get(context.Background(), "/limited", &map[string]any{})
	require.ErrorIs(t, err, sdktypes.ErrRateLimited)
}

func TestHealthCheck_ReturnsFalseOnFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	require.False(t, c.HealthCheck(context.Background()))
}

func TestNetworkConfig_KnownNetworks(t *testing.T) {
	t.Parallel()

	require.Equal(t, "aethelred-1", Mainnet.Config().ChainID)
	require.Equal(t, "aethelred-testnet-1", Testnet.Config().ChainID)
	require.Equal(t, "http://127.0.0.1:26657", Local.Config().RPCURL)
}

func TestNetworkConfig_UnknownFallsBackToMainnet(t *testing.T) {
	t.Parallel()

	cfg := Network("unknown").Config()
	require.Equal(t, Mainnet.Config(), cfg)
}

func TestDefaultConfig_HasExpectedDefaults(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	require.Equal(t, Mainnet, cfg.Network)
	require.Equal(t, 30*time.Second, cfg.Timeout)
	require.Equal(t, 3, cfg.MaxRetries)
}

func TestClientPost_MarshalsBodyAndDecodesResponse(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		err := json.NewDecoder(r.Body).Decode(&gotBody)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"tx": "ok"})
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	var resp map[string]string
	err = c.Post(context.Background(), "/submit", map[string]any{"foo": "bar"}, &resp)
	require.NoError(t, err)
	require.Equal(t, "bar", gotBody["foo"])
	require.Equal(t, "ok", resp["tx"])
}

func TestClientRequest_HTTPErrorIncludesStatusAndBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request payload"))
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	err = c.Get(context.Background(), "/fail", &map[string]any{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 400")
	require.Contains(t, err.Error(), "bad request payload")
}

func TestGetNodeInfo_UnwrapsResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/cosmos/base/tendermint/v1beta1/node_info", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"default_node_info": map[string]any{
				"default_node_id": "node1",
				"listen_addr":     "tcp://0.0.0.0:26656",
				"network":         "aethelred-local",
				"version":         "1.0.0",
				"moniker":         "local",
			},
		})
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	info, err := c.GetNodeInfo(context.Background())
	require.NoError(t, err)
	require.Equal(t, "node1", info.DefaultNodeID)
	require.Equal(t, "aethelred-local", info.Network)
}

func TestHealthCheck_ReturnsTrueOnSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"default_node_info": map[string]any{
				"default_node_id": "node1",
				"listen_addr":     "tcp://0.0.0.0:26656",
				"network":         "aethelred-local",
				"version":         "1.0.0",
				"moniker":         "local",
			},
		})
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL))
	require.NoError(t, err)

	require.True(t, c.HealthCheck(context.Background()))
}

func TestClientPost_MarshalErrorPropagates(t *testing.T) {
	t.Parallel()

	c, err := NewClient(Local, WithRPCURL("http://example.invalid"))
	require.NoError(t, err)

	err = c.Post(context.Background(), "/submit", map[string]any{"bad": make(chan int)}, &map[string]any{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to marshal request")
}

func TestClientRequest_ContextCancellationPropagates(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer srv.Close()

	c, err := NewClient(Local, WithRPCURL(srv.URL), WithTimeout(2*time.Second))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err = c.Get(ctx, "/slow", &map[string]string{})
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "request failed") || strings.Contains(err.Error(), "context deadline"))
}

type mockTransport struct {
	lastReq *TransportRequest
	resp    *TransportResponse
	err     error
}

func (m *mockTransport) Do(_ context.Context, req *TransportRequest) (*TransportResponse, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

func TestClient_UsesCustomTransport(t *testing.T) {
	t.Parallel()

	mt := &mockTransport{
		resp: &TransportResponse{
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": []string{"application/json"}},
			Body:       []byte(`{"ok":"true"}`),
		},
	}

	c, err := NewClient(Local, WithGRPCTransport(mt), WithAPIKey("k1"))
	require.NoError(t, err)

	var out map[string]string
	err = c.Get(context.Background(), "/custom", &out)
	require.NoError(t, err)
	require.Equal(t, "true", out["ok"])
	require.NotNil(t, mt.lastReq)
	require.Equal(t, http.MethodGet, mt.lastReq.Method)
	require.Equal(t, "/custom", strings.TrimPrefix(mt.lastReq.URL, c.RPCURL()))
	require.Equal(t, "k1", mt.lastReq.Headers.Get("X-API-Key"))
}

func TestNewClient_AppliesConnectionPoolConfig(t *testing.T) {
	t.Parallel()

	c, err := NewClient(Local, WithConnectionPool(ConnectionPoolConfig{
		MaxIdleConns:        77,
		MaxIdleConnsPerHost: 11,
		MaxConnsPerHost:     22,
		IdleConnTimeout:     42 * time.Second,
	}))
	require.NoError(t, err)

	transport, ok := c.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.Equal(t, 77, transport.MaxIdleConns)
	require.Equal(t, 11, transport.MaxIdleConnsPerHost)
	require.Equal(t, 22, transport.MaxConnsPerHost)
	require.Equal(t, 42*time.Second, transport.IdleConnTimeout)
}
