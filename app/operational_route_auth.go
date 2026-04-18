package app

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

func authorizeLoopbackOrBearer(r *http.Request, envVar string, errMsg string) error {
	if isLoopbackRemoteAddr(r.RemoteAddr) {
		return nil
	}

	expectedToken := strings.TrimSpace(os.Getenv(envVar))
	if expectedToken == "" {
		return operationalRouteAuthError(errMsg)
	}

	providedToken, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok {
		return operationalRouteAuthError(errMsg)
	}

	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
		return operationalRouteAuthError(errMsg)
	}

	return nil
}

type operationalRouteAuthError string

func (e operationalRouteAuthError) Error() string {
	return string(e)
}

func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}
	return token, true
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return false
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}
