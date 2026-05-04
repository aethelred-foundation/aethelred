package audit

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// RequestAuthorizer decides whether a generic mutating HTTP request is
// authorized.
type RequestAuthorizer interface {
	AuthorizeRequest(r *http.Request) error
}

// ControlLedgerWriteAuthorizer decides whether a mutating control-ledger HTTP
// request is authorized.
type ControlLedgerWriteAuthorizer interface {
	Authorize(r *http.Request, req *PutControlLedgerRequest) error
}

// StaticBearerTokenAuthorizer requires a matching bearer token in the
// Authorization header.
type StaticBearerTokenAuthorizer struct {
	token string
}

// NewStaticBearerTokenAuthorizer creates a bearer-token authorizer.
func NewStaticBearerTokenAuthorizer(token string) (*StaticBearerTokenAuthorizer, error) {
	normalizedToken := strings.TrimSpace(token)
	if normalizedToken == "" {
		return nil, fmt.Errorf("audit/auth: %w: bearer token is required", ErrInvalidInput)
	}
	return &StaticBearerTokenAuthorizer{token: normalizedToken}, nil
}

// Authorize checks the Authorization header for a matching bearer token.
func (a *StaticBearerTokenAuthorizer) Authorize(r *http.Request, _ *PutControlLedgerRequest) error {
	if a == nil {
		return fmt.Errorf("audit/auth: %w: authorizer is nil", ErrInvalidInput)
	}
	return authorizeBearerToken(r, a.token)
}

// StaticBearerTokenRequestAuthorizer requires a matching bearer token for a
// generic privileged HTTP mutation.
type StaticBearerTokenRequestAuthorizer struct {
	token string
}

// NewStaticBearerTokenRequestAuthorizer creates a generic bearer-token request
// authorizer.
func NewStaticBearerTokenRequestAuthorizer(token string) (*StaticBearerTokenRequestAuthorizer, error) {
	normalizedToken := strings.TrimSpace(token)
	if normalizedToken == "" {
		return nil, fmt.Errorf("audit/auth: %w: bearer token is required", ErrInvalidInput)
	}
	return &StaticBearerTokenRequestAuthorizer{token: normalizedToken}, nil
}

// AuthorizeRequest checks the Authorization header for a matching bearer
// token.
func (a *StaticBearerTokenRequestAuthorizer) AuthorizeRequest(r *http.Request) error {
	if a == nil {
		return fmt.Errorf("audit/auth: %w: authorizer is nil", ErrInvalidInput)
	}
	return authorizeBearerToken(r, a.token)
}

// DisabledWriteAuthorizer denies all mutating requests with a stable reason.
type DisabledWriteAuthorizer struct {
	reason string
}

// NewDisabledWriteAuthorizer creates an authorizer that disables writes.
func NewDisabledWriteAuthorizer(reason string) *DisabledWriteAuthorizer {
	return &DisabledWriteAuthorizer{reason: strings.TrimSpace(reason)}
}

// Authorize always rejects the request because writes are disabled.
func (a *DisabledWriteAuthorizer) Authorize(_ *http.Request, _ *PutControlLedgerRequest) error {
	if a == nil {
		return fmt.Errorf("audit/auth: %w: control-ledger writes are disabled", ErrWriteDisabled)
	}
	return disabledReasonError(a.reason)
}

// DisabledRequestAuthorizer denies privileged request mutations with a stable
// reason.
type DisabledRequestAuthorizer struct {
	reason string
}

// NewDisabledRequestAuthorizer creates a disabled request authorizer.
func NewDisabledRequestAuthorizer(reason string) *DisabledRequestAuthorizer {
	return &DisabledRequestAuthorizer{reason: strings.TrimSpace(reason)}
}

// AuthorizeRequest always rejects the request because writes are disabled.
func (a *DisabledRequestAuthorizer) AuthorizeRequest(_ *http.Request) error {
	if a == nil {
		return fmt.Errorf("audit/auth: %w: request writes are disabled", ErrWriteDisabled)
	}
	return disabledReasonError(a.reason)
}

func authorizeBearerToken(r *http.Request, expectedToken string) error {
	presentedToken, err := extractBearerToken(r)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(presentedToken), []byte(expectedToken)) != 1 {
		return fmt.Errorf("audit/auth: %w: invalid bearer token", ErrUnauthorized)
	}
	return nil
}

func disabledReasonError(reason string) error {
	if strings.TrimSpace(reason) != "" {
		return fmt.Errorf("audit/auth: %w: %s", ErrWriteDisabled, strings.TrimSpace(reason))
	}
	return fmt.Errorf("audit/auth: %w: writes are disabled", ErrWriteDisabled)
}

func extractBearerToken(r *http.Request) (string, error) {
	if r == nil {
		return "", fmt.Errorf("audit/auth: %w: request is required", ErrInvalidInput)
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", fmt.Errorf("audit/auth: %w: missing bearer token", ErrUnauthorized)
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("audit/auth: %w: expected Authorization: Bearer <token>", ErrUnauthorized)
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("audit/auth: %w: empty bearer token", ErrUnauthorized)
	}
	return token, nil
}

// AnyOfControlLedgerWriteAuthorizer authorizes a request if any configured
// strategy authorizes it successfully.
type AnyOfControlLedgerWriteAuthorizer struct {
	strategies []ControlLedgerWriteAuthorizer
}

// NewAnyOfControlLedgerWriteAuthorizer creates a composite authorizer.
func NewAnyOfControlLedgerWriteAuthorizer(strategies ...ControlLedgerWriteAuthorizer) *AnyOfControlLedgerWriteAuthorizer {
	filtered := make([]ControlLedgerWriteAuthorizer, 0, len(strategies))
	for _, strategy := range strategies {
		if strategy != nil {
			filtered = append(filtered, strategy)
		}
	}
	return &AnyOfControlLedgerWriteAuthorizer{strategies: filtered}
}

// Authorize succeeds if any strategy authorizes the request.
func (a *AnyOfControlLedgerWriteAuthorizer) Authorize(r *http.Request, req *PutControlLedgerRequest) error {
	if a == nil || len(a.strategies) == 0 {
		return fmt.Errorf("audit/auth: %w: no authorization strategies configured", ErrWriteDisabled)
	}

	var unauthorizedErr error
	var disabledErr error
	for _, strategy := range a.strategies {
		err := strategy.Authorize(r, req)
		if err == nil {
			return nil
		}
		switch {
		case errors.Is(err, ErrUnauthorized):
			unauthorizedErr = err
		case errors.Is(err, ErrWriteDisabled):
			disabledErr = err
		default:
			unauthorizedErr = err
		}
	}

	if unauthorizedErr != nil {
		return unauthorizedErr
	}
	if disabledErr != nil {
		return disabledErr
	}
	return fmt.Errorf("audit/auth: %w: authorization failed", ErrUnauthorized)
}
