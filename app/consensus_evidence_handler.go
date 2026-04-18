package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type consensusEvidenceAuditErrorResponse struct {
	Error string `json:"error"`
}

const (
	adminAuditAuthTokenEnv = "AETHELRED_ADMIN_API_TOKEN"
	adminAuditMaxBodyBytes = 4 << 20
)

var errConsensusAuditUnauthorized = errors.New("admin consensus audit endpoint requires loopback access or a valid bearer token")

// ConsensusEvidenceAuditHandler exposes deterministic consensus evidence
// auditing for proposal preflight checks.
func (app *AethelredApp) ConsensusEvidenceAuditHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if err := authorizeLoopbackOrBearer(r, adminAuditAuthTokenEnv, errConsensusAuditUnauthorized.Error()); err != nil {
			writeConsensusAuditError(w, http.StatusForbidden, err.Error())
			return
		}

		if r.ContentLength > adminAuditMaxBodyBytes {
			writeConsensusAuditError(w, http.StatusRequestEntityTooLarge, "request body exceeds admin audit size limit")
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, adminAuditMaxBodyBytes)

		var req ConsensusEvidenceAuditRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			if strings.Contains(err.Error(), "http: request body too large") {
				writeConsensusAuditError(w, http.StatusRequestEntityTooLarge, "request body exceeds admin audit size limit")
				return
			}
			writeConsensusAuditError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		resp, err := RunConsensusEvidenceAudit(req)
		if err != nil {
			writeConsensusAuditError(w, http.StatusBadRequest, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func writeConsensusAuditError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(consensusEvidenceAuditErrorResponse{Error: msg})
}
