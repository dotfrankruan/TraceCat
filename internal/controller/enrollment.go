package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	// enrollmentBodyLimit is intentionally the same strict bound as job
	// creation; enrollment bodies are tiny.
	enrollmentBodyLimit = 8 << 10

	// enrollmentPerIPPerMinute and enrollmentGlobalPerMinute bound credential
	// guessing and registration churn. Both are token buckets.
	enrollmentPerIPPerMinute  = 30
	enrollmentGlobalPerMinute = 120

	// enrollmentAgentTokenBytes is the entropy of the per-Agent trace token
	// returned to an enrolled Agent (base64url encoded, so 43 characters).
	enrollmentAgentTokenBytes = 32

	maxEnrollmentProtocols = 8
)

// handleEnroll implements POST /api/v1/agents/enroll. It is the only
// Controller endpoint authenticated by the shared enrollment secret instead of
// browser credentials; CSRF and session/JWT authentication do not apply here.
func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.EnrollmentEnabled() {
		writeError(w, model.ErrNotFound, "not found")
		return
	}

	client := clientIP(r, a.cfg.TrustedProxyPrefixes())
	if !a.enrollIPLimiter.Allow(client) || !a.enrollGlobalLimiter.Allow("global") {
		w.Header().Set("Retry-After", "60")
		writeError(w, model.ErrRateLimited, "too many enrollment attempts")
		return
	}

	provided, ok := bearerToken(r)
	if !ok || !constantTimeTokenEqual(provided, a.cfg.EnrollmentToken()) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, model.ErrUnauthorized, "invalid enrollment credentials")
		return
	}

	var req model.AgentEnrollRequest
	if apiErr := decodeJSONBody(w, r, enrollmentBodyLimit, &req); apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}

	record, apiErr := buildEnrollmentRecord(&req)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}

	// Static configuration always wins; never let an enrollment override it.
	if a.registry.StaticNodeID(record.NodeID) {
		writeError(w, model.ErrConflict, "node id is statically configured")
		return
	}

	agentToken, err := generateAgentToken()
	if err != nil {
		a.logger.Error("could not generate an agent token")
		writeError(w, model.ErrInternal, "internal error")
		return
	}
	now := a.now().UTC()
	record.AgentToken = agentToken
	record.CreatedAt = now
	record.UpdatedAt = now
	record.LastSeenAt = now

	if _, err := a.registry.RegisterAuto(r.Context(), record); err != nil {
		switch {
		case errors.Is(err, ErrStaticNodeCollision):
			writeError(w, model.ErrConflict, "node id is statically configured")
		case errors.Is(err, ErrRegistryHasNoStore):
			a.logger.Error("auto-enrollment is not wired to the store")
			writeError(w, model.ErrInternal, "internal error")
		default:
			a.logger.Error("could not persist enrolled agent", "node_id", record.NodeID)
			writeError(w, model.ErrInternal, "internal error")
		}
		return
	}

	// Never log the agent token or the enrollment secret.
	a.logger.Info("agent enrolled", "node_id", record.NodeID, "source", string(model.NodeSourceAuto))
	writeJSON(w, http.StatusOK, model.AgentEnrollResponse{
		SchemaVersion: model.ControllerSchemaVersion,
		NodeID:        record.NodeID,
		AgentToken:    agentToken,
		TraceURL:      record.URL,
		RefreshAfterS: a.cfg.EnrollmentRefreshSeconds(),
	})
}

// buildEnrollmentRecord validates and sanitizes an enrollment request. The
// advertised URL is checked with exactly the same transport policy as static
// Agent configuration.
func buildEnrollmentRecord(req *model.AgentEnrollRequest) (RegisteredAgent, *model.APIError) {
	if req.SchemaVersion != model.AgentSchemaVersion {
		return RegisteredAgent{}, model.NewError(model.ErrInvalidRequest, "unsupported schema_version")
	}
	if err := model.ValidateNodeID(req.NodeID); err != nil {
		return RegisteredAgent{}, model.NewError(model.ErrInvalidRequest, "invalid node_id")
	}
	name := model.SanitizeText(req.Name, 64)
	if name == "" {
		return RegisteredAgent{}, model.NewError(model.ErrInvalidRequest, "name is required")
	}
	normalizedURL, err := normalizeEnrolledAgentURL(req.URL)
	if err != nil {
		return RegisteredAgent{}, model.NewError(model.ErrInvalidRequest, "invalid url: "+err.Error())
	}
	protocols, apiErr := normalizeEnrollmentProtocols(req.Protocols)
	if apiErr != nil {
		return RegisteredAgent{}, apiErr
	}
	return RegisteredAgent{
		NodeID:           req.NodeID,
		Name:             name,
		Location:         model.SanitizeText(req.Location, 128),
		Provider:         model.SanitizeText(req.Provider, 128),
		URL:              normalizedURL,
		Protocols:        protocols,
		NextTraceVersion: model.SanitizeText(req.NextTraceVersion, 64),
	}, nil
}

// normalizeEnrolledAgentURL validates and canonicalizes an Agent-advertised
// base URL. The same rules as static agent configuration apply: http/https
// only, no credentials/query/fragment/path, https for hostnames and public IPs,
// cleartext http only for literal non-public addresses.
func normalizeEnrolledAgentURL(raw string) (string, error) {
	if err := validateAgentURL(raw); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("must be an absolute URL")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// normalizeEnrollmentProtocols validates the Agent-advertised protocol list.
// Unknown names are rejected; duplicates are collapsed while preserving order.
// An empty list (older Agents) is allowed.
func normalizeEnrollmentProtocols(raw []string) ([]string, *model.APIError) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxEnrollmentProtocols {
		return nil, model.NewError(model.ErrInvalidRequest, "too many protocols")
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		name := strings.ToLower(strings.TrimSpace(item))
		protocol := model.Protocol(name)
		if !protocol.Valid() {
			return nil, model.NewError(model.ErrInvalidRequest, "unsupported protocol")
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

// bearerToken extracts a Bearer credential from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value == "" {
		return "", false
	}
	scheme, token, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// constantTimeTokenEqual compares two bearer tokens without leaking length or
// prefix information through timing. Hashing first makes the comparison a fixed
// 32-byte constant-time compare even for attacker-chosen lengths.
func constantTimeTokenEqual(provided, want string) bool {
	if want == "" || provided == "" {
		return false
	}
	providedHash := sha256.Sum256([]byte(provided))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(providedHash[:], wantHash[:]) == 1
}

// generateAgentToken returns a fresh 256-bit per-Agent bearer token.
func generateAgentToken() (string, error) {
	buf := make([]byte, enrollmentAgentTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
