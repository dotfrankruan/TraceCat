package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
	"github.com/dotfrankruan/tracecat/internal/webui"
)

const (
	resolveBodyLimit   = 1 << 10 // 1 KiB
	createJobBodyLimit = 8 << 10 // 8 KiB
	loginBodyLimit     = 4 << 10 // 4 KiB

	defaultSSEHeartbeat = 15 * time.Second
)

// API is the browser-facing HTTP surface. It contains no Agent URLs or secrets.
type API struct {
	cfg                 *Config
	store               *Store
	resolver            *ResolverService
	registry            *Registry
	manager             *Manager
	auth                *Auth
	logger              *slog.Logger
	resolveLimiter      *rateLimiter
	enrollIPLimiter     *rateLimiter
	enrollGlobalLimiter *rateLimiter
	sseHeartbeat        time.Duration
	now                 func() time.Time
}

// APIOption customizes the API service (tests inject auth/verifier and a fast
// SSE heartbeat).
type APIOption func(*API)

// WithAPIAuth injects a pre-built Auth (for Cloudflare Access tests).
func WithAPIAuth(auth *Auth) APIOption {
	return func(a *API) { a.auth = auth }
}

// WithAPISSEHeartbeat overrides the SSE keepalive interval.
func WithAPISSEHeartbeat(d time.Duration) APIOption {
	return func(a *API) {
		if d > 0 {
			a.sseHeartbeat = d
		}
	}
}

// WithAPILogger injects the structured logger.
func WithAPILogger(logger *slog.Logger) APIOption {
	return func(a *API) {
		if logger != nil {
			a.logger = logger
		}
	}
}

// NewAPI builds the HTTP API.
func NewAPI(cfg *Config, store *Store, resolver *ResolverService, registry *Registry, manager *Manager, logger *slog.Logger, opts ...APIOption) (*API, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	api := &API{
		cfg:                 cfg,
		store:               store,
		resolver:            resolver,
		registry:            registry,
		manager:             manager,
		logger:              logger,
		resolveLimiter:      newRateLimiter(float64(cfg.Limits.MaxResolvesPerMinute)),
		enrollIPLimiter:     newRateLimiter(enrollmentPerIPPerMinute),
		enrollGlobalLimiter: newRateLimiter(enrollmentGlobalPerMinute),
		sseHeartbeat:        defaultSSEHeartbeat,
		now:                 time.Now,
	}
	for _, opt := range opts {
		opt(api)
	}
	if api.auth == nil {
		auth, err := NewAuth(cfg, store)
		if err != nil {
			return nil, err
		}
		api.auth = auth
	}
	return api, nil
}

// Auth returns the authentication service (used by main for diagnostics).
func (a *API) Auth() *Auth { return a.auth }

// Handler builds the complete HTTP handler: API routes win over the embedded
// single-page dashboard, and every response carries the security headers.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", a.endpoint(a.handleHealthz, endpointOptions{methods: []string{http.MethodGet}}))
	mux.HandleFunc(model.EnrollmentPath, a.endpoint(a.handleEnroll, endpointOptions{methods: []string{http.MethodPost}}))
	mux.HandleFunc("/api/v1/session", a.endpoint(a.handleSession, endpointOptions{methods: []string{http.MethodGet}, auth: true}))
	mux.HandleFunc("/api/v1/auth/login", a.localOnly(a.endpoint(a.handleLogin, endpointOptions{methods: []string{http.MethodPost}})))
	mux.HandleFunc("/api/v1/auth/logout", a.localOnly(a.endpoint(a.handleLogout, endpointOptions{
		methods: []string{http.MethodPost}, auth: true, csrf: true,
	})))
	mux.HandleFunc("/api/v1/nodes", a.endpoint(a.handleNodes, endpointOptions{methods: []string{http.MethodGet}, auth: true}))
	mux.HandleFunc("/api/v1/resolve", a.endpoint(a.handleResolve, endpointOptions{
		methods: []string{http.MethodPost}, auth: true, csrf: true,
	}))
	mux.HandleFunc("/api/v1/jobs", a.endpoint(a.handleJobsCollection, endpointOptions{
		methods: []string{http.MethodGet, http.MethodPost}, auth: true, csrf: true,
	}))
	mux.HandleFunc("/api/v1/jobs/{id}", a.endpoint(a.handleJob, endpointOptions{methods: []string{http.MethodGet}, auth: true}))
	mux.HandleFunc("/api/v1/jobs/{id}/cancel", a.endpoint(a.handleCancelJob, endpointOptions{
		methods: []string{http.MethodPost}, auth: true, csrf: true,
	}))
	mux.HandleFunc("/api/v1/jobs/{id}/events", a.endpoint(a.handleJobEvents, endpointOptions{methods: []string{http.MethodGet}, auth: true}))
	mux.HandleFunc("/api/v1/jobs/{id}/export", a.endpoint(a.handleExportJob, endpointOptions{methods: []string{http.MethodGet}, auth: true}))
	mux.HandleFunc("/api/", a.handleAPINotFound)
	mux.Handle("/", webui.Handler())

	var handler http.Handler = mux
	handler = requestLogger(a.logger, a.cfg.TrustedProxyPrefixes(), handler)
	handler = recoverPanics(a.logger, handler)
	if a.cfg.Auth.Mode == AuthModeDev {
		// Dev mode must never be reached through a proxy: reject every request
		// that carries forwarding headers, including liveness probes.
		handler = devProxyHeaderGuard(handler)
	}
	handler = securityHeaders(handler)
	return handler
}

type endpointOptions struct {
	methods []string
	auth    bool
	csrf    bool
}

func (a *API) endpoint(handler http.HandlerFunc, opts endpointOptions) http.HandlerFunc {
	h := handler
	if opts.csrf {
		h = a.auth.RequireCSRF(h).ServeHTTP
	}
	if opts.auth {
		h = a.auth.RequireAuth(http.HandlerFunc(h)).ServeHTTP
	}
	if len(opts.methods) > 0 {
		h = allowedMethods(h, opts.methods...)
	}
	return h
}

// localOnly returns 404 for endpoints that only exist in local auth mode.
func (a *API) localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Auth.Mode != AuthModeLocal {
			writeError(w, model.ErrNotFound, "not found")
			return
		}
		next(w, r)
	}
}

func (a *API) handleAPINotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, model.ErrNotFound, "not found")
}

func (a *API) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Status        string `json:"status"`
		SchemaVersion string `json:"schema_version"`
	}{Status: "ok", SchemaVersion: model.ControllerSchemaVersion})
}

func (a *API) handleSession(w http.ResponseWriter, r *http.Request) {
	principal := PrincipalFrom(r.Context())
	if principal == nil {
		writeAPIError(w, http.StatusUnauthorized, model.NewError(model.ErrUnauthorized, "authentication required"))
		return
	}
	writeJSON(w, http.StatusOK, a.auth.SessionResponse(principal))
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Auth.Mode != AuthModeLocal {
		writeError(w, model.ErrNotFound, "not found")
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeAPIError(w, http.StatusUnsupportedMediaType, model.NewError(model.ErrInvalidRequest, "Content-Type must be application/json"))
		return
	}
	var req model.LoginRequest
	if apiErr := decodeJSONBody(w, r, loginBodyLimit, &req); apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	principal, apiErr := a.auth.Login(r.Context(), clientIP(r, a.cfg.TrustedProxyPrefixes()), req.Password)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	a.auth.SetSessionCookie(w, principal)
	writeJSON(w, http.StatusOK, a.auth.SessionResponse(principal))
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Auth.Mode != AuthModeLocal {
		writeError(w, model.ErrNotFound, "not found")
		return
	}
	principal := PrincipalFrom(r.Context())
	if principal == nil {
		writeAPIError(w, http.StatusUnauthorized, model.NewError(model.ErrUnauthorized, "authentication required"))
		return
	}
	if apiErr := a.auth.RevokeSession(r.Context(), principal); apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	a.auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleNodes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, model.NodeList{Nodes: a.registry.NodeInfos()})
}

func (a *API) handleResolve(w http.ResponseWriter, r *http.Request) {
	var req model.ResolveRequest
	if apiErr := decodeJSONBody(w, r, resolveBodyLimit, &req); apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	if !a.resolveLimiter.Allow(clientIP(r, a.cfg.TrustedProxyPrefixes())) {
		writeError(w, model.ErrRateLimited, "resolve rate limit exceeded")
		return
	}
	resp, apiErr := a.resolver.Resolve(r.Context(), req.Target)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleJobsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleListJobs(w, r)
	case http.MethodPost:
		a.handleCreateJob(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeAPIError(w, http.StatusMethodNotAllowed, model.NewError(model.ErrInvalidRequest, "method not allowed"))
	}
}

func (a *API) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req model.CreateJobRequest
	if apiErr := decodeJSONBody(w, r, createJobBodyLimit, &req); apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	principal := PrincipalFrom(r.Context())
	job, apiErr := a.manager.CreateJob(r.Context(), principal, clientIP(r, a.cfg.TrustedProxyPrefixes()), &req)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusAccepted, model.JobResponse{Job: *job})
}

func (a *API) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 {
			writeError(w, model.ErrInvalidRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
		if limit > 100 {
			limit = 100
		}
	}
	items, apiErr := a.manager.ListJobs(r.Context(), limit)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	if items == nil {
		items = []model.JobListItem{}
	}
	writeJSON(w, http.StatusOK, model.JobList{Jobs: items})
}

func (a *API) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, apiErr := a.manager.GetJob(r.Context(), id)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusOK, model.JobResponse{Job: *job})
}

func (a *API) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, apiErr := a.manager.CancelJob(r.Context(), id)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	writeJSON(w, http.StatusOK, model.JobResponse{Job: *job})
}

func (a *API) handleExportJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	export, apiErr := a.manager.Export(r.Context(), id)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "tracecat-"+id+".json"))
	writeJSON(w, http.StatusOK, export)
}

func (a *API) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, model.ErrInternal, "streaming is not supported")
		return
	}
	// Subscribe before taking the snapshot so no state change can be missed
	// between the initial snapshot and the stream loop.
	snapshots, unsubscribe := a.manager.Subscribe(id)
	defer unsubscribe()

	job, apiErr := a.manager.GetJob(r.Context(), id)
	if apiErr != nil {
		writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if err := writeSSEEvent(w, *job); err != nil {
		return
	}
	flusher.Flush()
	if jobIsTerminal(job.Status) {
		return
	}

	heartbeat := time.NewTicker(a.sseHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case snapshot, open := <-snapshots:
			if !open {
				return
			}
			if err := writeSSEEvent(w, snapshot); err != nil {
				return
			}
			flusher.Flush()
			if jobIsTerminal(snapshot.Status) {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, job model.Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", model.SSEEventJob, data)
	return err
}

// devProxyHeaderGuard rejects requests carrying forwarding headers in dev
// mode, so a loopback-only bypass cannot be exposed through a reverse proxy.
func devProxyHeaderGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"} {
			if strings.TrimSpace(r.Header.Get(header)) != "" {
				writeError(w, model.ErrForbidden, "proxy headers are not permitted in dev mode")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RunHealthPoller is a convenience used by main to start the node health
// poller with the configured interval.
func RunHealthPoller(ctx context.Context, registry *Registry, interval time.Duration) {
	registry.Start(ctx, interval)
}
