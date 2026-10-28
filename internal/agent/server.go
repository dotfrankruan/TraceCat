package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
	"github.com/dotfrankruan/tracecat/internal/nexttrace"
	"github.com/dotfrankruan/tracecat/internal/version"
)

const (
	maxRequestBodyBytes = 64 << 10
	maxHeaderBytes      = 16 << 10
	readHeaderTimeout   = 5 * time.Second
	readTimeout         = 15 * time.Second
	idleTimeout         = 60 * time.Second
	shutdownGracePeriod = 15 * time.Second
)

// Agent is the TraceCat Agent HTTP service.
type Agent struct {
	cfg    Config
	logger *slog.Logger

	auth   tokenAuth
	policy ipguard.Policy
	runner *nexttrace.Runner
	caps   nexttrace.Capabilities
	info   model.NextTraceInfo
	limits model.AgentLimits

	limiter   *rateLimiter
	httpSem   chan struct{}
	traceSem  chan struct{}
	protocols []model.Protocol

	handler http.Handler
	baseCtx context.Context
	cancel  context.CancelFunc
}

// New validates cfg, detects the installed NextTrace binary and prepares the
// HTTP service. An unusable NextTrace binary does not prevent startup: the
// Agent starts in a degraded state so /v1/health can report the problem.
func New(cfg Config, logger *slog.Logger) (*Agent, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("node_id", cfg.NodeID)

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	token, ok := os.LookupEnv(cfg.Auth.TokenEnv)
	if !ok || len(token) < minTokenLength {
		return nil, fmt.Errorf("auth.token_env %q must be set and contain at least %d characters", cfg.Auth.TokenEnv, minTokenLength)
	}
	policy, err := buildPolicy(cfg.Security)
	if err != nil {
		return nil, fmt.Errorf("building target policy: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	agent := &Agent{
		cfg:      cfg,
		logger:   logger,
		auth:     newTokenAuth(token),
		policy:   policy,
		limiter:  newRateLimiter(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst),
		httpSem:  make(chan struct{}, cfg.RateLimit.MaxConcurrentHTTP),
		traceSem: make(chan struct{}, cfg.NextTrace.MaxConcurrentTraces),
		baseCtx:  ctx,
		cancel:   cancel,
	}

	caps, detectErr := nexttrace.Detect(context.Background(), cfg.NextTrace.Binary)
	agent.caps = caps
	agent.info = model.NextTraceInfo{
		Available:    caps.Available(),
		Version:      caps.Version,
		Capabilities: caps.CapabilityNames(),
	}
	if !agent.info.Available {
		if detectErr == nil {
			detectErr = model.NewError(model.ErrNextTraceMissing, "nexttrace is not available")
		}
		agent.info.Error = detectErr
		logger.Warn("nexttrace is not usable; agent starts degraded", "error", detectErr.Message)
	} else {
		logger.Info("nexttrace detected", "nexttrace_version", caps.Version, "capabilities", agent.info.Capabilities)
	}
	agent.runner = nexttrace.NewRunner(cfg.NextTrace.Binary, caps)

	configuredProtocols, err := model.ParseProtocolList(cfg.NextTrace.AllowedProtocols)
	if err != nil {
		return nil, fmt.Errorf("nexttrace.allowed_protocols: %s", errorMessage(err))
	}
	agent.protocols = make([]model.Protocol, 0, len(configuredProtocols))
	for _, protocol := range configuredProtocols {
		if caps.SupportsProtocol(protocol) {
			agent.protocols = append(agent.protocols, protocol)
		}
	}
	agent.limits = model.AgentLimits{
		MaxHops:             model.MaxMaxHops,
		MaxQueries:          model.MaxQueries,
		MaxTimeoutMS:        cfg.NextTrace.MaxExecutionMS,
		MaxConcurrentTraces: cfg.NextTrace.MaxConcurrentTraces,
		Protocols:           model.ProtocolNames(agent.protocols),
	}
	agent.handler = http.HandlerFunc(agent.serveHTTP)
	return agent, nil
}

// Handler exposes the authenticated HTTP handler (used by tests and Run).
func (a *Agent) Handler() http.Handler { return a.handler }

// Info returns the safe NextTrace description reported by /v1/health.
func (a *Agent) Info() model.NextTraceInfo { return a.info }

// Limits returns the enforced limits reported by /v1/health.
func (a *Agent) Limits() model.AgentLimits { return a.limits }

// Run listens on the configured address and serves until ctx is cancelled or
// the listener fails. On shutdown it stops accepting new requests, cancels
// in-flight traces (killing their process groups) and waits a bounded time.
func (a *Agent) Run(ctx context.Context) error {
	addr, port, err := a.cfg.ListenAddr()
	if err != nil {
		return err
	}
	listenAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(port)))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}

	writeTimeout := time.Duration(a.cfg.NextTrace.MaxExecutionMS)*time.Millisecond + 30*time.Second
	server := &http.Server{
		Handler:           a.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		BaseContext:       func(net.Listener) context.Context { return a.baseCtx },
		ErrorLog:          slog.NewLogLogger(a.logger.Handler(), slog.LevelWarn),
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	a.logger.Info("agent listening", "listen", listenAddr, "nexttrace_available", a.info.Available)

	select {
	case <-ctx.Done():
		a.logger.Info("shutdown requested; cancelling in-flight traces")
		a.cancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
		}
		return nil
	case err := <-serveErr:
		a.cancel()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Close cancels the agent context without a listener (used by tests).
func (a *Agent) Close() { a.cancel() }

// trackedWriter records whether a response has been committed so panic
// recovery never attempts to rewrite headers.
type trackedWriter struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (w *trackedWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (a *Agent) serveHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &trackedWriter{ResponseWriter: w}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	defer func() {
		if recovered := recover(); recovered != nil {
			a.logger.Error("panic while handling request", "method", r.Method, "path", r.URL.Path)
			if !rec.wroteHeader {
				writeError(rec, http.StatusInternalServerError, model.ErrInternal, "internal error")
			}
		}
	}()

	if !a.acquireHTTP() {
		writeError(rec, http.StatusServiceUnavailable, model.ErrBusy, "too many concurrent requests")
		return
	}
	defer a.releaseHTTP()

	if allowed, wait := a.limiter.allow(remoteIP(r)); !allowed {
		rec.Header().Set("Retry-After", rateLimitRetryAfterHeader(wait))
		writeError(rec, http.StatusTooManyRequests, model.ErrRateLimited, "rate limit exceeded")
		return
	}

	if !a.auth.authorized(r) {
		rec.Header().Set("WWW-Authenticate", "Bearer")
		writeError(rec, http.StatusUnauthorized, model.ErrUnauthorized, "missing or invalid bearer token")
		return
	}

	switch r.URL.Path {
	case "/v1/health":
		if r.Method != http.MethodGet {
			methodNotAllowed(rec, http.MethodGet)
			return
		}
		a.handleHealth(rec)
	case "/v1/trace":
		if r.Method != http.MethodPost {
			methodNotAllowed(rec, http.MethodPost)
			return
		}
		a.handleTrace(rec, r)
	default:
		writeError(rec, http.StatusNotFound, model.ErrNotFound, "not found")
	}
}

func (a *Agent) acquireHTTP() bool {
	select {
	case a.httpSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *Agent) releaseHTTP() { <-a.httpSem }

func (a *Agent) handleHealth(w http.ResponseWriter) {
	status := "ok"
	if !a.info.Available {
		status = "degraded"
	}
	health := model.AgentHealth{
		SchemaVersion: model.AgentSchemaVersion,
		Status:        status,
		NodeID:        a.cfg.NodeID,
		Version:       version.Version,
		NextTrace:     a.info,
		Limits:        a.limits,
		Time:          formatTimestamp(time.Now()),
	}
	writeJSON(w, http.StatusOK, health)
}

func (a *Agent) handleTrace(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, model.ErrInvalidRequest, "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req model.AgentTraceRequest
	if err := decoder.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, model.ErrPayloadTooLarge, "request body is too large")
			return
		}
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "invalid JSON body")
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "unexpected trailing data after JSON body")
		return
	}

	if err := req.Validate(); err != nil {
		var apiErr *model.APIError
		if errors.As(err, &apiErr) {
			status := http.StatusBadRequest
			writeError(w, status, apiErr.Code, apiErr.Message)
			return
		}
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "invalid request")
		return
	}
	if req.NodeID != a.cfg.NodeID {
		writeError(w, http.StatusForbidden, model.ErrForbidden, "node_id does not match this Agent")
		return
	}

	target, err := ipguard.NormalizeIP(req.TargetIP)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, model.ErrTargetRejected, "target_ip must be a numeric IP literal")
		return
	}
	if target.String() != req.TargetIP {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "target_ip must be a canonical IP literal")
		return
	}
	if err := a.policy.CheckAddr(target); err != nil {
		writeError(w, http.StatusUnprocessableEntity, model.ErrTargetRejected, err.Error())
		return
	}
	if model.FamilyOf(target) != req.Family {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "family does not match target_ip")
		return
	}
	if req.TimeoutMS > a.cfg.NextTrace.MaxExecutionMS {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "timeout_ms exceeds this Agent's maximum")
		return
	}
	// Redundant with req.Validate, but this is the Agent-local authoritative
	// check: the port contract is enforced at the boundary that executes.
	if err := model.ValidatePortForProtocol(req.Protocol, req.Port); err != nil {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, errorMessage(err))
		return
	}
	// When the binary is usable, a protocol not enabled by this Agent or not
	// supported by the installed binary is a malformed request. When the binary
	// is unusable the trace proceeds to executeTrace, which reports
	// nexttrace_unavailable (HTTP 200 + terminal failed status).
	if a.caps.Available() && !a.protocolEnabled(req.Protocol) {
		writeError(w, http.StatusBadRequest, model.ErrInvalidRequest, "protocol is not enabled by this Agent")
		return
	}

	if !a.acquireTrace() {
		writeError(w, http.StatusServiceUnavailable, model.ErrBusy, "too many concurrent traces")
		return
	}
	defer a.releaseTrace()

	started := time.Now()
	outcome := a.executeTrace(r.Context(), &req, target)
	ended := time.Now()

	response := model.AgentTraceResponse{
		SchemaVersion:      model.AgentSchemaVersion,
		JobID:              req.JobID,
		NodeID:             a.cfg.NodeID,
		Status:             outcome.status,
		TargetIP:           target.String(),
		Family:             req.Family,
		Protocol:           req.Protocol,
		Port:               req.Port,
		StartedAt:          formatTimestamp(started),
		EndedAt:            formatTimestamp(ended),
		DurationMS:         ended.Sub(started).Milliseconds(),
		NextTraceVersion:   a.caps.Version,
		ParserSchema:       outcome.parserSchema,
		Summary:            outcome.summary,
		Hops:               outcome.hops,
		Error:              outcome.err,
		RawResult:          outcome.raw,
		RawResultTruncated: outcome.rawTruncated,
	}

	attrs := []any{
		"job_id", req.JobID,
		"target", target.String(),
		"protocol", req.Protocol,
		"status", outcome.status,
		"duration_ms", response.DurationMS,
		"hop_count", len(outcome.hops),
	}
	if req.Port != nil {
		attrs = append(attrs, "port", *req.Port)
	}
	if outcome.err != nil {
		attrs = append(attrs, "error_code", outcome.err.Code)
	}
	a.logger.Info("trace finished", attrs...)

	writeJSON(w, http.StatusOK, response)
}

func (a *Agent) acquireTrace() bool {
	select {
	case a.traceSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *Agent) releaseTrace() { <-a.traceSem }

// protocolEnabled reports whether protocol is in the Agent's effective
// protocol list (configured allowlist intersected with binary capabilities).
func (a *Agent) protocolEnabled(protocol model.Protocol) bool {
	for _, enabled := range a.protocols {
		if enabled == protocol {
			return true
		}
	}
	return false
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, model.ErrInvalidRequest, "method not allowed")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code model.ErrorCode, message string) {
	writeJSON(w, status, model.Err(code, message))
}

func formatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
