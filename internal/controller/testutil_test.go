package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

// testLogger discards log output; tests that assert logging can build their own.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeAgent is an in-process Agent implementing the documented API contract.
type fakeAgent struct {
	t      *testing.T
	nodeID string
	token  string
	srv    *httptest.Server

	mu           sync.Mutex
	healthHits   int
	traceHits    int
	lastTrace    model.AgentTraceRequest
	lastTraceRaw []byte
	lastAuth     string
	traceFn      func(w http.ResponseWriter, r *http.Request, req model.AgentTraceRequest)
	healthFn     func(w http.ResponseWriter, r *http.Request)
}

func newFakeAgent(t *testing.T, nodeID string) *fakeAgent {
	t.Helper()
	agent := &fakeAgent{
		t:      t,
		nodeID: nodeID,
		token:  "agent-token-" + nodeID + "-0123456789abcdef",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", agent.handleHealth)
	mux.HandleFunc("/v1/trace", agent.handleTrace)
	agent.srv = httptest.NewServer(mux)
	t.Cleanup(agent.srv.Close)
	return agent
}

func (f *fakeAgent) tokenEnv() string {
	return "TRACECAT_TEST_AGENT_" + strings.ToUpper(strings.ReplaceAll(f.nodeID, "-", "_"))
}

func (f *fakeAgent) url() string { return f.srv.URL }

func (f *fakeAgent) authOK(r *http.Request) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuth = r.Header.Get("Authorization")
	return r.Header.Get("Authorization") == "Bearer "+f.token
}

func (f *fakeAgent) handleHealth(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.healthHits++
	f.mu.Unlock()
	if !f.authOK(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, `{"error":{"code":"unauthorized","message":"unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	healthFn := f.healthFn
	f.mu.Unlock()
	if healthFn != nil {
		healthFn(w, r)
		return
	}
	writeTestJSON(f.t, w, model.AgentHealth{
		SchemaVersion: model.AgentSchemaVersion,
		Status:        "ok",
		NodeID:        f.nodeID,
		Version:       "0.1.0-test",
		NextTrace:     model.NextTraceInfo{Available: true, Version: "v1.7.3"},
		Limits:        model.AgentLimits{MaxHops: 64, MaxQueries: 5, MaxTimeoutMS: 120000, MaxConcurrentTraces: 4},
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (f *fakeAgent) handleTrace(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.traceHits++
	f.mu.Unlock()
	if !f.authOK(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeTestJSONStatus(f.t, w, http.StatusUnauthorized, model.Err(model.ErrUnauthorized, "unauthorized"))
		return
	}
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeTestJSONStatus(f.t, w, http.StatusBadRequest, model.Err(model.ErrInvalidRequest, "invalid body"))
		return
	}
	var req model.AgentTraceRequest
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeTestJSONStatus(f.t, w, http.StatusBadRequest, model.Err(model.ErrInvalidRequest, "invalid body"))
		return
	}
	f.mu.Lock()
	f.lastTrace = req
	f.lastTraceRaw = append([]byte(nil), rawBody...)
	traceFn := f.traceFn
	f.mu.Unlock()
	if traceFn != nil {
		traceFn(w, r, req)
		return
	}
	writeTestJSON(f.t, w, completedTraceResponse(req))
}

func (f *fakeAgent) setTraceHandler(fn func(w http.ResponseWriter, r *http.Request, req model.AgentTraceRequest)) {
	f.mu.Lock()
	f.traceFn = fn
	f.mu.Unlock()
}

func (f *fakeAgent) setHealthHandler(fn func(w http.ResponseWriter, r *http.Request)) {
	f.mu.Lock()
	f.healthFn = fn
	f.mu.Unlock()
}

func (f *fakeAgent) lastTraceRequest() (model.AgentTraceRequest, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastTrace, append([]byte(nil), f.lastTraceRaw...)
}

func (f *fakeAgent) traceCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.traceHits
}

func (f *fakeAgent) healthCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthHits
}

func completedTraceResponse(req model.AgentTraceRequest) model.AgentTraceResponse {
	started := time.Now().UTC().Add(-1500 * time.Millisecond)
	rtt := 12.5
	return model.AgentTraceResponse{
		SchemaVersion:    model.AgentSchemaVersion,
		JobID:            req.JobID,
		NodeID:           req.NodeID,
		Status:           model.NodeCompleted,
		TargetIP:         req.TargetIP,
		Family:           req.Family,
		Protocol:         req.Protocol,
		Port:             clonePort(req.Port),
		StartedAt:        started.Format(time.RFC3339Nano),
		EndedAt:          started.Add(1500 * time.Millisecond).Format(time.RFC3339Nano),
		DurationMS:       1500,
		NextTraceVersion: "v1.7.3",
		ParserSchema:     model.NextTraceJSONSchema,
		Summary:          model.TraceSummary{HopCount: 2},
		Hops: []model.Hop{
			{TTL: 1, Probes: []model.Probe{{Success: true, Address: "10.200.0.1", RTTMS: &rtt}}},
			{TTL: 2, Probes: []model.Probe{{Success: true, Address: req.TargetIP, RTTMS: &rtt}}},
		},
		RawResult: json.RawMessage(`{"Hops":[{"TTL":1},{"TTL":2}],"Origin":"test"}`),
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	writeTestJSONStatus(t, w, http.StatusOK, v)
}

func writeTestJSONStatus(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Errorf("marshal test JSON: %v", err)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// harness bundles a fully wired Controller for HTTP-level tests.
type harness struct {
	t        *testing.T
	cfg      *Config
	store    *Store
	registry *Registry
	manager  *Manager
	hub      *Hub
	api      *API
	srv      *httptest.Server
	agents   []*fakeAgent
	client   *http.Client
	csrf     string
}

type harnessOption func(*harnessOptions)

type harnessOptions struct {
	mode         string
	agents       []*fakeAgent
	resolver     Resolver
	managerOpts  []ManagerOption
	apiOpts      []APIOption
	mutateConfig func(*Config)
	docMutate    func(map[string]any)
	agentClient  *AgentClient
	password     string
}

func withMode(mode string) harnessOption {
	return func(o *harnessOptions) { o.mode = mode }
}

func withAgents(agents ...*fakeAgent) harnessOption {
	return func(o *harnessOptions) { o.agents = agents }
}

func withResolver(resolver Resolver) harnessOption {
	return func(o *harnessOptions) { o.resolver = resolver }
}

func withManagerOptions(opts ...ManagerOption) harnessOption {
	return func(o *harnessOptions) { o.managerOpts = append(o.managerOpts, opts...) }
}

func withAPIOptions(opts ...APIOption) harnessOption {
	return func(o *harnessOptions) { o.apiOpts = append(o.apiOpts, opts...) }
}

func withConfigMutation(fn func(*Config)) harnessOption {
	return func(o *harnessOptions) { o.mutateConfig = fn }
}

func withDocMutation(fn func(map[string]any)) harnessOption {
	return func(o *harnessOptions) { o.docMutate = fn }
}

func withAgentClient(client *AgentClient) harnessOption {
	return func(o *harnessOptions) { o.agentClient = client }
}

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	options := harnessOptions{mode: AuthModeDev}
	for _, opt := range opts {
		opt(&options)
	}
	doc := testConfigDoc(t, options.mode, options.agents, options.password)
	if options.docMutate != nil {
		options.docMutate(doc)
	}
	cfg, err := LoadConfig(writeConfigDoc(t, doc))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if options.mutateConfig != nil {
		options.mutateConfig(cfg)
	}

	storePath := t.TempDir() + "/controller.db"
	store, err := OpenStore(storePath, cfg.Database.MaxHistoryJobs)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	resolverImpl := options.resolver
	if resolverImpl == nil {
		resolverImpl = staticResolver{}
	}
	policy, err := ipguard.NewPolicy(nil)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	resolver := NewResolverService(resolverImpl, policy,
		time.Duration(cfg.DNS.TimeoutMS)*time.Millisecond, cfg.DNS.MaxAddresses)
	agentClient := options.agentClient
	if agentClient == nil {
		agentClient = NewAgentClient()
	}
	registry := NewRegistry(cfg, agentClient, testLogger())
	hub := NewHub()
	manager := NewManager(cfg, store, registry, agentClient, hub, testLogger(), options.managerOpts...)
	api, err := NewAPI(cfg, store, resolver, registry, manager, testLogger(), options.apiOpts...)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	srv.Client().Jar = jar

	h := &harness{
		t: t, cfg: cfg, store: store, registry: registry, manager: manager,
		hub: hub, api: api, srv: srv, agents: options.agents,
		client: srv.Client(),
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		manager.Shutdown(ctx)
	})
	return h
}

// staticResolver returns public addresses for domain lookups.
type staticResolver struct{}

func (staticResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	if network == "ip4" {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, nil
}

func testConfigDoc(t *testing.T, mode string, agents []*fakeAgent, password string) map[string]any {
	t.Helper()
	agentDocs := make([]any, 0, len(agents))
	for _, agent := range agents {
		t.Setenv(agent.tokenEnv(), agent.token)
		agentDocs = append(agentDocs, map[string]any{
			"id":        agent.nodeID,
			"name":      "Agent " + agent.nodeID,
			"location":  "Test lab",
			"provider":  "httptest",
			"url":       agent.url(),
			"token_env": agent.tokenEnv(),
			"enabled":   true,
		})
	}
	doc := map[string]any{
		"listen":          "127.0.0.1:8080",
		"public_origin":   "http://127.0.0.1:8080",
		"auth":            map[string]any{"mode": mode},
		"database":        map[string]any{"path": t.TempDir() + "/unused.db", "max_history_jobs": 50},
		"dns":             map[string]any{"timeout_ms": 1000, "max_addresses": 16},
		"agents":          agentDocs,
		"trusted_proxies": []any{},
		"log_level":       "error",
	}
	if mode == AuthModeCloudflare {
		doc["auth"] = map[string]any{
			"mode": "cloudflare",
			"cloudflare": map[string]any{
				"team_domain":            "https://team.example.cloudflareaccess.com",
				"audience":               []any{"aud-tag-1"},
				"jwks_cache_ttl_seconds": 300,
			},
		}
	}
	if mode == AuthModeLocal {
		if password == "" {
			password = "correct horse battery staple"
		}
		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		doc["auth"] = map[string]any{
			"mode": "local",
			"local": map[string]any{
				"password_hash_env":   "TRACECAT_TEST_PASSWORD_HASH",
				"session_ttl_seconds": 3600,
			},
		}
		t.Setenv("TRACECAT_TEST_PASSWORD_HASH", hash)
	}
	return doc
}

// request performs an HTTP request with optional JSON body and headers.
func (h *harness) request(method, path string, body any, headers map[string]string) (*http.Response, []byte) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		h.t.Fatalf("read response: %v", err)
	}
	return resp, data
}

// csrfToken fetches and caches the session CSRF token.
func (h *harness) csrfToken() string {
	h.t.Helper()
	if h.csrf != "" {
		return h.csrf
	}
	resp, body := h.request(http.MethodGet, "/api/v1/session", nil, nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("session status = %d body=%s", resp.StatusCode, body)
	}
	var session model.Session
	if err := json.Unmarshal(body, &session); err != nil {
		h.t.Fatalf("decode session: %v", err)
	}
	if session.CSRFToken == "" {
		h.t.Fatal("session has no CSRF token")
	}
	h.csrf = session.CSRFToken
	return h.csrf
}

// login performs a local-mode password login. The harness cookie jar stores the
// session cookie for subsequent requests.
func (h *harness) login(password string) (model.Session, *http.Response, []byte) {
	h.t.Helper()
	resp, body := h.request(http.MethodPost, "/api/v1/auth/login", model.LoginRequest{Password: password}, nil)
	var session model.Session
	if resp.StatusCode == http.StatusOK {
		session = decodeJSONResponse[model.Session](h.t, resp, body)
		h.csrf = session.CSRFToken
	}
	return session, resp, body
}

func (h *harness) get(path string) (*http.Response, []byte) {
	h.t.Helper()
	return h.request(http.MethodGet, path, nil, nil)
}

func (h *harness) post(path string, body any) (*http.Response, []byte) {
	h.t.Helper()
	return h.request(http.MethodPost, path, body, map[string]string{csrfHeaderName: h.csrfToken()})
}

func (h *harness) createJob(req model.CreateJobRequest) (*http.Response, []byte) {
	h.t.Helper()
	return h.post("/api/v1/jobs", req)
}

func decodeJSONResponse[T any](t *testing.T, resp *http.Response, body []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode response (status %d): %v body=%s", resp.StatusCode, err, body)
	}
	return out
}

func waitForTerminalJob(t *testing.T, manager *Manager, id string) model.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, apiErr := manager.GetJob(context.Background(), id)
		if apiErr != nil {
			t.Fatalf("GetJob: %v", apiErr)
		}
		if jobIsTerminal(job.Status) {
			return *job
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach a terminal state", id)
	return model.Job{}
}
