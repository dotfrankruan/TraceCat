package controller

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

// failingTransport makes Agent calls fail immediately so enrollment URL-matrix
// tests never touch the network.
type failingTransport struct{ calls atomic.Int64 }

func (f *failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	f.calls.Add(1)
	return nil, errors.New("test: outbound network disabled")
}

func newEnrollmentHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	base := []harnessOption{withEnrollment(t, true), withAgents()}
	base = append(base, opts...)
	return newHarness(t, base...)
}

func validEnrollRequest(nodeID string, agentURL string) model.AgentEnrollRequest {
	return model.AgentEnrollRequest{
		SchemaVersion:    model.AgentSchemaVersion,
		NodeID:           nodeID,
		Name:             "Auto node",
		Location:         "Test lab",
		Provider:         "httptest",
		URL:              agentURL,
		NextTraceVersion: "v1.7.3",
		Protocols:        []string{"icmp", "tcp", "udp"},
	}
}

func (h *harness) enroll(token string, req model.AgentEnrollRequest) (*http.Response, []byte) {
	h.t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return h.request(http.MethodPost, model.EnrollmentPath, req, headers)
}

func decodeEnrollment(t *testing.T, resp *http.Response, body []byte) model.AgentEnrollResponse {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d body=%s", resp.StatusCode, body)
	}
	return decodeJSONResponse[model.AgentEnrollResponse](t, resp, body)
}

func TestEnrollmentDisabledReturns404(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")), withEnrollment(t, false))
	resp, body := h.enroll(testEnrollmentToken, validEnrollRequest("auto-1", "http://127.0.0.1:9000"))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled enrollment status = %d body=%s", resp.StatusCode, body)
	}
	envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error == nil || envelope.Error.Code != model.ErrNotFound {
		t.Fatalf("unexpected error: %+v", envelope.Error)
	}
}

func TestEnrollmentAuthentication(t *testing.T) {
	h := newEnrollmentHarness(t)
	req := validEnrollRequest("auto-1", "http://127.0.0.1:9000")

	t.Run("missing token", func(t *testing.T) {
		resp, body := h.enroll("", req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", resp.StatusCode, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	})
	t.Run("wrong token", func(t *testing.T) {
		resp, body := h.enroll("definitely-the-wrong-enrollment-secret", req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", resp.StatusCode, body)
		}
	})
	t.Run("wrong scheme", func(t *testing.T) {
		resp, _ := h.request(http.MethodPost, model.EnrollmentPath, req, map[string]string{
			"Authorization": "Basic " + testEnrollmentToken,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
	t.Run("browser cookie only is rejected", func(t *testing.T) {
		resp, _ := h.request(http.MethodPost, model.EnrollmentPath, req, map[string]string{
			"Cookie": "tracecat_session=some-browser-session",
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})
	t.Run("valid token reaches validation", func(t *testing.T) {
		bad := req
		bad.SchemaVersion = "tracecat.agent.v2"
		resp, body := h.enroll(testEnrollmentToken, bad)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d body=%s", resp.StatusCode, body)
		}
	})
}

func TestEnrollmentStrictBodyAndFieldValidation(t *testing.T) {
	h := newEnrollmentHarness(t)
	base := validEnrollRequest("auto-1", "http://127.0.0.1:9000")

	cases := []struct {
		name string
		req  any
	}{
		{"unknown field", map[string]any{
			"schema_version": model.AgentSchemaVersion, "node_id": "auto-1", "name": "Auto",
			"url": "http://127.0.0.1:9000", "extra": true,
		}},
		{"bad schema version", func() model.AgentEnrollRequest { r := base; r.SchemaVersion = "tracecat.agent.v0"; return r }()},
		{"invalid node id", func() model.AgentEnrollRequest { r := base; r.NodeID = "Not-A-Node"; return r }()},
		{"empty name", func() model.AgentEnrollRequest { r := base; r.Name = "   "; return r }()},
		{"empty url", func() model.AgentEnrollRequest { r := base; r.URL = ""; return r }()},
		{"unknown protocol", func() model.AgentEnrollRequest { r := base; r.Protocols = []string{"gre"}; return r }()},
		{"too many protocols", func() model.AgentEnrollRequest {
			r := base
			r.Protocols = []string{"icmp", "tcp", "udp", "icmp", "tcp", "udp", "icmp", "tcp", "udp"}
			return r
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.request(http.MethodPost, model.EnrollmentPath, tc.req, map[string]string{
				"Authorization": "Bearer " + testEnrollmentToken,
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
		})
	}

	// Malformed JSON is rejected too.
	rawReq, err := http.NewRequest(http.MethodPost, h.srv.URL+model.EnrollmentPath, strings.NewReader(`{"node_id":`))
	if err != nil {
		t.Fatal(err)
	}
	rawReq.Header.Set("Authorization", "Bearer "+testEnrollmentToken)
	rawResp, err := h.client.Do(rawReq)
	if err != nil {
		t.Fatal(err)
	}
	rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", rawResp.StatusCode)
	}

	// Oversized bodies are rejected before decoding (8 KiB limit).
	oversized := `{"schema_version":"` + model.AgentSchemaVersion + `","node_id":"auto-1","name":"` + strings.Repeat("a", 9000) + `"}`
	bigReq, err := http.NewRequest(http.MethodPost, h.srv.URL+model.EnrollmentPath, strings.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	bigReq.Header.Set("Authorization", "Bearer "+testEnrollmentToken)
	bigResp, err := h.client.Do(bigReq)
	if err != nil {
		t.Fatal(err)
	}
	bigResp.Body.Close()
	if bigResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", bigResp.StatusCode)
	}
}

func TestEnrollmentURLMatrix(t *testing.T) {
	transport := &failingTransport{}
	agentClient := NewAgentClient(WithAgentHTTPClient(&http.Client{Transport: transport}))
	h := newEnrollmentHarness(t, withAgentClient(agentClient))

	valid := []struct {
		name    string
		url     string
		wantURL string
	}{
		{"https hostname", "https://agent.example.com", "https://agent.example.com"},
		{"https hostname port", "https://agent.example.com:8443", "https://agent.example.com:8443"},
		{"https public ip", "https://8.8.8.8:8443", "https://8.8.8.8:8443"},
		{"http loopback", "http://127.0.0.1:8443", "http://127.0.0.1:8443"},
		{"http rfc1918", "http://10.0.0.5:8443", "http://10.0.0.5:8443"},
		{"http cgnat", "http://100.64.0.5:8443", "http://100.64.0.5:8443"},
		{"http ipv6 ula", "http://[fd7a:115c:a1e0::1]:8443", "http://[fd7a:115c:a1e0::1]:8443"},
		{"normalizes host case and slash", "https://Example.COM/", "https://example.com"},
	}
	for i, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			nodeID := "auto-valid-" + string(rune('a'+i))
			resp, body := h.enroll(testEnrollmentToken, validEnrollRequest(nodeID, tc.url))
			enrolled := decodeEnrollment(t, resp, body)
			if enrolled.TraceURL != tc.wantURL {
				t.Fatalf("trace_url = %q, want %q", enrolled.TraceURL, tc.wantURL)
			}
			if enrolled.NodeID != nodeID || len(enrolled.AgentToken) < 40 {
				t.Fatalf("unexpected enrollment response: %+v", enrolled)
			}
			if enrolled.RefreshAfterS != 300 || enrolled.SchemaVersion != model.ControllerSchemaVersion {
				t.Fatalf("unexpected enrollment response: %+v", enrolled)
			}
		})
	}

	invalid := []string{
		"http://8.8.8.8:8443",
		"http://agent.example.com",
		"https://user:pass@agent.example.com",
		"https://agent.example.com/v1",
		"https://agent.example.com?x=1",
		"https://agent.example.com#fragment",
		"ftp://agent.example.com",
		"https://agent.example.com:99999",
		"not-a-url",
		"",
	}
	for i, rawURL := range invalid {
		t.Run("reject-"+string(rune('a'+i)), func(t *testing.T) {
			nodeID := "auto-invalid-" + string(rune('a'+i))
			resp, body := h.enroll(testEnrollmentToken, validEnrollRequest(nodeID, rawURL))
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("url %q status = %d body=%s", rawURL, resp.StatusCode, body)
			}
		})
	}
	if transport.calls.Load() > int64(len(valid)) {
		t.Fatalf("URL-matrix enrollment triggered unexpected network calls: %d", transport.calls.Load())
	}
}

func TestEnrollmentRegistersNodeAndJobDispatch(t *testing.T) {
	autoAgent := newFakeAgent(t, "auto-node-1")
	h := newEnrollmentHarness(t)

	resp, body := h.enroll(testEnrollmentToken, validEnrollRequest(autoAgent.nodeID, autoAgent.url()))
	enrolled := decodeEnrollment(t, resp, body)
	if enrolled.NodeID != autoAgent.nodeID || enrolled.TraceURL != autoAgent.url() {
		t.Fatalf("unexpected enrollment response: %+v", enrolled)
	}

	// The Agent accepts the freshly issued token and the Controller can check
	// its health.
	autoAgent.setToken(enrolled.AgentToken)
	h.registry.CheckAll(context.Background())

	resp, body = h.get("/api/v1/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", resp.StatusCode, body)
	}
	nodes := decodeJSONResponse[model.NodeList](t, resp, body)
	if len(nodes.Nodes) != 1 {
		t.Fatalf("nodes = %+v", nodes.Nodes)
	}
	node := nodes.Nodes[0]
	if node.ID != autoAgent.nodeID || node.Source != model.NodeSourceAuto {
		t.Fatalf("node = %+v", node)
	}
	if node.Health != HealthOK {
		t.Fatalf("node health = %q", node.Health)
	}
	if node.NextTraceVersion != "v1.7.3" {
		t.Fatalf("node version = %q", node.NextTraceVersion)
	}

	// Auto-registered nodes are first-class job targets.
	resp, body = h.createJob(model.CreateJobRequest{
		TargetIP: "8.8.8.8", OriginalTarget: "dns.example",
		NodeIDs: []string{autoAgent.nodeID}, Protocol: model.ProtocolICMP,
		MaxHops: 30, Queries: 3, TimeoutMS: 60000,
	})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create job status = %d body=%s", resp.StatusCode, body)
	}
	id := decodeJSONResponse[model.JobResponse](t, resp, body).Job.ID
	final := waitForTerminalJob(t, h.manager, id)
	if final.Status != model.JobCompleted || final.Nodes[0].Status != model.NodeCompleted {
		t.Fatalf("auto node job = %+v", final)
	}
	dispatched, _ := autoAgent.lastTraceRequest()
	if dispatched.NodeID != autoAgent.nodeID || dispatched.TargetIP != "8.8.8.8" {
		t.Fatalf("dispatched request = %+v", dispatched)
	}
	if autoAgent.traceCount() != 1 {
		t.Fatalf("agent trace count = %d", autoAgent.traceCount())
	}
}

func TestEnrollmentReenrollRotatesToken(t *testing.T) {
	autoAgent := newFakeAgent(t, "auto-node-2")
	h := newEnrollmentHarness(t)
	req := validEnrollRequest(autoAgent.nodeID, autoAgent.url())

	firstResp, firstBody := h.enroll(testEnrollmentToken, req)
	first := decodeEnrollment(t, firstResp, firstBody)
	autoAgent.setToken(first.AgentToken)
	secondResp, secondBody := h.enroll(testEnrollmentToken, req)
	second := decodeEnrollment(t, secondResp, secondBody)

	if first.AgentToken == second.AgentToken {
		t.Fatal("re-enrollment did not rotate the agent token")
	}
	if first.NodeID != second.NodeID {
		t.Fatalf("node id changed across re-enrollment: %q vs %q", first.NodeID, second.NodeID)
	}

	// Only one node exists after re-enrollment.
	resp, body := h.get("/api/v1/nodes")
	nodes := decodeJSONResponse[model.NodeList](t, resp, body)
	if len(nodes.Nodes) != 1 || nodes.Nodes[0].ID != autoAgent.nodeID {
		t.Fatalf("nodes after re-enrollment = %+v", nodes.Nodes)
	}

	// The Agent now only accepts the rotated token.
	autoAgent.setToken(second.AgentToken)
	if resp := rawAgentRequest(t, autoAgent.url()+"/v1/health", first.AgentToken); resp != http.StatusUnauthorized {
		t.Fatalf("old token health status = %d, want 401", resp)
	}
	if resp := rawAgentRequest(t, autoAgent.url()+"/v1/health", second.AgentToken); resp != http.StatusOK {
		t.Fatalf("new token health status = %d, want 200", resp)
	}
}

func rawAgentRequest(t *testing.T, url, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestEnrollmentStaticCollision(t *testing.T) {
	staticAgent := newFakeAgent(t, "node-one")
	h := newHarness(t, withAgents(staticAgent), withEnrollment(t, true))

	resp, body := h.enroll(testEnrollmentToken, validEnrollRequest("node-one", staticAgent.url()))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("static collision status = %d body=%s", resp.StatusCode, body)
	}
	envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error == nil || envelope.Error.Code != model.ErrConflict {
		t.Fatalf("unexpected error: %+v", envelope.Error)
	}
	if strings.Contains(string(body), "agent_token") {
		t.Fatalf("static collision response leaked a token: %s", body)
	}

	// The static node still reports source static.
	nodesResp, nodesBody := h.get("/api/v1/nodes")
	nodes := decodeJSONResponse[model.NodeList](t, nodesResp, nodesBody)
	if len(nodes.Nodes) != 1 || nodes.Nodes[0].Source != model.NodeSourceStatic {
		t.Fatalf("nodes = %+v", nodes.Nodes)
	}
}

func TestEnrollmentRateLimit(t *testing.T) {
	h := newEnrollmentHarness(t)
	req := validEnrollRequest("auto-rate", "http://127.0.0.1:9000")
	var sawUnauthorized, sawLimited bool
	for i := 0; i < enrollmentPerIPPerMinute+1; i++ {
		resp, _ := h.enroll("wrong-token-for-rate-limit", req)
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			sawUnauthorized = true
		case http.StatusTooManyRequests:
			sawLimited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("rate-limited response has no Retry-After header")
			}
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if !sawUnauthorized || !sawLimited {
		t.Fatalf("expected 401 then 429, got unauthorized=%v limited=%v", sawUnauthorized, sawLimited)
	}
}

func TestRegisteredAgentsPersistAcrossReopen(t *testing.T) {
	t.Setenv(testEnrollmentTokenEnv, testEnrollmentToken)
	doc := testConfigDoc(t, AuthModeDev, nil, "")
	doc["enrollment"] = map[string]any{"enabled": true, "token_env": testEnrollmentTokenEnv}
	cfg, err := LoadConfig(writeConfigDoc(t, doc))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	path := filepath.Join(t.TempDir(), "controller.db")
	store, err := OpenStore(path, 10)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	now := time.Now().UTC()
	record := RegisteredAgent{
		NodeID: "auto-persist", Name: "Persisted", Location: "Lab", Provider: "test",
		URL: "http://127.0.0.1:9000", AgentToken: "first-agent-token", Protocols: []string{"icmp", "tcp"},
		NextTraceVersion: "v1.7.3", CreatedAt: now, UpdatedAt: now, LastSeenAt: now,
	}
	if err := store.UpsertRegisteredAgent(context.Background(), record); err != nil {
		t.Fatalf("UpsertRegisteredAgent: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenStore(path, 10)
	if err != nil {
		t.Fatalf("OpenStore reopen: %v", err)
	}
	defer reopened.Close()
	stored, err := reopened.GetRegisteredAgent(context.Background(), record.NodeID)
	if err != nil {
		t.Fatalf("GetRegisteredAgent: %v", err)
	}
	if stored.AgentToken != record.AgentToken || stored.URL != record.URL || len(stored.Protocols) != 2 {
		t.Fatalf("stored record = %+v", stored)
	}

	client := NewAgentClient(WithAgentHTTPClient(&http.Client{Transport: &failingTransport{}}))
	registry := NewRegistry(cfg, client, testLogger())
	if err := registry.LoadRegisteredAgents(context.Background(), reopened); err != nil {
		t.Fatalf("LoadRegisteredAgents: %v", err)
	}
	node, ok := registry.Get(record.NodeID)
	if !ok {
		t.Fatal("restored node is missing from the registry")
	}
	if node.Token() != record.AgentToken || node.BaseURL() != record.URL {
		t.Fatalf("restored agent = %+v", node)
	}
	infos := registry.NodeInfos()
	if len(infos) != 1 || infos[0].Source != model.NodeSourceAuto {
		t.Fatalf("restored node infos = %+v", infos)
	}

	// Re-enrollment rotates the token and preserves the creation timestamp.
	rotated := record
	rotated.AgentToken = "second-agent-token"
	rotated.CreatedAt = time.Time{}
	rotated.UpdatedAt = time.Now().UTC().Add(time.Second)
	if err := reopened.UpsertRegisteredAgent(context.Background(), rotated); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	stored, err = reopened.GetRegisteredAgent(context.Background(), record.NodeID)
	if err != nil {
		t.Fatalf("GetRegisteredAgent rotated: %v", err)
	}
	if stored.AgentToken != rotated.AgentToken {
		t.Fatalf("token was not rotated: %+v", stored)
	}
	if stored.CreatedAt.UnixNano() != record.CreatedAt.UnixNano() {
		t.Fatalf("creation timestamp was not preserved: %v vs %v", stored.CreatedAt, record.CreatedAt)
	}
}
