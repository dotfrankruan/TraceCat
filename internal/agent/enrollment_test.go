package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

type enrollmentCall struct {
	Request     model.AgentEnrollRequest
	AuthHeader  string
	Path        string
	ContentType string
}

type fakeEnrollmentController struct {
	mu      sync.Mutex
	calls   []enrollmentCall
	respond func(call int, request model.AgentEnrollRequest) (status int, body string)
	server  *httptest.Server
}

func newFakeEnrollmentController(t *testing.T, respond func(call int, request model.AgentEnrollRequest) (int, string)) *fakeEnrollmentController {
	t.Helper()
	if respond == nil {
		respond = successEnrollmentResponder("issued-agent-token-1")
	}
	controller := &fakeEnrollmentController{respond: respond}
	controller.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var request model.AgentEnrollRequest
		_ = json.Unmarshal(body, &request)

		controller.mu.Lock()
		controller.calls = append(controller.calls, enrollmentCall{
			Request:     request,
			AuthHeader:  r.Header.Get("Authorization"),
			Path:        r.URL.Path,
			ContentType: r.Header.Get("Content-Type"),
		})
		call := len(controller.calls)
		responder := controller.respond
		controller.mu.Unlock()

		status, responseBody := responder(call, request)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, responseBody)
	}))
	t.Cleanup(controller.server.Close)
	return controller
}

func successEnrollmentResponder(token string) func(int, model.AgentEnrollRequest) (int, string) {
	return func(_ int, request model.AgentEnrollRequest) (int, string) {
		return http.StatusOK, enrollmentResponseBody(request.NodeID, request.URL, token)
	}
}

func enrollmentResponseBody(nodeID, traceURL, token string) string {
	body, err := json.Marshal(model.AgentEnrollResponse{
		SchemaVersion: model.ControllerSchemaVersion,
		NodeID:        nodeID,
		AgentToken:    token,
		TraceURL:      traceURL,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func (f *fakeEnrollmentController) setRespond(respond func(call int, request model.AgentEnrollRequest) (int, string)) {
	f.mu.Lock()
	f.respond = respond
	f.mu.Unlock()
}

func (f *fakeEnrollmentController) snapshot() []enrollmentCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]enrollmentCall{}, f.calls...)
}

func (f *fakeEnrollmentController) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newEnrollmentAgent(t *testing.T, ctrl fakeControl, controllerURL string, logger *slog.Logger, mutate func(*Config), opts ...Option) (*Agent, string) {
	t.Helper()
	fake := newFakeNexttrace(t, ctrl)
	t.Setenv(testTokenEnv, testToken)
	t.Setenv(testEnrollmentTokenEnv, testEnrollmentSecret)
	cfg := testConfig(fake)
	cfg.Auth.TokenEnv = "" // enrollment mode: token comes from the Controller
	cfg.Controller = &ControllerConfig{
		URL:                controllerURL,
		EnrollmentTokenEnv: testEnrollmentTokenEnv,
		RefreshSeconds:     60,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	agent, err := New(cfg, logger, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(agent.Close)
	return agent, fake
}

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func authorizedHealthStatus(t *testing.T, agent *Agent, token string) int {
	t.Helper()
	return doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil,
		requestOptions{token: &token}).Code
}

func TestEnrollmentRequestShapeAndTokenLifecycle(t *testing.T) {
	controller := newFakeEnrollmentController(t, nil)
	agent, _ := newEnrollmentAgent(t, fakeControl{Stdout: successTraceJSON}, controller.server.URL, nil, nil)

	// Before enrollment every inbound request must be rejected.
	if got := authorizedHealthStatus(t, agent, testToken); got != http.StatusUnauthorized {
		t.Fatalf("pre-enrollment health status = %d, want 401", got)
	}
	unauthorizedTrace := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{token: strptr("")})
	if unauthorizedTrace.Code != http.StatusUnauthorized {
		t.Fatalf("pre-enrollment trace status = %d, want 401", unauthorizedTrace.Code)
	}

	if err := agent.enrollOnce(context.Background()); err != nil {
		t.Fatalf("enrollOnce: %v", err)
	}
	calls := controller.snapshot()
	if len(calls) != 1 {
		t.Fatalf("enrollment calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.Path != model.EnrollmentPath {
		t.Fatalf("enrollment path = %q, want %q", call.Path, model.EnrollmentPath)
	}
	if call.AuthHeader != "Bearer "+testEnrollmentSecret {
		t.Fatalf("enrollment Authorization header is wrong: %q", call.AuthHeader)
	}
	if call.ContentType != "application/json" {
		t.Fatalf("enrollment Content-Type = %q", call.ContentType)
	}
	wantRequest := model.AgentEnrollRequest{
		SchemaVersion:    model.AgentSchemaVersion,
		NodeID:           "tokyo-1",
		Name:             "Tokyo",
		URL:              "http://127.0.0.1:9481",
		NextTraceVersion: "v1.7.1",
		Protocols:        []string{"icmp", "tcp", "udp"},
	}
	if call.Request.SchemaVersion != wantRequest.SchemaVersion ||
		call.Request.NodeID != wantRequest.NodeID ||
		call.Request.Name != wantRequest.Name ||
		call.Request.URL != wantRequest.URL ||
		call.Request.NextTraceVersion != wantRequest.NextTraceVersion ||
		strings.Join(call.Request.Protocols, ",") != strings.Join(wantRequest.Protocols, ",") {
		t.Fatalf("enrollment request = %+v, want %+v", call.Request, wantRequest)
	}

	// The issued token authenticates inbound health and trace calls.
	if got := authorizedHealthStatus(t, agent, "issued-agent-token-1"); got != http.StatusOK {
		t.Fatalf("post-enrollment health status = %d, want 200", got)
	}
	if got := authorizedHealthStatus(t, agent, testToken); got != http.StatusUnauthorized {
		t.Fatalf("old/static token health status = %d, want 401", got)
	}
	trace := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil),
		requestOptions{token: strptr("issued-agent-token-1")})
	if trace.Code != http.StatusOK {
		t.Fatalf("post-enrollment trace status = %d, want 200: %s", trace.Code, trace.Body.String())
	}
	if response := decodeTraceResponse(t, trace); response.Status != model.NodeCompleted {
		t.Fatalf("trace status = %s, want completed", response.Status)
	}
}

func TestEnrollmentUsesControllerMetadata(t *testing.T) {
	controller := newFakeEnrollmentController(t, nil)
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, func(cfg *Config) {
		cfg.Controller.Name = "Tokyo edge"
		cfg.Controller.Location = "Tokyo, JP"
		cfg.Controller.Provider = "DMIT"
		cfg.Controller.AdvertiseURL = "https://agent.example.com:8443"
	})
	if err := agent.enrollOnce(context.Background()); err != nil {
		t.Fatalf("enrollOnce: %v", err)
	}
	request := controller.snapshot()[0].Request
	if request.Name != "Tokyo edge" || request.Location != "Tokyo, JP" || request.Provider != "DMIT" {
		t.Fatalf("enrollment metadata = %+v", request)
	}
	if request.URL != "https://agent.example.com:8443" {
		t.Fatalf("enrollment URL = %q", request.URL)
	}
}

func TestEnrollmentRetriesWithBackoffUntilSuccess(t *testing.T) {
	controller := newFakeEnrollmentController(t, func(call int, request model.AgentEnrollRequest) (int, string) {
		if call < 3 {
			return http.StatusInternalServerError, `{"error":"not ready"}`
		}
		return http.StatusOK, enrollmentResponseBody(request.NodeID, request.URL, "retry-token")
	})
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, nil,
		WithEnrollmentRetry(10*time.Millisecond, 40*time.Millisecond, 100*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.runEnrollment(ctx)
		close(done)
	}()
	waitUntil(t, 3*time.Second, func() bool {
		return controller.callCount() >= 3 && authorizedHealthStatus(t, agent, "retry-token") == http.StatusOK
	}, "retry enrollment to succeed")
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEnrollment did not stop after cancellation")
	}
}

func TestEnrollmentRefreshRotatesToken(t *testing.T) {
	controller := newFakeEnrollmentController(t, func(call int, request model.AgentEnrollRequest) (int, string) {
		token := "rotate-token-1"
		if call >= 2 {
			token = "rotate-token-2"
		}
		return http.StatusOK, enrollmentResponseBody(request.NodeID, request.URL, token)
	})
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, nil,
		WithEnrollmentRetry(10*time.Millisecond, 40*time.Millisecond, 40*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.runEnrollment(ctx)
		close(done)
	}()
	waitUntil(t, 3*time.Second, func() bool {
		return controller.callCount() >= 2 && authorizedHealthStatus(t, agent, "rotate-token-2") == http.StatusOK
	}, "token rotation")
	if got := authorizedHealthStatus(t, agent, "rotate-token-1"); got != http.StatusUnauthorized {
		t.Fatalf("old rotated token status = %d, want 401", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEnrollment did not stop after cancellation")
	}
}

func TestEnrollmentRejectsBadResponses(t *testing.T) {
	valid := func(request model.AgentEnrollRequest) string {
		return enrollmentResponseBody(request.NodeID, request.URL, "issued-token")
	}
	cases := []struct {
		name     string
		response func(int, model.AgentEnrollRequest) (int, string)
	}{
		{
			name: "http error",
			response: func(int, model.AgentEnrollRequest) (int, string) {
				return http.StatusForbidden, `{"error":"denied"}`
			},
		},
		{
			name: "malformed json",
			response: func(int, model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, `not json`
			},
		},
		{
			name: "unknown field",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				body, _ := json.Marshal(model.AgentEnrollResponse{
					SchemaVersion: model.ControllerSchemaVersion,
					NodeID:        request.NodeID,
					AgentToken:    "issued-token",
					TraceURL:      request.URL,
				})
				return http.StatusOK, string(body[:len(body)-1]) + `,"extra":true}`
			},
		},
		{
			name: "trailing data",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, valid(request) + `{}`
			},
		},
		{
			name: "wrong schema",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				body, _ := json.Marshal(model.AgentEnrollResponse{
					SchemaVersion: "tracecat.controller.v2",
					NodeID:        request.NodeID,
					AgentToken:    "issued-token",
					TraceURL:      request.URL,
				})
				return http.StatusOK, string(body)
			},
		},
		{
			name: "wrong node",
			response: func(int, model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, enrollmentResponseBody("other-node", "http://127.0.0.1:9481", "issued-token")
			},
		},
		{
			name: "empty token",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, enrollmentResponseBody(request.NodeID, request.URL, "")
			},
		},
		{
			name: "token with whitespace",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, enrollmentResponseBody(request.NodeID, request.URL, "bad token")
			},
		},
		{
			name: "trace url mismatch",
			response: func(_ int, request model.AgentEnrollRequest) (int, string) {
				return http.StatusOK, enrollmentResponseBody(request.NodeID, "http://10.0.0.9:8443", "issued-token")
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			controller := newFakeEnrollmentController(t, tc.response)
			agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, nil)
			if err := agent.enrollOnce(context.Background()); err == nil {
				t.Fatal("enrollOnce = nil error, want rejection")
			}
			if got := authorizedHealthStatus(t, agent, "issued-token"); got != http.StatusUnauthorized {
				t.Fatalf("health with rejected token status = %d, want 401", got)
			}
		})
	}

	t.Run("failed refresh preserves the previous token", func(t *testing.T) {
		controller := newFakeEnrollmentController(t, nil)
		agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, nil)
		if err := agent.enrollOnce(context.Background()); err != nil {
			t.Fatalf("initial enroll: %v", err)
		}
		controller.setRespond(func(int, model.AgentEnrollRequest) (int, string) {
			return http.StatusInternalServerError, `{"error":"temporary"}`
		})
		if err := agent.enrollOnce(context.Background()); err == nil {
			t.Fatal("refresh = nil error, want rejection")
		}
		if got := authorizedHealthStatus(t, agent, "issued-agent-token-1"); got != http.StatusOK {
			t.Fatalf("previous token status = %d, want 200", got)
		}
	})
}

func TestEnrollmentFailureDoesNotCrashAgent(t *testing.T) {
	controller := newFakeEnrollmentController(t, func(int, model.AgentEnrollRequest) (int, string) {
		return http.StatusServiceUnavailable, `{"error":"down"}`
	})
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, nil,
		WithEnrollmentRetry(5*time.Millisecond, 20*time.Millisecond, time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.runEnrollment(ctx)
		close(done)
	}()
	waitUntil(t, 2*time.Second, func() bool { return controller.callCount() >= 2 }, "retry attempts")
	if got := authorizedHealthStatus(t, agent, "anything"); got != http.StatusUnauthorized {
		t.Fatalf("health during failed enrollment = %d, want 401", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runEnrollment did not stop after cancellation")
	}
}

func TestEnrollmentNeverLogsTokens(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	controller := newFakeEnrollmentController(t, successEnrollmentResponder("issued-secret-token-value"))
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, logger, nil)
	if err := agent.enrollOnce(context.Background()); err != nil {
		t.Fatalf("enrollOnce: %v", err)
	}

	controller.setRespond(func(int, model.AgentEnrollRequest) (int, string) {
		return http.StatusInternalServerError, `{"error":"down"}`
	})
	if err := agent.enrollOnce(context.Background()); err == nil {
		t.Fatal("expected failed refresh")
	}

	logged := logs.String()
	for _, secret := range []string{testEnrollmentSecret, "issued-secret-token-value"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("logs leaked a token value: %q", logged)
		}
	}
}

func TestStaticModeRegression(t *testing.T) {
	agent, _ := newTestAgent(t, fakeControl{Stdout: successTraceJSON})
	if agent.enrollment != nil {
		t.Fatal("static-mode Agent unexpectedly has an enrollment client")
	}
	if got := authorizedHealthStatus(t, agent, testToken); got != http.StatusOK {
		t.Fatalf("static health status = %d, want 200", got)
	}
	if got := authorizedHealthStatus(t, agent, "wrong-token"); got != http.StatusUnauthorized {
		t.Fatalf("static wrong-token status = %d, want 401", got)
	}
}

func TestRunStartsEnrollmentWhileListening(t *testing.T) {
	controller := newFakeEnrollmentController(t, successEnrollmentResponder("run-mode-token"))
	t.Setenv(testTokenEnv, testToken)
	t.Setenv(testEnrollmentTokenEnv, testEnrollmentSecret)
	fake := newFakeNexttrace(t, fakeControl{})

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	cfg := testConfig(fake)
	cfg.Auth.TokenEnv = ""
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Controller = &ControllerConfig{
		URL:                controller.server.URL,
		EnrollmentTokenEnv: testEnrollmentTokenEnv,
		RefreshSeconds:     60,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, err := New(cfg, logger, WithEnrollmentRetry(10*time.Millisecond, 40*time.Millisecond, time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- agent.Run(ctx) }()

	healthURL := "http://" + cfg.Listen + "/v1/health"
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		request, err := http.NewRequest(http.MethodGet, healthURL, nil)
		if err == nil {
			request.Header.Set("Authorization", "Bearer run-mode-token")
			response, reqErr := client.Do(request)
			if reqErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK && controller.callCount() > 0 {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("agent did not enroll and serve on %s", cfg.Listen)
		}
		time.Sleep(10 * time.Millisecond)
	}

	calls := controller.snapshot()
	if calls[0].Request.URL != "http://"+cfg.Listen {
		t.Fatalf("advertised URL = %q, want http://%s", calls[0].Request.URL, cfg.Listen)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestEnrollmentAcceptsControllerNormalizedTraceURL(t *testing.T) {
	controller := newFakeEnrollmentController(t, func(_ int, request model.AgentEnrollRequest) (int, string) {
		return http.StatusOK, enrollmentResponseBody(request.NodeID, "https://agent.example.com:8443", "normalized-token")
	})
	agent, _ := newEnrollmentAgent(t, fakeControl{}, controller.server.URL, nil, func(cfg *Config) {
		cfg.Controller.AdvertiseURL = "https://Agent.EXAMPLE.com:8443"
	})
	if err := agent.enrollOnce(context.Background()); err != nil {
		t.Fatalf("enrollOnce with controller-normalized trace_url: %v", err)
	}
	if got := authorizedHealthStatus(t, agent, "normalized-token"); got != http.StatusOK {
		t.Fatalf("health status = %d, want 200", got)
	}
}
