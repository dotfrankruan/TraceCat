package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"

	"strings"
	"testing"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func TestSecurityHeadersAndNoStore(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))

	paths := []string{"/", "/healthz", "/api/v1/session"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, _ := h.get(path)
			csp := resp.Header.Get("Content-Security-Policy")
			for _, fragment := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'",
				"img-src 'self' data:", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'",
				"form-action 'self'", "object-src 'none'"} {
				if !strings.Contains(csp, fragment) {
					t.Fatalf("CSP %q missing %q", csp, fragment)
				}
			}
			checks := map[string]string{
				"X-Content-Type-Options":     "nosniff",
				"X-Frame-Options":            "DENY",
				"Referrer-Policy":            "no-referrer",
				"Cross-Origin-Opener-Policy": "same-origin",
			}
			for header, want := range checks {
				if got := resp.Header.Get(header); got != want {
					t.Fatalf("%s = %q, want %q", header, got, want)
				}
			}
			if resp.Header.Get("Permissions-Policy") == "" {
				t.Fatal("Permissions-Policy is missing")
			}
			if resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("permissive CORS must never be enabled")
			}
			if strings.HasPrefix(path, "/api/") && resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))
	resp, body := h.get("/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type = %q", ct)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["status"] != "ok" || payload["schema_version"] != model.ControllerSchemaVersion {
		t.Fatalf("unexpected health payload: %s", body)
	}
	if _, ok := payload["version"]; ok {
		t.Fatal("healthz must not expose the build version")
	}
	if len(payload) != 2 {
		t.Fatalf("healthz exposes extra fields: %s", body)
	}
}

func TestUnauthenticatedAPIsDefaultDeny(t *testing.T) {
	h := newHarness(t, withMode(AuthModeLocal), withAgents(newFakeAgent(t, "node-one")))
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/session"},
		{http.MethodGet, "/api/v1/nodes"},
		{http.MethodGet, "/api/v1/jobs"},
		{http.MethodGet, "/api/v1/jobs/0123456789abcdef0123456789abcdef"},
		{http.MethodPost, "/api/v1/resolve"},
		{http.MethodPost, "/api/v1/jobs"},
	} {
		resp, body := h.request(tc.method, tc.path, nil, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d body=%s", tc.method, tc.path, resp.StatusCode, body)
		}
		envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
		if envelope.Error == nil || envelope.Error.Code != model.ErrUnauthorized {
			t.Fatalf("unexpected error envelope: %s", body)
		}
	}
}

func TestJSONNotFoundAndMethodNotAllowed(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))

	resp, body := h.get("/api/v1/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown API path status = %d", resp.StatusCode)
	}
	envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error == nil || envelope.Error.Code != model.ErrNotFound {
		t.Fatalf("unexpected error: %s", body)
	}

	resp, body = h.request(http.MethodDelete, "/api/v1/jobs", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("method not allowed status = %d body=%s", resp.StatusCode, body)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "GET") || !strings.Contains(allow, "POST") {
		t.Fatalf("Allow header = %q", allow)
	}
	envelope = decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error == nil {
		t.Fatalf("405 body is not a JSON error envelope: %s", body)
	}

	// HEAD is not enabled on API routes; method handling stays strict.
	resp, _ = h.request(http.MethodHead, "/api/v1/nodes", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD status = %d", resp.StatusCode)
	}

	// healthz only answers GET.
	resp, _ = h.request(http.MethodPost, "/healthz", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("healthz POST status = %d", resp.StatusCode)
	}
}

func TestWebUIMountedAndAPIWins(t *testing.T) {
	h := newHarness(t, withMode(AuthModeLocal), withAgents(newFakeAgent(t, "node-one")))

	resp, body := h.get("/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("root status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "TraceCat") {
		t.Fatalf("root did not serve the dashboard placeholder: %s", body)
	}
	// The API prefix must never fall through to the SPA handler.
	resp, body = h.get("/api/v1/session")
	if strings.Contains(string(body), "<!doctype html>") {
		t.Fatalf("API route fell through to the web UI: %s", body)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session status = %d", resp.StatusCode)
	}
}

func TestPanicRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := recoverPanics(logger, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: secret internal detail")
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "secret internal detail") || strings.Contains(body, "goroutine") {
		t.Fatalf("panic details leaked: %s", body)
	}
	var envelope model.ErrorResponse
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || envelope.Error == nil || envelope.Error.Code != model.ErrInternal {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestResolveStrictBodyAndLimits(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))

	resp, body := h.post("/api/v1/resolve", map[string]any{"target": "dns.example", "extra": 1})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d body=%s", resp.StatusCode, body)
	}

	resp, body = h.post("/api/v1/resolve", map[string]any{"target": strings.Repeat("a", 2000)})
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d body=%s", resp.StatusCode, body)
	}

	resp, body = h.post("/api/v1/resolve", model.ResolveRequest{Target: "dns.example"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resolve status = %d body=%s", resp.StatusCode, body)
	}
	envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error != nil {
		t.Fatalf("unexpected error: %+v", envelope.Error)
	}
}

func TestResolveErrorsDoNotLeakResolverInternals(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")), withResolver(failingResolver{}))
	resp, body := h.post("/api/v1/resolve", model.ResolveRequest{Target: "dns.example"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
	if envelope.Error == nil || envelope.Error.Code != model.ErrDNSError {
		t.Fatalf("unexpected error: %s", body)
	}
	for _, leak := range []string{"resolver", "127.0.0.1", "internal/dns", "goroutine"} {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(leak)) {
			t.Fatalf("response leaks %q: %s", leak, body)
		}
	}
}

type failingResolver struct{}

func (failingResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return nil, errors.New("dns transport failure")
}

func TestNodesEndpointShowsCachedHealth(t *testing.T) {
	a1 := newFakeAgent(t, "node-one")
	a2 := newFakeAgent(t, "node-two")
	h := newHarness(t, withMode(AuthModeLocal), withAgents(a1, a2), withConfigMutation(func(cfg *Config) {
		cfg.Agents[1].Enabled = boolPtr(false)
	}))
	if _, resp, body := h.login(testLocalPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	h.registry.CheckAll(context.Background())
	resp, body := h.get("/api/v1/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", resp.StatusCode, body)
	}
	list := decodeJSONResponse[model.NodeList](t, resp, body)
	if len(list.Nodes) != 2 {
		t.Fatalf("nodes = %+v", list.Nodes)
	}
	if list.Nodes[0].Health != HealthOK || list.Nodes[1].Health != HealthDisabled {
		t.Fatalf("unexpected health: %+v", list.Nodes)
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}

	// Untrusted peer: forwarding headers are ignored.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.50:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	if got := clientIP(req, prefixes); got != "192.0.2.50" {
		t.Fatalf("untrusted peer client IP = %q", got)
	}

	// Trusted peer: rightmost non-trusted hop wins.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.1.2.3")
	if got := clientIP(req, prefixes); got != "1.2.3.4" {
		t.Fatalf("trusted peer client IP = %q", got)
	}

	// Trusted peer with only X-Real-IP.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Real-IP", "9.9.9.9")
	if got := clientIP(req, prefixes); got != "9.9.9.9" {
		t.Fatalf("X-Real-IP fallback = %q", got)
	}
}
