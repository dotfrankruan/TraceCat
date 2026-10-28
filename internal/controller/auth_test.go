package controller

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const testLocalPassword = "correct horse battery staple"

func localHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	all := []harnessOption{
		withMode(AuthModeLocal),
		withAgents(newFakeAgent(t, "node-one")),
	}
	all = append(all, opts...)
	return newHarness(t, all...)
}

func TestLocalAuthLoginSessionLogout(t *testing.T) {
	h := localHarness(t)
	session, resp, body := h.login(testLocalPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d body=%s", resp.StatusCode, body)
	}
	if !session.Authenticated || session.Mode != AuthModeLocal || session.User == nil {
		t.Fatalf("unexpected session: %+v", session)
	}
	if session.User.Subject != localSubject || session.User.AuthMethod != AuthModeLocal {
		t.Fatalf("unexpected user: %+v", session.User)
	}
	if session.CSRFToken == "" {
		t.Fatal("login response has no CSRF token")
	}
	if session.Limits.MaxHops != h.cfg.Limits.MaxHops || session.Limits.MaxHistoryJobs != h.cfg.Database.MaxHistoryJobs {
		t.Fatalf("session limits do not reflect config: %+v", session.Limits)
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
		t.Fatalf("unexpected cookies: %+v", cookies)
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("insecure cookie flags: %+v", cookie)
	}
	if cookie.Secure {
		t.Fatalf("Secure cookie flag must not be set for an http origin")
	}
	if cookie.Value == "" || cookie.MaxAge <= 0 {
		t.Fatalf("unexpected cookie value: %+v", cookie)
	}

	// Authenticated session endpoint via the cookie.
	resp, body = h.get("/api/v1/session")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session status = %d body=%s", resp.StatusCode, body)
	}
	current := decodeJSONResponse[model.Session](t, resp, body)
	if current.User.Subject != localSubject {
		t.Fatalf("unexpected session user: %+v", current.User)
	}

	// Logout revokes the session server-side and clears the cookie.
	resp, body = h.post("/api/v1/auth/logout", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d body=%s", resp.StatusCode, body)
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("logout did not clear the session cookie")
	}
	// The jar now holds the expired cookie; even replaying the original value
	// must fail because the row was deleted.
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/session", nil)
	req.Header.Set("Cookie", sessionCookieName+"="+cookie.Value)
	resp2, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session status = %d", resp2.StatusCode)
	}
}

func TestLocalAuthWrongPasswordAndRateLimit(t *testing.T) {
	h := localHarness(t)
	for i := 0; i < loginRatePerMinute; i++ {
		_, resp, body := h.login("wrong password")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body=%s", i, resp.StatusCode, body)
		}
	}
	_, resp, body := h.login(testLocalPassword)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected rate limiting, got %d body=%s", resp.StatusCode, body)
	}
}

func TestLocalAuthSessionExpiry(t *testing.T) {
	h := localHarness(t)
	// Create an already-expired session row and present its cookie.
	token := "expired-session-token-value"
	hash := hashSessionToken(token)
	now := time.Now().UTC()
	if err := h.store.CreateSession(context.Background(), SessionRecord{
		TokenHash: hash,
		Subject:   localSubject,
		CSRFToken: "csrf",
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/api/v1/session", nil)
	req.Header.Set("Cookie", sessionCookieName+"="+token)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session status = %d", resp.StatusCode)
	}
}

func TestSecureCookieForHTTPSOrigin(t *testing.T) {
	h := localHarness(t, withDocMutation(func(doc map[string]any) {
		doc["public_origin"] = "https://trace.example.com"
	}))
	_, resp, body := h.login(testLocalPassword)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d body=%s", resp.StatusCode, body)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 || !cookies[0].Secure {
		t.Fatalf("expected Secure session cookie for an https origin: %+v", cookies)
	}
}

func TestCSRFEnforcement(t *testing.T) {
	h := localHarness(t)
	if _, resp, body := h.login(testLocalPassword); resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resp.StatusCode, body)
	}
	csrf := h.csrf

	resolveBody := model.ResolveRequest{Target: "dns.example"}
	cases := []struct {
		name    string
		headers map[string]string
		status  int
	}{
		{"missing token", nil, http.StatusForbidden},
		{"wrong token", map[string]string{csrfHeaderName: "definitely-wrong"}, http.StatusForbidden},
		{"correct token", map[string]string{csrfHeaderName: csrf}, http.StatusOK},
		{"correct token bad origin", map[string]string{csrfHeaderName: csrf, "Origin": "https://evil.example"}, http.StatusForbidden},
		{"correct token matching origin", map[string]string{csrfHeaderName: csrf, "Origin": h.cfg.PublicOrigin}, http.StatusOK},
		{"null origin", map[string]string{csrfHeaderName: csrf, "Origin": "null"}, http.StatusForbidden},
		{"cross-site fetch metadata", map[string]string{csrfHeaderName: csrf, "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-origin fetch metadata", map[string]string{csrfHeaderName: csrf, "Sec-Fetch-Site": "same-origin"}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := h.request(http.MethodPost, "/api/v1/resolve", resolveBody, tc.headers)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d body=%s", resp.StatusCode, tc.status, body)
			}
			if tc.status == http.StatusForbidden {
				envelope := decodeJSONResponse[model.ErrorResponse](t, resp, body)
				if envelope.Error == nil || envelope.Error.Code != model.ErrCSRFFailed {
					t.Fatalf("unexpected error: %+v", envelope.Error)
				}
			}
		})
	}
}

func TestDevModeRejectsProxyHeaders(t *testing.T) {
	h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"} {
		t.Run(header, func(t *testing.T) {
			resp, body := h.request(http.MethodGet, "/api/v1/session", nil, map[string]string{header: "203.0.113.5"})
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d body=%s", resp.StatusCode, body)
			}
		})
	}
	// healthz remains an unauthenticated liveness probe, but proxy headers are
	// rejected there too in dev mode.
	resp, _ := h.get("/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	proxiedResp, proxiedBody := h.request(http.MethodGet, "/healthz", nil, map[string]string{"X-Forwarded-For": "203.0.113.5"})
	if proxiedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxied healthz status = %d body=%s", proxiedResp.StatusCode, proxiedBody)
	}
}

func TestAuthLoginEndpointsOnlyInLocalMode(t *testing.T) {
	for _, mode := range []string{AuthModeDev, AuthModeCloudflare} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, withMode(mode), withAgents(newFakeAgent(t, "node-one")))
			resp, body := h.request(http.MethodPost, "/api/v1/auth/login", model.LoginRequest{Password: "x"}, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("login status = %d body=%s", resp.StatusCode, body)
			}
			resp, body = h.request(http.MethodPost, "/api/v1/auth/logout", nil, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("logout status = %d body=%s", resp.StatusCode, body)
			}
		})
	}
}

func TestCloudflareIdentityHeaderSpoofIgnored(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)

	doc := testConfigDoc(t, AuthModeCloudflare, []*fakeAgent{newFakeAgent(t, "node-one")}, "")
	cfg, err := LoadConfig(writeConfigDoc(t, doc))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	store := testStore(t, 5)
	auth, err := NewAuth(cfg, store, WithAuthCloudflareVerifier(verifier))
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	token := signAccessJWT(t, key, "kid-1", accessClaims(now))
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Access-Jwt-Assertion", token)
	req.Header.Set("Cf-Access-Authenticated-User-Email", "admin@evil.example")
	req.Header.Set("Cf-Access-Authenticated-User-Id", "spoofed")
	principal, apiErr := auth.Authenticate(req)
	if apiErr != nil {
		t.Fatalf("Authenticate: %v", apiErr)
	}
	if principal.User.Email != "ops@example.com" || principal.User.Subject != "user-123" {
		t.Fatalf("identity header spoofing was trusted: %+v", principal.User)
	}
	if principal.CSRFToken == "" {
		t.Fatal("cloudflare principal has no CSRF token")
	}
}

func TestCloudflareCookieAuthentication(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)
	doc := testConfigDoc(t, AuthModeCloudflare, []*fakeAgent{newFakeAgent(t, "node-one")}, "")
	cfg, err := LoadConfig(writeConfigDoc(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	store := testStore(t, 5)
	auth, err := NewAuth(cfg, store, WithAuthCloudflareVerifier(verifier))
	if err != nil {
		t.Fatal(err)
	}
	token := signAccessJWT(t, key, "kid-1", accessClaims(now))

	t.Run("cookie only", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
		req.AddCookie(&http.Cookie{Name: cfAuthCookieName, Value: token})
		principal, apiErr := auth.Authenticate(req)
		if apiErr != nil || principal.User.Email != "ops@example.com" {
			t.Fatalf("cookie auth failed: %v %+v", apiErr, principal)
		}
	})
	t.Run("no credentials", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
		if _, apiErr := auth.Authenticate(req); apiErr == nil || apiErr.Code != model.ErrUnauthorized {
			t.Fatalf("expected unauthorized, got %v", apiErr)
		}
	})
	t.Run("dev csrf is stable", func(t *testing.T) {
		h := newHarness(t, withAgents(newFakeAgent(t, "node-one")))
		resp, body := h.get("/api/v1/session")
		session := decodeJSONResponse[model.Session](t, resp, body)
		resp, body = h.get("/api/v1/session")
		again := decodeJSONResponse[model.Session](t, resp, body)
		if session.CSRFToken == "" || session.CSRFToken != again.CSRFToken {
			t.Fatalf("dev CSRF token is not stable: %q vs %q", session.CSRFToken, again.CSRFToken)
		}
	})
}

func TestAuthStrictLoginBody(t *testing.T) {
	h := localHarness(t)
	// Unknown fields are rejected.
	resp, body := h.request(http.MethodPost, "/api/v1/auth/login",
		map[string]any{"password": testLocalPassword, "extra": true}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	// Oversized bodies are rejected (4 KiB limit).
	resp, body = h.request(http.MethodPost, "/api/v1/auth/login",
		map[string]any{"password": strings.Repeat("x", 5000)}, nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}
	// Malformed JSON is rejected without detail.
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/api/v1/auth/login", strings.NewReader(`{"password":`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rawResp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rawResp.Body.Close()
	if rawResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", rawResp.StatusCode)
	}
	_ = json.Valid
}
