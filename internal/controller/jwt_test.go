package controller

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const testCFIssuer = "https://team.example.cloudflareaccess.com"

type jwksServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetches int
}

func newJWKSServer(t *testing.T, keys map[string]*rsa.PublicKey) *jwksServer {
	t.Helper()
	j := &jwksServer{keys: keys}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		j.mu.Lock()
		j.fetches++
		doc := map[string]any{"keys": jwksKeys(j.keys)}
		j.mu.Unlock()
		data, _ := json.Marshal(doc)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwksServer) setKeys(keys map[string]*rsa.PublicKey) {
	j.mu.Lock()
	j.keys = keys
	j.mu.Unlock()
}

func (j *jwksServer) fetchCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.fetches
}

func jwksKeys(keys map[string]*rsa.PublicKey) []map[string]any {
	out := make([]map[string]any, 0, len(keys))
	for kid, pub := range keys {
		out = append(out, map[string]any{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return out
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func signAccessJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func accessClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   testCFIssuer,
		"aud":   []string{"aud-tag-1"},
		"sub":   "user-123",
		"email": "ops@example.com",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
	}
}

func newTestCFVerifier(t *testing.T, jwks *jwksServer, now time.Time, opts ...CloudflareVerifierOption) *CloudflareVerifier {
	t.Helper()
	cfg := CloudflareConfig{
		TeamDomain:          testCFIssuer,
		Audience:            []string{"aud-tag-1"},
		JWKSCacheTTLSeconds: 300,
	}
	allOpts := []CloudflareVerifierOption{
		WithJWKSURL(jwks.srv.URL),
		WithCloudflareIssuer(testCFIssuer),
		WithCloudflareNow(func() time.Time { return now }),
		WithCloudflareRefreshCooldown(10 * time.Second),
	}
	allOpts = append(allOpts, opts...)
	verifier, err := NewCloudflareVerifier(cfg, allOpts...)
	if err != nil {
		t.Fatalf("NewCloudflareVerifier: %v", err)
	}
	return verifier
}

func TestCloudflareVerifierValidToken(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)

	claims := accessClaims(now)
	token := signAccessJWT(t, key, "kid-1", claims)

	principal, apiErr := verifier.Verify(context.Background(), token, "")
	if apiErr != nil {
		t.Fatalf("Verify header token: %v", apiErr)
	}
	if principal.Subject != "user-123" || principal.Email != "ops@example.com" {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	// The cookie is consulted when the header is absent.
	principal, apiErr = verifier.Verify(context.Background(), "", token)
	if apiErr != nil || principal.Subject != "user-123" {
		t.Fatalf("Verify cookie token: %v %+v", apiErr, principal)
	}

	// The header takes precedence over the cookie.
	otherKey := generateRSAKey(t)
	badToken := signAccessJWT(t, otherKey, "kid-1", accessClaims(now))
	if _, apiErr := verifier.Verify(context.Background(), badToken, token); apiErr == nil {
		t.Fatal("expected the invalid header token to take precedence")
	}
}

func TestCloudflareVerifierSignatureAndClaimFailures(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	otherKey := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)

	cases := []struct {
		name  string
		token func() string
	}{
		{"bad signature", func() string {
			return signAccessJWT(t, otherKey, "kid-1", accessClaims(now))
		}},
		{"wrong issuer", func() string {
			claims := accessClaims(now)
			claims["iss"] = "https://evil.example.com"
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"wrong audience", func() string {
			claims := accessClaims(now)
			claims["aud"] = []string{"other-aud"}
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"expired", func() string {
			claims := accessClaims(now)
			claims["exp"] = now.Add(-2 * time.Minute).Unix()
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"not yet valid", func() string {
			claims := accessClaims(now)
			claims["nbf"] = now.Add(2 * time.Minute).Unix()
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"issued in the future", func() string {
			claims := accessClaims(now)
			claims["iat"] = now.Add(2 * time.Minute).Unix()
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"missing exp", func() string {
			claims := accessClaims(now)
			delete(claims, "exp")
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"missing subject", func() string {
			claims := accessClaims(now)
			delete(claims, "sub")
			return signAccessJWT(t, key, "kid-1", claims)
		}},
		{"none algorithm", func() string {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"kid-1"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + testCFIssuer + `","sub":"x"}`))
			return header + "." + payload + "."
		}},
		{"malformed", func() string { return "not.a.jwt" }},
		{"empty", func() string { return "" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			principal, apiErr := verifier.Verify(context.Background(), tc.token(), "")
			if apiErr == nil {
				t.Fatalf("expected failure, got %+v", principal)
			}
			if apiErr.Code != model.ErrUnauthorized {
				t.Fatalf("error code = %q, want unauthorized", apiErr.Code)
			}
		})
	}
}

func TestCloudflareVerifierClockLeeway(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)

	// 30 s in the past is inside the 60 s leeway.
	claims := accessClaims(now)
	claims["exp"] = now.Add(-30 * time.Second).Unix()
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", claims), ""); apiErr != nil {
		t.Fatalf("expected leeway to accept slightly expired token: %v", apiErr)
	}
	// 30 s in the future for nbf is also inside the leeway.
	claims = accessClaims(now)
	claims["nbf"] = now.Add(30 * time.Second).Unix()
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", claims), ""); apiErr != nil {
		t.Fatalf("expected leeway to accept slightly future nbf: %v", apiErr)
	}
}

func TestCloudflareVerifierEmailAllowlists(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier, err := NewCloudflareVerifier(CloudflareConfig{
		TeamDomain:          testCFIssuer,
		Audience:            []string{"aud-tag-1"},
		AllowedEmails:       []string{"ops@example.com"},
		AllowedEmailDomains: []string{"example.com"},
		JWKSCacheTTLSeconds: 300,
	},
		WithJWKSURL(jwks.srv.URL),
		WithCloudflareIssuer(testCFIssuer),
		WithCloudflareNow(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}

	makeToken := func(email string) string {
		claims := accessClaims(now)
		claims["email"] = email
		return signAccessJWT(t, key, "kid-1", claims)
	}
	if _, apiErr := verifier.Verify(context.Background(), makeToken("ops@example.com"), ""); apiErr != nil {
		t.Fatalf("allowlisted email rejected: %v", apiErr)
	}
	if _, apiErr := verifier.Verify(context.Background(), makeToken("other@example.com"), ""); apiErr != nil {
		t.Fatalf("allowlisted domain rejected: %v", apiErr)
	}
	if _, apiErr := verifier.Verify(context.Background(), makeToken("ops@evil.example"), ""); apiErr == nil {
		t.Fatal("email outside allowlists must be rejected")
	}
	claims := accessClaims(now)
	delete(claims, "email")
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", claims), ""); apiErr == nil {
		t.Fatal("missing email must be rejected when an allowlist is configured")
	}
}

func TestCloudflareVerifierUnknownKidRefresh(t *testing.T) {
	now := time.Now().UTC()
	key1 := generateRSAKey(t)
	key2 := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key1.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now, WithCloudflareRefreshCooldown(0))

	claims := accessClaims(now)
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key1, "kid-1", claims), ""); apiErr != nil {
		t.Fatalf("initial verification failed: %v", apiErr)
	}
	if jwks.fetchCount() != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", jwks.fetchCount())
	}

	// Key rotation: a new kid is signed by a new key that only appears after a
	// refresh.
	jwks.setKeys(map[string]*rsa.PublicKey{
		"kid-1": &key1.PublicKey,
		"kid-2": &key2.PublicKey,
	})
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key2, "kid-2", claims), ""); apiErr != nil {
		t.Fatalf("rotated key was not refreshed: %v", apiErr)
	}
	if jwks.fetchCount() != 2 {
		t.Fatalf("expected 2 JWKS fetches after rotation, got %d", jwks.fetchCount())
	}
}

func TestCloudflareVerifierUnknownKidRefreshRateLimited(t *testing.T) {
	now := time.Now().UTC()
	key1 := generateRSAKey(t)
	unknown := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key1.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now) // default 10 s cooldown

	claims := accessClaims(now)
	if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key1, "kid-1", claims), ""); apiErr != nil {
		t.Fatalf("initial verification failed: %v", apiErr)
	}
	before := jwks.fetchCount()
	for i := 0; i < 3; i++ {
		if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, unknown, "kid-unknown", claims), ""); apiErr == nil {
			t.Fatal("unknown kid must be rejected")
		}
	}
	if got := jwks.fetchCount() - before; got != 1 {
		t.Fatalf("expected exactly one rate-limited refresh, got %d", got)
	}
}

func TestCloudflareVerifierJWKSFailures(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)

	t.Run("server error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer srv.Close()
		verifier, err := NewCloudflareVerifier(CloudflareConfig{
			TeamDomain: testCFIssuer, Audience: []string{"aud-tag-1"}, JWKSCacheTTLSeconds: 300,
		}, WithJWKSURL(srv.URL), WithCloudflareIssuer(testCFIssuer), WithCloudflareNow(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", accessClaims(now)), ""); apiErr == nil {
			t.Fatal("expected unauthorized when JWKS is unavailable")
		}
	})

	t.Run("oversized document", func(t *testing.T) {
		jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
		verifier := newTestCFVerifier(t, jwks, now, WithCloudflareJWKSMaxBytes(16))
		if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", accessClaims(now)), ""); apiErr == nil {
			t.Fatal("expected unauthorized when JWKS is too large")
		}
	})

	t.Run("no usable keys", func(t *testing.T) {
		jwks := newJWKSServer(t, nil)
		verifier := newTestCFVerifier(t, jwks, now)
		if _, apiErr := verifier.Verify(context.Background(), signAccessJWT(t, key, "kid-1", accessClaims(now)), ""); apiErr == nil {
			t.Fatal("expected unauthorized when JWKS has no keys")
		}
	})
}

func TestCloudflareVerifierRejectsOversizedToken(t *testing.T) {
	now := time.Now().UTC()
	key := generateRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier := newTestCFVerifier(t, jwks, now)
	token := strings.Repeat("a", maxAccessTokenBytes+1)
	if _, apiErr := verifier.Verify(context.Background(), token, ""); apiErr == nil {
		t.Fatal("expected oversized token to be rejected")
	}
}
