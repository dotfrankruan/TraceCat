package controller

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
	"github.com/dotfrankruan/tracecat/internal/version"
)

const (
	sessionCookieName = "tracecat_session"
	cfAuthCookieName  = "CF_Authorization"
	csrfHeaderName    = "X-TraceCat-CSRF"

	sessionTokenBytes = 32
	csrfTokenBytes    = 32

	// loginRatePerMinute bounds password attempts per client IP.
	loginRatePerMinute = 10

	devUserSubject = "dev"
	localSubject   = "local"
)

type principalContextKey struct{}

// Principal is the authenticated browser identity plus the CSRF token that must
// accompany state-changing requests.
type Principal struct {
	User        model.User
	CSRFToken   string
	SessionHash string

	// sessionToken is the raw local-auth cookie value. It exists only between
	// Login and SetSessionCookie and is never logged or serialized.
	sessionToken string
}

// Auth implements the three browser authentication modes and the CSRF policy.
type Auth struct {
	cfg          *Config
	store        *Store
	verifier     *CloudflareVerifier
	csrfKey      []byte
	loginLimiter *rateLimiter
	now          func() time.Time
	random       io.Reader
}

// AuthOption customizes Auth construction (tests inject a verifier whose JWKS
// endpoint is an httptest server).
type AuthOption func(*Auth)

// WithAuthCloudflareVerifier injects a pre-built verifier.
func WithAuthCloudflareVerifier(v *CloudflareVerifier) AuthOption {
	return func(a *Auth) { a.verifier = v }
}

// WithAuthClock injects a clock.
func WithAuthClock(now func() time.Time) AuthOption {
	return func(a *Auth) { a.now = now }
}

// WithAuthRandom injects the entropy source.
func WithAuthRandom(r io.Reader) AuthOption {
	return func(a *Auth) { a.random = r }
}

// NewAuth builds the authentication service for the configured mode.
func NewAuth(cfg *Config, store *Store, opts ...AuthOption) (*Auth, error) {
	if cfg == nil || store == nil {
		return nil, errors.New("auth: config and store are required")
	}
	a := &Auth{
		cfg:          cfg,
		store:        store,
		loginLimiter: newRateLimiter(loginRatePerMinute),
		now:          time.Now,
		random:       rand.Reader,
	}
	if cfg.Auth.Mode == AuthModeCloudflare {
		if len(cfg.Auth.Cloudflare.csrfSecret) > 0 {
			a.csrfKey = append([]byte(nil), cfg.Auth.Cloudflare.csrfSecret...)
		} else {
			key := make([]byte, 32)
			if _, err := io.ReadFull(a.random, key); err != nil {
				return nil, fmt.Errorf("auth: generate CSRF secret: %w", err)
			}
			a.csrfKey = key
		}
	} else {
		key := make([]byte, 32)
		if _, err := io.ReadFull(a.random, key); err != nil {
			return nil, fmt.Errorf("auth: generate CSRF secret: %w", err)
		}
		a.csrfKey = key
	}
	for _, opt := range opts {
		opt(a)
	}
	if cfg.Auth.Mode == AuthModeCloudflare && a.verifier == nil {
		verifier, err := NewCloudflareVerifier(cfg.Auth.Cloudflare)
		if err != nil {
			return nil, err
		}
		a.verifier = verifier
	}
	return a, nil
}

// Mode returns the active authentication mode.
func (a *Auth) Mode() string { return a.cfg.Auth.Mode }

// Authenticate resolves the current request's principal. It never trusts
// unverified identity headers.
func (a *Auth) Authenticate(r *http.Request) (*Principal, *model.APIError) {
	switch a.cfg.Auth.Mode {
	case AuthModeDev:
		if apiErr := rejectProxyHeaders(r); apiErr != nil {
			return nil, apiErr
		}
		subject := devUserSubject
		return &Principal{
			User:      model.User{Email: "dev@localhost", Subject: subject, AuthMethod: AuthModeDev},
			CSRFToken: a.statelessCSRF(subject),
		}, nil
	case AuthModeLocal:
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			return nil, model.NewError(model.ErrUnauthorized, "authentication required")
		}
		hash := hashSessionToken(strings.TrimSpace(cookie.Value))
		sess, err := a.store.GetSession(r.Context(), hash, a.now())
		if err != nil {
			if errors.Is(err, ErrStoreNotFound) {
				return nil, model.NewError(model.ErrUnauthorized, "session expired or invalid")
			}
			return nil, model.NewError(model.ErrInternal, "internal error")
		}
		if sess.CSRFToken == "" {
			return nil, model.NewError(model.ErrUnauthorized, "session expired or invalid")
		}
		return &Principal{
			User:        model.User{Email: sess.Email, Subject: sess.Subject, AuthMethod: AuthModeLocal},
			CSRFToken:   sess.CSRFToken,
			SessionHash: hash,
		}, nil
	case AuthModeCloudflare:
		if a.verifier == nil {
			return nil, model.NewError(model.ErrInternal, "internal error")
		}
		headerToken := r.Header.Get("Cf-Access-Jwt-Assertion")
		cookieToken := ""
		if cookie, err := r.Cookie(cfAuthCookieName); err == nil {
			cookieToken = cookie.Value
		}
		verified, apiErr := a.verifier.Verify(r.Context(), headerToken, cookieToken)
		if apiErr != nil {
			return nil, apiErr
		}
		return &Principal{
			User:      model.User{Email: verified.Email, Subject: verified.Subject, AuthMethod: AuthModeCloudflare},
			CSRFToken: a.statelessCSRF(verified.Subject),
		}, nil
	default:
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
}

func rejectProxyHeaders(r *http.Request) *model.APIError {
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"} {
		if strings.TrimSpace(r.Header.Get(header)) != "" {
			return model.NewError(model.ErrForbidden, "proxy headers are not permitted in dev mode")
		}
	}
	return nil
}

// RequireAuth is the default-deny authentication middleware for API routes.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, apiErr := a.Authenticate(r)
		if apiErr != nil {
			writeAPIError(w, statusForErrorCode(apiErr.Code), apiErr)
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireCSRF enforces the double-submit CSRF policy and same-origin fetch
// metadata for state-changing requests.
func (a *Auth) RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		principal := PrincipalFrom(r.Context())
		if principal == nil {
			writeAPIError(w, http.StatusUnauthorized, model.NewError(model.ErrUnauthorized, "authentication required"))
			return
		}
		if apiErr := a.validateCSRF(r, principal); apiErr != nil {
			writeAPIError(w, http.StatusForbidden, apiErr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) validateCSRF(r *http.Request, principal *Principal) *model.APIError {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		if !a.originMatches(origin) {
			return model.NewError(model.ErrCSRFFailed, "request origin is not allowed")
		}
	}
	if site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); site != "" {
		if site != "same-origin" && site != "none" {
			return model.NewError(model.ErrCSRFFailed, "cross-site request is not allowed")
		}
	}
	provided := strings.TrimSpace(r.Header.Get(csrfHeaderName))
	if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(principal.CSRFToken)) != 1 {
		return model.NewError(model.ErrCSRFFailed, "missing or invalid CSRF token")
	}
	return nil
}

func (a *Auth) originMatches(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || parsed.Scheme == "" {
		return false
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return false
	}
	target := a.cfg.PublicOriginURL()
	if target == nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, target.Scheme) && strings.EqualFold(parsed.Host, target.Host)
}

func (a *Auth) statelessCSRF(subject string) string {
	mac := hmac.New(sha256.New, a.csrfKey)
	mac.Write([]byte("tracecat-csrf-v1:"))
	mac.Write([]byte(subject))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Login verifies a local-mode password and creates a server-side session. It
// returns the principal (including the per-session CSRF token) for the response.
func (a *Auth) Login(ctx context.Context, clientIP, password string) (*Principal, *model.APIError) {
	if a.cfg.Auth.Mode != AuthModeLocal {
		return nil, model.NewError(model.ErrNotFound, "not found")
	}
	if !a.loginLimiter.Allow(clientIP) {
		return nil, model.NewError(model.ErrRateLimited, "too many login attempts; try again later")
	}
	ok, err := VerifyPassword(password, a.cfg.Auth.Local.passwordHash)
	if err != nil || !ok {
		return nil, model.NewError(model.ErrUnauthorized, "invalid password")
	}
	tokenBytes := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(a.random, tokenBytes); err != nil {
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
	csrfBytes := make([]byte, csrfTokenBytes)
	if _, err := io.ReadFull(a.random, csrfBytes); err != nil {
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	csrf := base64.RawURLEncoding.EncodeToString(csrfBytes)
	now := a.now().UTC()
	expires := now.Add(time.Duration(a.cfg.Auth.Local.SessionTTLSeconds) * time.Second)
	record := SessionRecord{
		TokenHash: hashSessionToken(token),
		Subject:   localSubject,
		CSRFToken: csrf,
		CreatedAt: now,
		ExpiresAt: expires,
	}
	if err := a.store.CreateSession(ctx, record); err != nil {
		return nil, model.NewError(model.ErrInternal, "internal error")
	}
	// Opportunistic cleanup so expired rows do not accumulate indefinitely.
	_, _ = a.store.DeleteExpiredSessions(ctx, now)
	return &Principal{
		User:         model.User{Subject: localSubject, AuthMethod: AuthModeLocal},
		CSRFToken:    csrf,
		SessionHash:  record.TokenHash,
		sessionToken: token,
	}, nil
}

// RevokeSession deletes the session backing the principal (local mode).
func (a *Auth) RevokeSession(ctx context.Context, principal *Principal) *model.APIError {
	if principal == nil || principal.SessionHash == "" {
		return nil
	}
	if err := a.store.DeleteSession(ctx, principal.SessionHash); err != nil {
		return model.NewError(model.ErrInternal, "internal error")
	}
	return nil
}

// SetSessionCookie writes the session cookie for a successful local login.
func (a *Auth) SetSessionCookie(w http.ResponseWriter, principal *Principal) {
	if principal == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    principal.sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.IsHTTPS(),
		SameSite: http.SameSiteStrictMode,
		Expires:  a.now().UTC().Add(time.Duration(a.cfg.Auth.Local.SessionTTLSeconds) * time.Second),
		MaxAge:   a.cfg.Auth.Local.SessionTTLSeconds,
	})
}

// ClearSessionCookie instructs the browser to drop the session cookie.
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.IsHTTPS(),
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
	})
}

// SessionResponse builds the GET /api/v1/session body.
func (a *Auth) SessionResponse(principal *Principal) model.Session {
	user := principal.User
	return model.Session{
		Authenticated: true,
		Mode:          a.cfg.Auth.Mode,
		User:          &user,
		CSRFToken:     principal.CSRFToken,
		Limits:        a.cfg.SessionLimits(),
		Version:       version.Version,
		Warnings:      a.cfg.Warnings(),
	}
}

// PrincipalFrom returns the authenticated principal stored by RequireAuth.
func PrincipalFrom(ctx context.Context) *Principal {
	principal, _ := ctx.Value(principalContextKey{}).(*Principal)
	return principal
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
