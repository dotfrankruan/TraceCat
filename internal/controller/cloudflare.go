package controller

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	cfJWKSPath            = "/cdn-cgi/access/certs"
	cfClockLeeway         = 60 * time.Second
	defaultJWKSMaxBytes   = 1 << 20
	defaultCFRefreshDelay = 10 * time.Second
	defaultCFHTTPTimeout  = 5 * time.Second
	maxAccessTokenBytes   = 16 * 1024
)

var (
	errUnknownSigningKey = errors.New("cloudflare: unknown signing key")
	errJWKSFetch         = errors.New("cloudflare: JWKS fetch failed")
)

// CloudflarePrincipal is the verified identity carried by a Cloudflare Access
// JWT. It is derived only from signature-verified claims; identity headers are
// never consulted.
type CloudflarePrincipal struct {
	Subject string
	Email   string
}

// CloudflareVerifier validates Cloudflare Access RS256 JWTs against the team
// JWKS endpoint. Keys are cached with a TTL and refreshed (rate limited) when
// an unknown key id appears, so access-key rotation works without a restart.
type CloudflareVerifier struct {
	jwksURL   string
	issuer    string
	audience  map[string]struct{}
	emails    map[string]struct{}
	domains   []string
	ttl       time.Duration
	client    *http.Client
	maxBytes  int64
	cooldown  time.Duration
	now       func() time.Time
	refreshMu sync.Mutex

	mu                 sync.Mutex
	keys               map[string]*rsa.PublicKey
	fetchedAt          time.Time
	lastUnknownRefresh time.Time
}

// CloudflareVerifierOption customizes the verifier (used by tests and for
// operational tuning).
type CloudflareVerifierOption func(*CloudflareVerifier)

// WithJWKSURL overrides the JWKS endpoint (tests use an httptest server).
func WithJWKSURL(raw string) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.jwksURL = raw }
}

// WithCloudflareIssuer overrides the expected issuer.
func WithCloudflareIssuer(issuer string) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.issuer = strings.TrimRight(issuer, "/") }
}

// WithCloudflareNow injects a clock.
func WithCloudflareNow(now func() time.Time) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.now = now }
}

// WithCloudflareHTTPClient injects the JWKS HTTP client.
func WithCloudflareHTTPClient(client *http.Client) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.client = client }
}

// WithCloudflareRefreshCooldown sets the minimum interval between unknown-kid
// JWKS refreshes.
func WithCloudflareRefreshCooldown(d time.Duration) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.cooldown = d }
}

// WithCloudflareJWKSMaxBytes bounds the JWKS response size.
func WithCloudflareJWKSMaxBytes(n int64) CloudflareVerifierOption {
	return func(v *CloudflareVerifier) { v.maxBytes = n }
}

// NewCloudflareVerifier builds a verifier from the validated configuration.
func NewCloudflareVerifier(cfg CloudflareConfig, opts ...CloudflareVerifierOption) (*CloudflareVerifier, error) {
	if cfg.TeamDomain == "" || len(cfg.Audience) == 0 {
		return nil, errors.New("cloudflare: team_domain and audience are required")
	}
	base := strings.TrimRight(cfg.TeamDomain, "/")
	ttl := time.Duration(cfg.JWKSCacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = defaultCFJWKSCacheTTL * time.Second
	}
	v := &CloudflareVerifier{
		jwksURL:  base + cfJWKSPath,
		issuer:   base,
		audience: make(map[string]struct{}, len(cfg.Audience)),
		emails:   make(map[string]struct{}, len(cfg.AllowedEmails)),
		domains:  append([]string(nil), cfg.AllowedEmailDomains...),
		ttl:      ttl,
		client: &http.Client{
			Timeout: defaultCFHTTPTimeout,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				MaxIdleConns:          4,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       30 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBytes: defaultJWKSMaxBytes,
		cooldown: defaultCFRefreshDelay,
		now:      time.Now,
	}
	for _, aud := range cfg.Audience {
		v.audience[aud] = struct{}{}
	}
	for _, email := range cfg.AllowedEmails {
		v.emails[strings.ToLower(strings.TrimSpace(email))] = struct{}{}
	}
	for _, opt := range opts {
		opt(v)
	}
	if _, err := url.Parse(v.jwksURL); err != nil {
		return nil, fmt.Errorf("cloudflare: invalid JWKS URL: %w", err)
	}
	return v, nil
}

// Verify validates a compact JWS from the Cf-Access-Jwt-Assertion header or the
// CF_Authorization cookie (the header takes precedence). It returns a verified
// principal or a 401 API error.
func (v *CloudflareVerifier) Verify(ctx context.Context, headerToken, cookieToken string) (*CloudflarePrincipal, *model.APIError) {
	token := strings.TrimSpace(headerToken)
	if token == "" {
		token = strings.TrimSpace(cookieToken)
	}
	if token == "" {
		return nil, model.NewError(model.ErrUnauthorized, "authentication required")
	}
	if len(token) > maxAccessTokenBytes {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	headerJSON, err := decodeBase64URL(parts[0])
	if err != nil || len(headerJSON) > 4096 {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	if header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}

	key, err := v.signingKey(ctx, header.KeyID)
	if err != nil {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}

	signature, err := decodeBase64URL(parts[2])
	if err != nil || len(signature) == 0 {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}

	payloadJSON, err := decodeBase64URL(parts[1])
	if err != nil || len(payloadJSON) > maxAccessTokenBytes {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	var claims cfClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}

	now := v.now().UTC()
	if claims.ExpiresAt == 0 {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token")
	}
	if now.After(time.Unix(claims.ExpiresAt, 0).Add(cfClockLeeway)) {
		return nil, model.NewError(model.ErrUnauthorized, "access token expired")
	}
	if claims.NotBefore != 0 && now.Add(cfClockLeeway).Before(time.Unix(claims.NotBefore, 0)) {
		return nil, model.NewError(model.ErrUnauthorized, "access token not yet valid")
	}
	if claims.IssuedAt != 0 && now.Add(cfClockLeeway).Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, model.NewError(model.ErrUnauthorized, "access token not yet valid")
	}
	if strings.TrimRight(claims.Issuer, "/") != v.issuer {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token issuer")
	}
	if !v.audienceAllowed(claims.Audience) {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token audience")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, model.NewError(model.ErrUnauthorized, "invalid access token subject")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if !v.emailAllowed(email) {
		return nil, model.NewError(model.ErrUnauthorized, "identity is not allowed")
	}
	return &CloudflarePrincipal{Subject: claims.Subject, Email: email}, nil
}

func (v *CloudflareVerifier) emailAllowed(email string) bool {
	if len(v.emails) == 0 && len(v.domains) == 0 {
		return true
	}
	if email == "" {
		return false
	}
	if _, ok := v.emails[email]; ok {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	for _, allowed := range v.domains {
		if domain == allowed {
			return true
		}
	}
	return false
}

func (v *CloudflareVerifier) audienceAllowed(audiences []string) bool {
	for _, aud := range audiences {
		if _, ok := v.audience[aud]; ok {
			return true
		}
	}
	return false
}

func (v *CloudflareVerifier) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	keys := v.keys
	fetchedAt := v.fetchedAt
	v.mu.Unlock()

	now := v.now()
	if keys != nil && now.Sub(fetchedAt) < v.ttl {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		// Access key rotation: refresh at most once per cooldown window.
		refreshed, err := v.refreshKeys(ctx, true)
		if err != nil {
			return nil, err
		}
		if key, ok := refreshed[kid]; ok {
			return key, nil
		}
		return nil, errUnknownSigningKey
	}

	keys, err := v.refreshKeys(ctx, false)
	if err != nil {
		return nil, err
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	return nil, errUnknownSigningKey
}

func (v *CloudflareVerifier) refreshKeys(ctx context.Context, unknownKid bool) (map[string]*rsa.PublicKey, error) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	now := v.now()
	v.mu.Lock()
	if !unknownKid && v.keys != nil && now.Sub(v.fetchedAt) < v.ttl {
		keys := v.keys
		v.mu.Unlock()
		return keys, nil
	}
	if unknownKid && !v.lastUnknownRefresh.IsZero() && now.Sub(v.lastUnknownRefresh) < v.cooldown {
		keys := v.keys
		v.mu.Unlock()
		if keys == nil {
			return nil, errJWKSFetch
		}
		return keys, nil
	}
	if unknownKid {
		v.lastUnknownRefresh = now
	}
	v.mu.Unlock()

	keys, err := v.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return keys, nil
}

type jwksDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KeyType   string   `json:"kty"`
	KeyID     string   `json:"kid"`
	Use       string   `json:"use"`
	Algorithm string   `json:"alg"`
	Modulus   string   `json:"n"`
	Exponent  string   `json:"e"`
	X5C       []string `json:"x5c"`
}

func (v *CloudflareVerifier) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	reqCtx, cancel := context.WithTimeout(ctx, defaultCFHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, errJWKSFetch
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: transport error", errJWKSFetch)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", errJWKSFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, v.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read error", errJWKSFetch)
	}
	if int64(len(body)) > v.maxBytes {
		return nil, fmt.Errorf("%w: response too large", errJWKSFetch)
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: malformed document", errJWKSFetch)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.KeyID == "" || k.KeyType != "RSA" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != "RS256" {
			continue
		}
		pub, err := rsaPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.KeyID] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no usable RSA signing keys", errJWKSFetch)
	}
	return keys, nil
}

func rsaPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	modulus, err := decodeBase64URL(k.Modulus)
	if err != nil || len(modulus) == 0 || len(modulus) > 1024 {
		return nil, errors.New("invalid modulus")
	}
	exponent, err := decodeBase64URL(k.Exponent)
	if err != nil || len(exponent) == 0 || len(exponent) > 8 {
		return nil, errors.New("invalid exponent")
	}
	e := 0
	for _, b := range exponent {
		e = e<<8 | int(b)
	}
	if e < 3 || e > 1<<31-1 || e%2 == 0 {
		return nil, errors.New("invalid exponent")
	}
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < 1024 || n.BitLen() > 8192 {
		return nil, errors.New("invalid RSA key size")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

type cfClaims struct {
	Issuer    string
	Audience  []string
	Subject   string
	Email     string
	ExpiresAt int64
	NotBefore int64
	IssuedAt  int64
}

func (c *cfClaims) UnmarshalJSON(data []byte) error {
	type alias struct {
		Issuer    string          `json:"iss"`
		Audience  json.RawMessage `json:"aud"`
		Subject   string          `json:"sub"`
		Email     string          `json:"email"`
		ExpiresAt json.Number     `json:"exp"`
		NotBefore json.Number     `json:"nbf"`
		IssuedAt  json.Number     `json:"iat"`
	}
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*c = cfClaims{
		Issuer:  a.Issuer,
		Subject: a.Subject,
		Email:   a.Email,
	}
	if exp, ok := numberSeconds(a.ExpiresAt); ok {
		c.ExpiresAt = exp
	}
	if nbf, ok := numberSeconds(a.NotBefore); ok {
		c.NotBefore = nbf
	}
	if iat, ok := numberSeconds(a.IssuedAt); ok {
		c.IssuedAt = iat
	}
	if len(a.Audience) > 0 {
		var single string
		if err := json.Unmarshal(a.Audience, &single); err == nil {
			c.Audience = []string{single}
		} else {
			var many []string
			if err := json.Unmarshal(a.Audience, &many); err == nil {
				c.Audience = many
			}
		}
	}
	return nil
}

func numberSeconds(n json.Number) (int64, bool) {
	if n == "" {
		return 0, false
	}
	if v, err := n.Int64(); err == nil {
		return v, true
	}
	if f, err := n.Float64(); err == nil {
		return int64(f), true
	}
	return 0, false
}

func decodeBase64URL(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base64url value")
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
