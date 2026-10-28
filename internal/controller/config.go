package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

// Auth modes accepted by the Controller. Each one changes the browser
// authentication mechanism and the CSRF token derivation.
const (
	// AuthModeCloudflare verifies Cloudflare Access JWTs on every request.
	AuthModeCloudflare = "cloudflare"
	// AuthModeLocal uses a password login with SQLite-backed sessions.
	AuthModeLocal = "local"
	// AuthModeDev is a loopback-only authentication bypass for development.
	AuthModeDev = "dev"
)

// Config defaults. These are applied by LoadConfig before validation so a
// minimal document only has to set the mandatory fields.
const (
	defaultListen           = "127.0.0.1:8080"
	defaultLogLevel         = "info"
	defaultMaxHistoryJobs   = 200
	defaultDNSTimeoutMS     = 4_000
	defaultDNSMaxAddresses  = 16
	defaultMaxHops          = 30
	defaultMaxQueries       = 3
	defaultMinExecutionMS   = model.MinExecutionTimeoutMS
	defaultMaxExecutionMS   = 60_000
	defaultMaxNodesPerJob   = 8
	defaultMaxJobsPerMinute = 30
	defaultMaxConcurrent    = 4
	defaultMaxRawResultSize = 1 << 20 // 1 MiB per node, as documented in API.md.
	defaultMaxResolves      = 120
	defaultCFJWKSCacheTTL   = 300
	defaultLocalSessionTTL  = 12 * 60 * 60
	dispatchTimeoutMargin   = 10 * 1_000 // ms added to the requested trace timeout

	maxConfigBytes = 1 << 20
)

// Config is the validated Controller configuration. Secrets are never read from
// the document itself: environment-variable names are configured and resolved
// into unexported fields by LoadConfig.
type Config struct {
	Listen         string         `json:"listen"`
	PublicOrigin   string         `json:"public_origin"`
	Auth           AuthConfig     `json:"auth"`
	Database       DatabaseConfig `json:"database"`
	DNS            DNSConfig      `json:"dns"`
	Limits         LimitsConfig   `json:"limits"`
	Agents         []AgentConfig  `json:"agents"`
	Security       SecurityConfig `json:"security"`
	TrustedProxies []string       `json:"trusted_proxies"`
	LogLevel       string         `json:"log_level"`

	// Derived, unexported state populated by LoadConfig.
	publicOrigin     *url.URL
	trustedPrefix    []netip.Prefix
	targetPolicy     ipguard.Policy
	allowedProtocols []model.Protocol
}

// SecurityConfig contains administrator-controlled target policy extensions.
// The default policy allows only globally routable unicast destinations; the
// allowlist is the single explicit way to permit private/lab ranges for
// testing. The same policy type is enforced independently by Agents.
type SecurityConfig struct {
	AllowedCIDRs []string `json:"allowed_cidrs"`
}

// AuthConfig selects and parameterizes the browser authentication mode.
type AuthConfig struct {
	Mode       string           `json:"mode"`
	Cloudflare CloudflareConfig `json:"cloudflare"`
	Local      LocalConfig      `json:"local"`
	Dev        DevConfig        `json:"dev"`
}

// CloudflareConfig configures Cloudflare Access JWT verification.
type CloudflareConfig struct {
	TeamDomain          string   `json:"team_domain"`
	Audience            []string `json:"audience"`
	AllowedEmails       []string `json:"allowed_emails"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
	JWKSCacheTTLSeconds int      `json:"jwks_cache_ttl_seconds"`
	// CSRFSecretEnv optionally names an environment variable holding a
	// high-entropy secret used to derive stateless CSRF tokens. When empty a
	// random per-process secret is generated (fine for a single instance).
	CSRFSecretEnv string `json:"csrf_secret_env"`

	csrfSecret []byte
}

// LocalConfig configures password login.
type LocalConfig struct {
	PasswordHashEnv   string `json:"password_hash_env"`
	SessionTTLSeconds int    `json:"session_ttl_seconds"`

	// passwordHash is the resolved PBKDF2 hash. It is never serialized.
	passwordHash string
}

// DevConfig has no fields: dev mode is an explicit loopback-only bypass.
type DevConfig struct{}

// DatabaseConfig configures the SQLite history store.
type DatabaseConfig struct {
	Path           string `json:"path"`
	MaxHistoryJobs int    `json:"max_history_jobs"`
}

// DNSConfig configures central DNS resolution.
type DNSConfig struct {
	TimeoutMS    int    `json:"timeout_ms"`
	MaxAddresses int    `json:"max_addresses"`
	Resolver     string `json:"resolver"`
}

// LimitsConfig holds the server-side allowlist of user-selectable trace limits
// and the Controller resource controls.
type LimitsConfig struct {
	MaxHops              int `json:"max_hops"`
	MaxQueries           int `json:"max_queries"`
	MinExecutionMS       int `json:"min_execution_ms"`
	MaxExecutionMS       int `json:"max_execution_ms"`
	MaxNodesPerJob       int `json:"max_nodes_per_job"`
	MaxJobsPerMinute     int `json:"max_jobs_per_minute"`
	MaxConcurrentJobs    int `json:"max_concurrent_jobs"`
	MaxConcurrentTraces  int `json:"max_concurrent_traces"`
	MaxResolvesPerMinute int `json:"max_resolves_per_minute"`
	MaxRawResultBytes    int `json:"max_raw_result_bytes"`
	// AllowedProtocols is the Controller-side protocol allowlist. The default
	// is all MVP protocols (icmp, tcp, udp). Duplicates and unknown names are
	// rejected at startup.
	AllowedProtocols []string `json:"allowed_protocols"`
	// MaxHistoryJobs is accepted here as an alias of database.max_history_jobs
	// for convenience; when both are set they must agree.
	MaxHistoryJobs int `json:"max_history_jobs"`
}

// AgentConfig is the administrative description of one Agent. There is no
// user-facing way to add Agents at runtime.
type AgentConfig struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Location         string `json:"location"`
	Provider         string `json:"provider"`
	URL              string `json:"url"`
	TokenEnv         string `json:"token_env"`
	Enabled          *bool  `json:"enabled"`
	RequestTimeoutMS int    `json:"request_timeout_ms"`

	// token is the resolved bearer token. It is never marshaled or logged.
	token string
}

// IsEnabled reports whether the Agent is enabled. Omitting the field enables
// the Agent; administrators must opt out explicitly.
func (a *AgentConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// Token returns the resolved bearer token for this Agent.
func (a *AgentConfig) Token() string { return a.token }

// BaseURL returns the Agent base URL without a trailing slash.
func (a *AgentConfig) BaseURL() string { return strings.TrimRight(a.URL, "/") }

// LoadConfig reads, strictly decodes, defaults and validates a Controller
// configuration document. Secrets referenced by environment variable names are
// resolved here; no secret is ever read from the JSON document.
func LoadConfig(path string) (*Config, error) {
	return loadConfig(path, os.LookupEnv)
}

func loadConfig(path string, lookupEnv func(string) (string, bool)) (*Config, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	limited := io.LimitReader(f, maxConfigBytes+1)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Reject trailing data after the single top-level object.
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse config: trailing data after top-level object")
		}
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.finalize(lookupEnv); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) finalize(lookupEnv func(string) (string, bool)) error {
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("config: listen %q must be host:port", c.Listen)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("config: listen %q uses a wildcard address; bind an explicit IP", c.Listen)
	}
	hostAddr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("config: listen host %q must be a literal IP address", host)
	}
	if hostAddr.IsUnspecified() {
		return fmt.Errorf("config: listen %q uses a wildcard address; bind an explicit IP", c.Listen)
	}
	if n, err := parsePort(port); err != nil || n == 0 {
		return fmt.Errorf("config: listen %q has an invalid port", c.Listen)
	}
	c.Listen = net.JoinHostPort(hostAddr.String(), port)

	// Normalize the auth mode first: public-origin defaults and validation
	// depend on it.
	c.Auth.Mode = strings.ToLower(strings.TrimSpace(c.Auth.Mode))
	if c.Auth.Mode == "" {
		return fmt.Errorf("config: auth.mode is required (cloudflare, local or dev)")
	}
	if c.Auth.Mode != AuthModeCloudflare && c.Auth.Mode != AuthModeLocal && c.Auth.Mode != AuthModeDev {
		return fmt.Errorf("config: auth.mode must be one of cloudflare, local, dev")
	}
	if c.Auth.Mode == AuthModeDev && !hostAddr.IsLoopback() {
		return fmt.Errorf("config: auth.mode=dev is only allowed when listen is a loopback address, got %q", c.Listen)
	}

	if err := c.finalizePublicOrigin(); err != nil {
		return err
	}

	if err := c.finalizeAuth(lookupEnv); err != nil {
		return err
	}
	if err := c.finalizeLimits(); err != nil {
		return err
	}
	if err := c.finalizeDatabase(); err != nil {
		return err
	}
	if err := c.finalizeDNS(); err != nil {
		return err
	}
	if err := c.finalizeTrustedProxies(); err != nil {
		return err
	}
	if err := c.finalizeAgents(lookupEnv); err != nil {
		return err
	}
	if err := c.finalizeSecurity(); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "":
		c.LogLevel = defaultLogLevel
	case "debug", "info", "warn", "error":
		c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	default:
		return fmt.Errorf("config: log_level must be one of debug, info, warn, error")
	}

	return nil
}

// finalizeSecurity builds the shared destination policy from the explicit
// administrator allowlist. Invalid CIDRs (including default routes) are a
// startup error rather than being silently ignored.
func (c *Config) finalizeSecurity() error {
	policy, err := ipguard.NewPolicy(c.Security.AllowedCIDRs)
	if err != nil {
		return fmt.Errorf("config: security.allowed_cidrs: %w", err)
	}
	c.targetPolicy = policy
	return nil
}

// TargetPolicy returns the validated destination policy.
func (c *Config) TargetPolicy() ipguard.Policy { return c.targetPolicy }

func parsePort(port string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(port, "%d", &n); err != nil {
		return 0, err
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port")
	}
	// Reject non-numeric suffixes such as "80abc": Sscanf stops early.
	for _, r := range port {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid port")
		}
	}
	return n, nil
}

func (c *Config) finalizePublicOrigin() error {
	raw := strings.TrimSpace(c.PublicOrigin)
	if raw == "" {
		if c.Auth.Mode == AuthModeDev {
			if _, port, err := net.SplitHostPort(c.Listen); err == nil {
				host, _, _ := net.SplitHostPort(c.Listen)
				c.PublicOrigin = "http://" + net.JoinHostPort(host, port)
			}
		}
		if c.PublicOrigin == "" {
			return fmt.Errorf("config: public_origin is required")
		}
		raw = c.PublicOrigin
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("config: public_origin must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("config: public_origin scheme must be http or https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("config: public_origin must not contain credentials, query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("config: public_origin must not contain a path")
	}
	if scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return fmt.Errorf("config: public_origin must use https unless it is a loopback address")
	}
	normalized := scheme + "://" + strings.ToLower(u.Host)
	c.PublicOrigin = normalized
	parsed, err := url.Parse(normalized)
	if err != nil {
		return fmt.Errorf("config: public_origin is invalid")
	}
	c.publicOrigin = parsed
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

func (c *Config) finalizeAuth(lookupEnv func(string) (string, bool)) error {
	mode := c.Auth.Mode // already normalized and validated in finalize
	c.Auth.Cloudflare.TeamDomain = strings.TrimSpace(c.Auth.Cloudflare.TeamDomain)
	c.Auth.Local.PasswordHashEnv = strings.TrimSpace(c.Auth.Local.PasswordHashEnv)

	switch mode {
	case AuthModeCloudflare:
		if c.Auth.Local.PasswordHashEnv != "" || c.Auth.Local.SessionTTLSeconds != 0 {
			return fmt.Errorf("config: auth.local must be empty when auth.mode=cloudflare")
		}
		return c.finalizeCloudflare(lookupEnv)
	case AuthModeLocal:
		if c.Auth.Cloudflare.TeamDomain != "" || len(c.Auth.Cloudflare.Audience) != 0 ||
			len(c.Auth.Cloudflare.AllowedEmails) != 0 || len(c.Auth.Cloudflare.AllowedEmailDomains) != 0 ||
			c.Auth.Cloudflare.JWKSCacheTTLSeconds != 0 || c.Auth.Cloudflare.CSRFSecretEnv != "" {
			return fmt.Errorf("config: auth.cloudflare must be empty when auth.mode=local")
		}
		return c.finalizeLocal(lookupEnv)
	default:
		if c.Auth.Cloudflare.TeamDomain != "" || len(c.Auth.Cloudflare.Audience) != 0 ||
			len(c.Auth.Cloudflare.AllowedEmails) != 0 || len(c.Auth.Cloudflare.AllowedEmailDomains) != 0 ||
			c.Auth.Cloudflare.JWKSCacheTTLSeconds != 0 || c.Auth.Cloudflare.CSRFSecretEnv != "" {
			return fmt.Errorf("config: auth.cloudflare must be empty when auth.mode=dev")
		}
		if c.Auth.Local.PasswordHashEnv != "" || c.Auth.Local.SessionTTLSeconds != 0 {
			return fmt.Errorf("config: auth.local must be empty when auth.mode=dev")
		}
		return nil
	}
}

func (c *Config) finalizeCloudflare(lookupEnv func(string) (string, bool)) error {
	cf := &c.Auth.Cloudflare
	if cf.TeamDomain == "" {
		return fmt.Errorf("config: auth.cloudflare.team_domain is required")
	}
	u, err := url.Parse(cf.TeamDomain)
	if err != nil || u.Host == "" {
		return fmt.Errorf("config: auth.cloudflare.team_domain must be an absolute URL")
	}
	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf("config: auth.cloudflare.team_domain must use https")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("config: auth.cloudflare.team_domain must not contain credentials, path, query or fragment")
	}
	if err := validateHostname(u.Hostname()); err != nil {
		return fmt.Errorf("config: auth.cloudflare.team_domain host is invalid")
	}
	cf.TeamDomain = "https://" + strings.ToLower(u.Host)

	if len(cf.Audience) == 0 {
		return fmt.Errorf("config: auth.cloudflare.audience must contain at least one audience tag")
	}
	for i, aud := range cf.Audience {
		aud = strings.TrimSpace(aud)
		if aud == "" || len(aud) > 512 || hasControlRune(aud) {
			return fmt.Errorf("config: auth.cloudflare.audience[%d] is invalid", i)
		}
		cf.Audience[i] = aud
	}
	for i, email := range cf.AllowedEmails {
		email = strings.ToLower(strings.TrimSpace(email))
		if !validEmail(email) {
			return fmt.Errorf("config: auth.cloudflare.allowed_emails[%d] is invalid", i)
		}
		cf.AllowedEmails[i] = email
	}
	for i, domain := range cf.AllowedEmailDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if err := validateHostname(domain); err != nil || strings.Contains(domain, "@") {
			return fmt.Errorf("config: auth.cloudflare.allowed_email_domains[%d] is invalid", i)
		}
		cf.AllowedEmailDomains[i] = domain
	}
	if cf.JWKSCacheTTLSeconds == 0 {
		cf.JWKSCacheTTLSeconds = defaultCFJWKSCacheTTL
	}
	if cf.JWKSCacheTTLSeconds < 30 || cf.JWKSCacheTTLSeconds > 86_400 {
		return fmt.Errorf("config: auth.cloudflare.jwks_cache_ttl_seconds must be between 30 and 86400")
	}
	if cf.CSRFSecretEnv != "" {
		secret, ok := lookupEnv(cf.CSRFSecretEnv)
		if !ok || len(secret) < 16 {
			return fmt.Errorf("config: auth.cloudflare.csrf_secret_env %q must name an environment variable with at least 16 bytes", cf.CSRFSecretEnv)
		}
		cf.csrfSecret = []byte(secret)
	}
	return nil
}

func (c *Config) finalizeLocal(lookupEnv func(string) (string, bool)) error {
	local := &c.Auth.Local
	if local.PasswordHashEnv == "" {
		return fmt.Errorf("config: auth.local.password_hash_env is required")
	}
	hash, ok := lookupEnv(local.PasswordHashEnv)
	if !ok || strings.TrimSpace(hash) == "" {
		return fmt.Errorf("config: auth.local.password_hash_env %q is not set", local.PasswordHashEnv)
	}
	if err := ValidatePasswordHash(strings.TrimSpace(hash)); err != nil {
		return fmt.Errorf("config: auth.local.password_hash_env %q does not contain a valid PBKDF2 hash", local.PasswordHashEnv)
	}
	local.passwordHash = strings.TrimSpace(hash)
	if local.SessionTTLSeconds == 0 {
		local.SessionTTLSeconds = defaultLocalSessionTTL
	}
	if local.SessionTTLSeconds < 60 || local.SessionTTLSeconds > 2_592_000 {
		return fmt.Errorf("config: auth.local.session_ttl_seconds must be between 60 and 2592000")
	}
	return nil
}

func (c *Config) finalizeLimits() error {
	l := &c.Limits
	// max_history_jobs is accepted in both database and limits for convenience.
	if l.MaxHistoryJobs != 0 && c.Database.MaxHistoryJobs != 0 && l.MaxHistoryJobs != c.Database.MaxHistoryJobs {
		return fmt.Errorf("config: limits.max_history_jobs and database.max_history_jobs must agree")
	}
	if c.Database.MaxHistoryJobs == 0 {
		c.Database.MaxHistoryJobs = l.MaxHistoryJobs
	}
	if c.Database.MaxHistoryJobs == 0 {
		c.Database.MaxHistoryJobs = defaultMaxHistoryJobs
	}
	l.MaxHistoryJobs = c.Database.MaxHistoryJobs

	if l.MaxHops == 0 {
		l.MaxHops = defaultMaxHops
	}
	if l.MaxHops < model.MinMaxHops || l.MaxHops > model.MaxMaxHops {
		return fmt.Errorf("config: limits.max_hops must be between %d and %d", model.MinMaxHops, model.MaxMaxHops)
	}
	if l.MaxQueries == 0 {
		l.MaxQueries = defaultMaxQueries
	}
	if l.MaxQueries < model.MinQueries || l.MaxQueries > model.MaxQueries {
		return fmt.Errorf("config: limits.max_queries must be between %d and %d", model.MinQueries, model.MaxQueries)
	}
	if l.MinExecutionMS == 0 {
		l.MinExecutionMS = defaultMinExecutionMS
	}
	if l.MaxExecutionMS == 0 {
		l.MaxExecutionMS = defaultMaxExecutionMS
	}
	if l.MinExecutionMS < model.MinExecutionTimeoutMS || l.MinExecutionMS > model.MaxExecutionTimeoutMS {
		return fmt.Errorf("config: limits.min_execution_ms must be between %d and %d", model.MinExecutionTimeoutMS, model.MaxExecutionTimeoutMS)
	}
	if l.MaxExecutionMS < l.MinExecutionMS || l.MaxExecutionMS > model.MaxExecutionTimeoutMS {
		return fmt.Errorf("config: limits.max_execution_ms must be between limits.min_execution_ms and %d", model.MaxExecutionTimeoutMS)
	}
	if l.MaxNodesPerJob == 0 {
		l.MaxNodesPerJob = defaultMaxNodesPerJob
	}
	if l.MaxNodesPerJob < 1 || l.MaxNodesPerJob > model.MaxBatchNodes {
		return fmt.Errorf("config: limits.max_nodes_per_job must be between 1 and %d", model.MaxBatchNodes)
	}
	if l.MaxJobsPerMinute == 0 {
		l.MaxJobsPerMinute = defaultMaxJobsPerMinute
	}
	if l.MaxJobsPerMinute < 1 || l.MaxJobsPerMinute > 10_000 {
		return fmt.Errorf("config: limits.max_jobs_per_minute must be between 1 and 10000")
	}
	if l.MaxConcurrentJobs == 0 {
		l.MaxConcurrentJobs = defaultMaxConcurrent
	}
	if l.MaxConcurrentJobs < 1 || l.MaxConcurrentJobs > 256 {
		return fmt.Errorf("config: limits.max_concurrent_jobs must be between 1 and 256")
	}
	if l.MaxConcurrentTraces == 0 {
		l.MaxConcurrentTraces = defaultMaxConcurrent
	}
	if l.MaxConcurrentTraces < 1 || l.MaxConcurrentTraces > 256 {
		return fmt.Errorf("config: limits.max_concurrent_traces must be between 1 and 256")
	}
	if l.MaxResolvesPerMinute == 0 {
		l.MaxResolvesPerMinute = defaultMaxResolves
	}
	if l.MaxResolvesPerMinute < 1 || l.MaxResolvesPerMinute > 10_000 {
		return fmt.Errorf("config: limits.max_resolves_per_minute must be between 1 and 10000")
	}
	if l.MaxRawResultBytes == 0 {
		l.MaxRawResultBytes = defaultMaxRawResultSize
	}
	if l.MaxRawResultBytes < 0 || l.MaxRawResultBytes > 16<<20 {
		return fmt.Errorf("config: limits.max_raw_result_bytes must be between 0 and 16777216")
	}
	if l.AllowedProtocols == nil {
		// Absent means "all MVP protocols"; an explicitly empty list is a
		// configuration error surfaced by ParseProtocolList.
		l.AllowedProtocols = []string{
			string(model.ProtocolICMP),
			string(model.ProtocolTCP),
			string(model.ProtocolUDP),
		}
	}
	protocols, err := model.ParseProtocolList(l.AllowedProtocols)
	if err != nil {
		return fmt.Errorf("config: limits.allowed_protocols: %v", err)
	}
	c.allowedProtocols = protocols
	l.AllowedProtocols = model.ProtocolNames(protocols)
	return nil
}

func (c *Config) finalizeDatabase() error {
	c.Database.Path = strings.TrimSpace(c.Database.Path)
	if c.Database.Path == "" {
		return fmt.Errorf("config: database.path is required")
	}
	if c.Database.MaxHistoryJobs < 1 || c.Database.MaxHistoryJobs > 10_000 {
		return fmt.Errorf("config: database.max_history_jobs must be between 1 and 10000")
	}
	return nil
}

func (c *Config) finalizeDNS() error {
	if c.DNS.TimeoutMS == 0 {
		c.DNS.TimeoutMS = defaultDNSTimeoutMS
	}
	if c.DNS.TimeoutMS < 100 || c.DNS.TimeoutMS > 10_000 {
		return fmt.Errorf("config: dns.timeout_ms must be between 100 and 10000")
	}
	if c.DNS.MaxAddresses == 0 {
		c.DNS.MaxAddresses = defaultDNSMaxAddresses
	}
	if c.DNS.MaxAddresses < 1 || c.DNS.MaxAddresses > 32 {
		return fmt.Errorf("config: dns.max_addresses must be between 1 and 32")
	}
	c.DNS.Resolver = strings.TrimSpace(c.DNS.Resolver)
	if c.DNS.Resolver != "" {
		host, port, err := net.SplitHostPort(c.DNS.Resolver)
		if err != nil {
			return fmt.Errorf("config: dns.resolver must be host:port")
		}
		host = strings.TrimSpace(host)
		if host == "" {
			return fmt.Errorf("config: dns.resolver host is required")
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if addr.Zone() != "" || addr.IsUnspecified() {
				return fmt.Errorf("config: dns.resolver address is invalid")
			}
			c.DNS.Resolver = net.JoinHostPort(addr.String(), port)
		} else if err := validateHostname(strings.ToLower(host)); err != nil {
			return fmt.Errorf("config: dns.resolver host is invalid")
		} else {
			c.DNS.Resolver = net.JoinHostPort(strings.ToLower(host), port)
		}
		if n, err := parsePort(port); err != nil || n == 0 {
			return fmt.Errorf("config: dns.resolver port is invalid")
		}
	}
	return nil
}

func (c *Config) finalizeTrustedProxies() error {
	c.trustedPrefix = c.trustedPrefix[:0]
	for i, raw := range c.TrustedProxies {
		raw = strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("config: trusted_proxies[%d] is not a CIDR", i)
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("config: trusted_proxies[%d] must not be a default route", i)
		}
		c.trustedPrefix = append(c.trustedPrefix, prefix.Masked())
	}
	return nil
}

func (c *Config) finalizeAgents(lookupEnv func(string) (string, bool)) error {
	if len(c.Agents) == 0 {
		return fmt.Errorf("config: at least one agents[] entry is required")
	}
	if len(c.Agents) > model.MaxBatchNodes {
		return fmt.Errorf("config: at most %d agents may be configured", model.MaxBatchNodes)
	}
	seen := make(map[string]struct{}, len(c.Agents))
	for i := range c.Agents {
		a := &c.Agents[i]
		a.ID = strings.TrimSpace(a.ID)
		if err := model.ValidateNodeID(a.ID); err != nil {
			return fmt.Errorf("config: agents[%d].id is invalid: must match %s", i, "^[a-z0-9][a-z0-9_-]{0,31}$")
		}
		if _, dup := seen[a.ID]; dup {
			return fmt.Errorf("config: duplicate agent id %q", a.ID)
		}
		seen[a.ID] = struct{}{}

		a.Name = model.SanitizeText(a.Name, 64)
		if a.Name == "" {
			return fmt.Errorf("config: agents[%d].name is required", i)
		}
		a.Location = model.SanitizeText(a.Location, 128)
		a.Provider = model.SanitizeText(a.Provider, 128)

		if err := validateAgentURL(a.URL); err != nil {
			return fmt.Errorf("config: agents[%d].url %v", i, err)
		}

		a.TokenEnv = strings.TrimSpace(a.TokenEnv)
		if a.TokenEnv == "" {
			return fmt.Errorf("config: agents[%d].token_env is required", i)
		}
		token, ok := lookupEnv(a.TokenEnv)
		if !ok || strings.TrimSpace(token) == "" {
			return fmt.Errorf("config: agents[%d].token_env %q is not set", i, a.TokenEnv)
		}
		if strings.ContainsAny(token, "\r\n\x00") || len(token) > 4096 {
			return fmt.Errorf("config: agents[%d].token_env %q contains an invalid token value", i, a.TokenEnv)
		}
		a.token = token

		if a.RequestTimeoutMS == 0 {
			a.RequestTimeoutMS = c.Limits.MaxExecutionMS + 15_000
		}
		if a.RequestTimeoutMS < c.Limits.MaxExecutionMS+5_000 || a.RequestTimeoutMS > 600_000 {
			return fmt.Errorf("config: agents[%d].request_timeout_ms must be between limits.max_execution_ms+5000 and 600000", i)
		}
	}
	enabled := 0
	for i := range c.Agents {
		if c.Agents[i].IsEnabled() {
			enabled++
		}
	}
	if enabled == 0 {
		return fmt.Errorf("config: at least one agent must be enabled")
	}
	return nil
}

// validateAgentURL enforces the Controller->Agent transport rules: only http
// or https, no credentials/query/fragment/path, and cleartext http only for
// non-public (loopback, private, CGNAT/Tailscale) literal IP addresses. Hostnames
// always require https because their policy classification needs DNS.
func validateAgentURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("must be an absolute URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("must use http or https")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("must not contain a path")
	}
	if port := u.Port(); port != "" {
		if n, err := parsePort(port); err != nil || n == 0 {
			return fmt.Errorf("has an invalid port")
		}
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return fmt.Errorf("must not contain a zone identifier")
		}
		if scheme == "http" && !ipguard.IsNonPublic(addr.Unmap()) {
			return fmt.Errorf("cannot use cleartext http to a public IP address; use https")
		}
		return nil
	}
	if scheme == "http" {
		return fmt.Errorf("cannot use cleartext http to a hostname; use https")
	}
	if err := validateHostname(strings.ToLower(host)); err != nil {
		return err
	}
	return nil
}

// validateHostname checks an ASCII DNS hostname (no trailing dot, no IDN).
func validateHostname(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("hostname is empty")
	}
	if strings.HasSuffix(host, ".") {
		return fmt.Errorf("hostname must not end with a dot")
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname is too long")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("hostname has an invalid label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return fmt.Errorf("hostname label must not start or end with a hyphen")
				}
			default:
				return fmt.Errorf("hostname contains an invalid character")
			}
		}
	}
	return nil
}

func validEmail(email string) bool {
	if len(email) < 3 || len(email) > 254 || hasControlRune(email) {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	local := email[:at]
	if local == "" || strings.ContainsAny(local, " \t\r\n") {
		return false
	}
	return validateHostname(email[at+1:]) == nil
}

func hasControlRune(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0xFFFD {
			return true
		}
	}
	return false
}

// IsHTTPS reports whether the configured public origin uses https. It drives
// the Secure attribute of the session cookie.
func (c *Config) IsHTTPS() bool { return c.publicOrigin != nil && c.publicOrigin.Scheme == "https" }

// PublicOriginURL returns the parsed public origin.
func (c *Config) PublicOriginURL() *url.URL {
	if c.publicOrigin == nil {
		u, _ := url.Parse(c.PublicOrigin)
		return u
	}
	return c.publicOrigin
}

// TrustedProxyPrefixes returns the parsed trusted-proxy CIDRs.
func (c *Config) TrustedProxyPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(c.trustedPrefix))
	copy(out, c.trustedPrefix)
	return out
}

// SessionLimits projects the configured limits into the session response the
// frontend renders. The frontend never hardcodes these values.
func (c *Config) SessionLimits() model.ControllerLimits {
	return model.ControllerLimits{
		MaxHops:        c.Limits.MaxHops,
		MaxQueries:     c.Limits.MaxQueries,
		MaxExecutionMS: c.Limits.MaxExecutionMS,
		MinExecutionMS: c.Limits.MinExecutionMS,
		MaxNodesPerJob: c.Limits.MaxNodesPerJob,
		MaxAddresses:   c.DNS.MaxAddresses,
		MaxHistoryJobs: c.Database.MaxHistoryJobs,
		Protocols:      model.ProtocolNames(c.allowedProtocols),
	}
}

// AllowedProtocols returns the validated Controller protocol allowlist.
func (c *Config) AllowedProtocols() []model.Protocol {
	out := make([]model.Protocol, len(c.allowedProtocols))
	copy(out, c.allowedProtocols)
	return out
}

// IsProtocolAllowed reports whether p is enabled by the Controller config.
func (c *Config) IsProtocolAllowed(p model.Protocol) bool {
	for _, allowed := range c.allowedProtocols {
		if allowed == p {
			return true
		}
	}
	return false
}

// Warnings returns static, non-sensitive warnings the UI shows in the session
// response.
func (c *Config) Warnings() []string {
	var out []string
	if c.Auth.Mode == AuthModeDev {
		out = append(out, "dev authentication bypass is enabled; never expose this Controller to untrusted networks")
	}
	return out
}

// EffectiveAgentTimeout returns the per-node dispatch timeout for a requested
// trace timeout: the requested duration plus a margin, capped by the Agent's
// configured request timeout. Agent health is validated before this is used.
func (c *Config) EffectiveAgentTimeout(a *AgentConfig, requestedMS int) int {
	ms := requestedMS + dispatchTimeoutMargin
	if a.RequestTimeoutMS > 0 && ms > a.RequestTimeoutMS {
		ms = a.RequestTimeoutMS
	}
	if ms < requestedMS {
		ms = requestedMS
	}
	return ms
}

// AgentByID returns the configured Agent with the given node id.
func (c *Config) AgentByID(id string) (*AgentConfig, bool) {
	for i := range c.Agents {
		if c.Agents[i].ID == id {
			return &c.Agents[i], true
		}
	}
	return nil, false
}
