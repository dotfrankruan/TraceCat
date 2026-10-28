// Package agent implements the TraceCat Agent: a small, hardened HTTP service
// that executes the locally installed NextTrace binary for the Controller.
//
// The Agent is deliberately stateless. It accepts only numeric IP targets,
// revalidates every request independently (schema, limits, target policy) and
// is the only component that runs the external NextTrace program.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
	"github.com/dotfrankruan/tracecat/internal/nexttrace"
)

const (
	// DefaultConfigPath is used when -config is not supplied.
	DefaultConfigPath = "/etc/tracecat/agent.json"
	maxConfigBytes    = 1 << 20
	minTokenLength    = 16

	minMaxStdoutBytes int64 = 1 << 10
	maxMaxStdoutBytes int64 = 64 << 20
)

var (
	envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

	allowedGeoProviders = map[string]bool{
		"":           true,
		"ipinfo":     true,
		"ip-api":     true,
		"ipdb":       true,
		"maxmind":    true,
		"cloudflare": true,
		"none":       true,
	}

	// privateTargetRanges are enabled only by the explicit
	// security.allow_private_targets lab switch.
	privateTargetRanges = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
)

// Config is the fully validated Agent runtime configuration.
type Config struct {
	NodeID    string          `json:"node_id"`
	Name      string          `json:"name"`
	Listen    string          `json:"listen"`
	Auth      AuthConfig      `json:"auth"`
	NextTrace NextTraceConfig `json:"nexttrace"`
	Security  SecurityConfig  `json:"security"`
	RateLimit RateLimitConfig `json:"rate_limit"`
	LogLevel  string          `json:"log_level"`
}

// AuthConfig names the environment variable that holds the per-Agent bearer
// token. The token itself is never stored in the configuration file.
type AuthConfig struct {
	TokenEnv string `json:"token_env"`
}

// NextTraceConfig configures execution of the external NextTrace binary.
type NextTraceConfig struct {
	// Binary is a fixed absolute path. Requests can never influence it.
	Binary              string `json:"binary"`
	MaxConcurrentTraces int    `json:"max_concurrent_traces"`
	ProbeTimeoutMS      int    `json:"probe_timeout_ms"`
	MaxExecutionMS      int    `json:"max_execution_ms"`
	MaxStdoutBytes      int64  `json:"max_stdout_bytes"`
	MaxRawBytes         int64  `json:"max_raw_bytes"`
	GeoProvider         string `json:"geo_provider"`
	// AllowedProtocols is the administrator protocol allowlist. The Agent's
	// effective protocols are this list intersected with the installed
	// NextTrace binary's detected capabilities. Nil means the default
	// ["icmp","tcp","udp"]; an explicitly empty list is rejected.
	AllowedProtocols []string `json:"allowed_protocols"`
}

// SecurityConfig is the Agent's local defense-in-depth policy.
type SecurityConfig struct {
	AllowPrivateTargets   bool     `json:"allow_private_targets"`
	AllowedCIDRs          []string `json:"allowed_cidrs"`
	RequireTailscaleBind  bool     `json:"require_tailscale_bind"`
	AllowNonTailscaleBind bool     `json:"allow_non_tailscale_bind"`
}

// RateLimitConfig controls the Agent's token buckets and HTTP concurrency.
type RateLimitConfig struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	Burst             int `json:"burst"`
	MaxConcurrentHTTP int `json:"max_concurrent_http"`
}

// rawConfig mirrors Config for strict decoding. Pointer fields are used where
// a zero value is meaningful (require_tailscale_bind defaults to true).
type rawConfig struct {
	NodeID    string          `json:"node_id"`
	Name      string          `json:"name"`
	Listen    string          `json:"listen"`
	Auth      AuthConfig      `json:"auth"`
	NextTrace NextTraceConfig `json:"nexttrace"`
	Security  struct {
		AllowPrivateTargets   bool     `json:"allow_private_targets"`
		AllowedCIDRs          []string `json:"allowed_cidrs"`
		RequireTailscaleBind  *bool    `json:"require_tailscale_bind"`
		AllowNonTailscaleBind bool     `json:"allow_non_tailscale_bind"`
	} `json:"security"`
	RateLimit RateLimitConfig `json:"rate_limit"`
	LogLevel  string          `json:"log_level"`
}

// Load reads, strictly decodes and validates the Agent configuration file.
// Unknown fields and trailing JSON data are rejected.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("agent config path is empty")
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("opening agent config: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(io.LimitReader(file, maxConfigBytes))
	decoder.DisallowUnknownFields()
	var raw rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parsing agent config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("parsing agent config: trailing data after JSON document")
	}
	return raw.toConfig()
}

func (r rawConfig) toConfig() (Config, error) {
	requireTailscale := true
	if r.Security.RequireTailscaleBind != nil {
		requireTailscale = *r.Security.RequireTailscaleBind
	}
	cfg := Config{
		NodeID:    r.NodeID,
		Name:      r.Name,
		Listen:    r.Listen,
		Auth:      r.Auth,
		NextTrace: r.NextTrace,
		Security: SecurityConfig{
			AllowPrivateTargets:   r.Security.AllowPrivateTargets,
			AllowedCIDRs:          r.Security.AllowedCIDRs,
			RequireTailscaleBind:  requireTailscale,
			AllowNonTailscaleBind: r.Security.AllowNonTailscaleBind,
		},
		RateLimit: r.RateLimit,
		LogLevel:  r.LogLevel,
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyDefaults fills optional settings. It is idempotent and also applied by
// New so programmatically constructed Configs behave the same as loaded ones.
func (c *Config) applyDefaults() {
	if c.Name == "" {
		c.Name = c.NodeID
	}
	if c.NextTrace.MaxConcurrentTraces == 0 {
		c.NextTrace.MaxConcurrentTraces = 4
	}
	if c.NextTrace.ProbeTimeoutMS == 0 {
		c.NextTrace.ProbeTimeoutMS = 1000
	}
	if c.NextTrace.MaxExecutionMS == 0 {
		c.NextTrace.MaxExecutionMS = 60_000
	}
	if c.NextTrace.MaxStdoutBytes == 0 {
		c.NextTrace.MaxStdoutBytes = nexttrace.DefaultMaxStdoutBytes
	}
	if c.NextTrace.MaxRawBytes == 0 {
		c.NextTrace.MaxRawBytes = nexttrace.DefaultMaxRawBytes
	}
	if c.NextTrace.AllowedProtocols == nil {
		c.NextTrace.AllowedProtocols = defaultAllowedProtocols()
	}
	if c.RateLimit.RequestsPerMinute == 0 {
		c.RateLimit.RequestsPerMinute = 60
	}
	if c.RateLimit.Burst == 0 {
		c.RateLimit.Burst = 10
	}
	if c.RateLimit.MaxConcurrentHTTP == 0 {
		c.RateLimit.MaxConcurrentHTTP = 16
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Security.AllowedCIDRs == nil {
		c.Security.AllowedCIDRs = []string{}
	}
}

// Validate enforces every structural, policy and local filesystem constraint.
// It reads the token environment variable only to check its presence and
// minimum length; the value is never retained here or logged.
func (c *Config) Validate() error {
	if err := model.ValidateNodeID(c.NodeID); err != nil {
		return fmt.Errorf("node_id: %s", errorMessage(err))
	}
	if c.Name == "" {
		return errors.New("name is required")
	}
	if sanitized := model.SanitizeText(c.Name, model.MaxLabelRunes); sanitized != c.Name {
		return errors.New("name contains control characters or is too long")
	}
	if _, _, err := parseListen(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if !envNamePattern.MatchString(c.Auth.TokenEnv) {
		return errors.New("auth.token_env must be a valid environment variable name")
	}
	token, ok := os.LookupEnv(c.Auth.TokenEnv)
	if !ok {
		return fmt.Errorf("auth.token_env %q is not set", c.Auth.TokenEnv)
	}
	if len(token) < minTokenLength {
		return fmt.Errorf("auth.token_env %q must contain at least %d characters", c.Auth.TokenEnv, minTokenLength)
	}
	if err := validateBinary(c.NextTrace.Binary); err != nil {
		return err
	}
	if c.NextTrace.MaxConcurrentTraces < 1 || c.NextTrace.MaxConcurrentTraces > 64 {
		return errors.New("nexttrace.max_concurrent_traces must be between 1 and 64")
	}
	if c.NextTrace.ProbeTimeoutMS < 200 || c.NextTrace.ProbeTimeoutMS > 3000 {
		return errors.New("nexttrace.probe_timeout_ms must be between 200 and 3000")
	}
	if c.NextTrace.MaxExecutionMS < model.MinExecutionTimeoutMS || c.NextTrace.MaxExecutionMS > model.MaxExecutionTimeoutMS {
		return fmt.Errorf("nexttrace.max_execution_ms must be between %d and %d",
			model.MinExecutionTimeoutMS, model.MaxExecutionTimeoutMS)
	}
	if c.NextTrace.MaxStdoutBytes < minMaxStdoutBytes || c.NextTrace.MaxStdoutBytes > maxMaxStdoutBytes {
		return fmt.Errorf("nexttrace.max_stdout_bytes must be between %d and %d", minMaxStdoutBytes, maxMaxStdoutBytes)
	}
	if c.NextTrace.MaxRawBytes < 1 || c.NextTrace.MaxRawBytes > c.NextTrace.MaxStdoutBytes {
		return errors.New("nexttrace.max_raw_bytes must be between 1 and max_stdout_bytes")
	}
	if !allowedGeoProviders[strings.ToLower(strings.TrimSpace(c.NextTrace.GeoProvider))] {
		return errors.New("nexttrace.geo_provider is not an allowed provider")
	}
	allowedProtocols := c.NextTrace.AllowedProtocols
	if allowedProtocols == nil {
		allowedProtocols = defaultAllowedProtocols()
	}
	if _, err := model.ParseProtocolList(allowedProtocols); err != nil {
		return fmt.Errorf("nexttrace.allowed_protocols: %s", errorMessage(err))
	}
	if _, err := ipguard.NewPolicy(c.Security.AllowedCIDRs); err != nil {
		return fmt.Errorf("security.allowed_cidrs: %w", err)
	}
	if !c.Security.RequireTailscaleBind && !c.Security.AllowNonTailscaleBind {
		return errors.New("security.require_tailscale_bind=false requires security.allow_non_tailscale_bind=true for an explicit lab configuration")
	}
	addrs, err := interfaceAddrs()
	if err != nil {
		return fmt.Errorf("inspecting local interfaces: %w", err)
	}
	if err := c.validateBindWith(addrs); err != nil {
		return err
	}
	if c.RateLimit.RequestsPerMinute < 1 || c.RateLimit.RequestsPerMinute > 6000 {
		return errors.New("rate_limit.requests_per_minute must be between 1 and 6000")
	}
	if c.RateLimit.Burst < 1 || c.RateLimit.Burst > 1000 {
		return errors.New("rate_limit.burst must be between 1 and 1000")
	}
	if c.RateLimit.MaxConcurrentHTTP < 1 || c.RateLimit.MaxConcurrentHTTP > 1024 {
		return errors.New("rate_limit.max_concurrent_http must be between 1 and 1024")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("log_level must be one of debug, info, warn, error")
	}
	return nil
}

func errorMessage(err error) string {
	var apiErr *model.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Message
	}
	return err.Error()
}

// validateBinary enforces the executable hardening rules for the NextTrace
// path: absolute, an existing regular file, executable and not world-writable.
func validateBinary(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("nexttrace.binary is required")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("nexttrace.binary %q must be an absolute path", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("nexttrace.binary %q does not exist", path)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("nexttrace.binary %q does not exist", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("nexttrace.binary %q is not a regular file", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("nexttrace.binary %q is not executable", path)
	}
	if info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("nexttrace.binary %q must not be world-writable", path)
	}
	return nil
}

// defaultAllowedProtocols is the protocol allowlist used when the operator
// does not configure one.
func defaultAllowedProtocols() []string {
	return []string{
		string(model.ProtocolICMP),
		string(model.ProtocolTCP),
		string(model.ProtocolUDP),
	}
}

// buildPolicy combines the configured CIDR allowlist with the explicit
// allow_private_targets lab switch. The ipguard default deny rules always
// apply otherwise.
func buildPolicy(security SecurityConfig) (ipguard.Policy, error) {
	cidrs := append([]string{}, security.AllowedCIDRs...)
	if security.AllowPrivateTargets {
		cidrs = append(cidrs, privateTargetRanges...)
	}
	return ipguard.NewPolicy(cidrs)
}
