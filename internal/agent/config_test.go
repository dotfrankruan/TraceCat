package agent

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func baseConfigMap(fake string) map[string]any {
	return map[string]any{
		"node_id": "tokyo-1",
		"name":    "Tokyo",
		"listen":  "127.0.0.1:9481",
		"auth":    map[string]any{"token_env": testTokenEnv},
		"nexttrace": map[string]any{
			"binary": fake,
		},
		"security": map[string]any{
			"require_tailscale_bind":   false,
			"allow_non_tailscale_bind": true,
		},
	}
}

func writeConfigFile(t *testing.T, value map[string]any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshalling config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func loadConfigWith(t *testing.T, fake string, mutate func(map[string]any)) (Config, error) {
	t.Helper()
	value := baseConfigMap(fake)
	if mutate != nil {
		mutate(value)
	}
	return Load(writeConfigFile(t, value))
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	old, present := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset env: %v", err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(name, old)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func TestLoadValidConfigAppliesDefaults(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	cfg, err := Load(writeConfigFile(t, baseConfigMap(fake)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NodeID != "tokyo-1" || cfg.Name != "Tokyo" {
		t.Fatalf("identity = %q/%q", cfg.NodeID, cfg.Name)
	}
	if cfg.NextTrace.MaxConcurrentTraces != 4 {
		t.Fatalf("max_concurrent_traces = %d, want 4", cfg.NextTrace.MaxConcurrentTraces)
	}
	if cfg.NextTrace.ProbeTimeoutMS != 1000 {
		t.Fatalf("probe_timeout_ms = %d, want 1000", cfg.NextTrace.ProbeTimeoutMS)
	}
	if cfg.NextTrace.MaxExecutionMS != 60_000 {
		t.Fatalf("max_execution_ms = %d, want 60000", cfg.NextTrace.MaxExecutionMS)
	}
	if cfg.NextTrace.MaxStdoutBytes != 4<<20 {
		t.Fatalf("max_stdout_bytes = %d, want 4 MiB", cfg.NextTrace.MaxStdoutBytes)
	}
	if cfg.NextTrace.MaxRawBytes != 1<<20 {
		t.Fatalf("max_raw_bytes = %d, want 1 MiB", cfg.NextTrace.MaxRawBytes)
	}
	if cfg.RateLimit.RequestsPerMinute != 60 || cfg.RateLimit.Burst != 10 || cfg.RateLimit.MaxConcurrentHTTP != 16 {
		t.Fatalf("rate_limit defaults = %+v", cfg.RateLimit)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("log_level = %q, want info", cfg.LogLevel)
	}
	if cfg.Security.RequireTailscaleBind {
		t.Fatal("explicit require_tailscale_bind=false was not honoured")
	}
	if !cfg.Security.AllowNonTailscaleBind {
		t.Fatal("allow_non_tailscale_bind = false, want true")
	}
}

func TestLoadRequiresTailscaleBindByDefault(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)
	value := baseConfigMap(fake)
	value["security"] = map[string]any{} // no bind switches
	_, err := Load(writeConfigFile(t, value))
	if err == nil {
		t.Fatal("Load = nil error; default Tailscale-only binding must reject a loopback listener")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tailscale") {
		t.Fatalf("error %q should mention the Tailscale requirement", err)
	}
}

func TestLoadRejectsUnknownAndTrailingData(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	t.Run("unknown top-level field", func(t *testing.T) {
		_, err := loadConfigWith(t, fake, func(m map[string]any) { m["surprise"] = true })
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("Load error = %v, want unknown field rejection", err)
		}
	})
	t.Run("unknown nested field", func(t *testing.T) {
		_, err := loadConfigWith(t, fake, func(m map[string]any) {
			m["security"] = map[string]any{"require_tailscale_bind": false, "allow_non_tailscale_bind": true, "bogus": 1}
		})
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("Load error = %v, want unknown field rejection", err)
		}
	})
	t.Run("trailing data", func(t *testing.T) {
		data, err := json.Marshal(baseConfigMap(fake))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "agent.json")
		if err := os.WriteFile(path, append(data, []byte("\n{\"extra\":true}")...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "trailing data") {
			t.Fatalf("Load error = %v, want trailing data rejection", err)
		}
	})
}

func TestLoadRejectsBadListenAddresses(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	cases := map[string]string{
		"wildcard ipv4": "0.0.0.0:9481",
		"wildcard ipv6": "[::]:9481",
		"hostname":      "localhost:9481",
		"port zero":     "127.0.0.1:0",
		"missing port":  "127.0.0.1",
		"zone":          "[fe80::1%25en0]:9481",
	}
	for name, listen := range cases {
		listen := listen
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigWith(t, fake, func(m map[string]any) { m["listen"] = listen }); err == nil {
				t.Fatalf("Load(%q) = nil error, want rejection", listen)
			}
		})
	}
}

func TestLoadRequiresEnvToken(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	unsetEnv(t, testTokenEnv)

	if _, err := loadConfigWith(t, fake, nil); err == nil {
		t.Fatal("Load = nil error, want missing token rejection")
	}

	t.Setenv(testTokenEnv, "short")
	if _, err := loadConfigWith(t, fake, nil); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Fatalf("Load error = %v, want minimum length rejection", err)
	}
}

func TestLoadRejectsBadBinaryPath(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	dir := t.TempDir()
	notExecutable := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	worldWritable := filepath.Join(dir, "world-writable")
	if err := os.WriteFile(worldWritable, []byte("#!/bin/true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o777); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "nexttrace-dir")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"relative":            "nexttrace",
		"missing":             filepath.Join(dir, "nope"),
		"not executable":      notExecutable,
		"world writable":      worldWritable,
		"directory":           subdir,
		"empty":               "",
		"valid handled below": fake,
	}
	for name, binary := range cases {
		binary := binary
		if name == "valid handled below" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigWith(t, fake, func(m map[string]any) {
				m["nexttrace"] = map[string]any{"binary": binary}
			}); err == nil {
				t.Fatalf("Load with binary %q = nil error, want rejection", binary)
			}
		})
	}

	if _, err := loadConfigWith(t, fake, func(m map[string]any) {
		m["nexttrace"] = map[string]any{"binary": fake}
	}); err != nil {
		t.Fatalf("Load with valid binary: %v", err)
	}
}

func TestLoadRejectsOutOfRangeSettings(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	cases := map[string]func(map[string]any){
		"invalid node id": func(m map[string]any) { m["node_id"] = "Not Valid" },
		"control in name": func(m map[string]any) { m["name"] = "Tok\nyo" },
		"long name":       func(m map[string]any) { m["name"] = strings.Repeat("n", model.MaxLabelRunes+1) },
		"bad token env name": func(m map[string]any) {
			m["auth"] = map[string]any{"token_env": "bad name"}
		},
		"too many traces": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "max_concurrent_traces": 65}
		},
		"probe timeout too low": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "probe_timeout_ms": 199}
		},
		"probe timeout too high": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "probe_timeout_ms": 3001}
		},
		"execution timeout too low": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "max_execution_ms": 1000}
		},
		"raw larger than stdout": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "max_stdout_bytes": 2048, "max_raw_bytes": 4096}
		},
		"bad geo provider": func(m map[string]any) {
			m["nexttrace"] = map[string]any{"binary": fake, "geo_provider": "evil-provider"}
		},
		"default route allowlist": func(m map[string]any) {
			m["security"] = map[string]any{
				"require_tailscale_bind": false, "allow_non_tailscale_bind": true,
				"allowed_cidrs": []string{"0.0.0.0/0"},
			}
		},
		"require tailscale without lab switch": func(m map[string]any) {
			m["security"] = map[string]any{"require_tailscale_bind": false}
		},
		"bad rate limit": func(m map[string]any) {
			m["rate_limit"] = map[string]any{"requests_per_minute": 7000}
		},
		"bad log level": func(m map[string]any) { m["log_level"] = "verbose" },
	}
	for name, mutate := range cases {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfigWith(t, fake, mutate); err == nil {
				t.Fatalf("Load = nil error, want rejection for %s", name)
			}
		})
	}
}

func TestValidateBindWithInjectedInterfaces(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{})
	t.Setenv(testTokenEnv, testToken)

	loopback := mustParseAddr(t, "127.0.0.1")
	tailscale := mustParseAddr(t, "100.64.0.5")

	cases := []struct {
		name        string
		listen      string
		require     bool
		allowNonTS  bool
		assigned    []netip.Addr
		wantErrPart string
	}{
		{
			name: "assigned loopback in lab mode", listen: "127.0.0.1:9481",
			require: false, allowNonTS: true, assigned: []netip.Addr{loopback},
		},
		{
			name: "tailscale address satisfies requirement", listen: "100.64.0.5:9481",
			require: true, allowNonTS: false, assigned: []netip.Addr{tailscale},
		},
		{
			name: "loopback fails tailscale requirement", listen: "127.0.0.1:9481",
			require: true, allowNonTS: false, assigned: []netip.Addr{loopback},
			wantErrPart: "tailscale",
		},
		{
			name: "unassigned address", listen: "100.100.0.5:9481",
			require: false, allowNonTS: true, assigned: []netip.Addr{loopback},
			wantErrPart: "not assigned",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(fake)
			cfg.Listen = tc.listen
			cfg.Security.RequireTailscaleBind = tc.require
			cfg.Security.AllowNonTailscaleBind = tc.allowNonTS
			err := cfg.validateBindWith(tc.assigned)
			if tc.wantErrPart == "" {
				if err != nil {
					t.Fatalf("validateBindWith: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantErrPart) {
				t.Fatalf("validateBindWith error = %v, want containing %q", err, tc.wantErrPart)
			}
		})
	}
}

func TestParseListenNormalizes(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:9481":           "127.0.0.1",
		"100.64.0.5:9480":          "100.64.0.5",
		"[fd7a:115c:a1e0::1]:9481": "fd7a:115c:a1e0::1",
	}
	for input, want := range cases {
		addr, port, err := parseListen(input)
		if err != nil {
			t.Fatalf("parseListen(%q): %v", input, err)
		}
		if addr.String() != want {
			t.Fatalf("parseListen(%q) addr = %s, want %s", input, addr, want)
		}
		if port == 0 {
			t.Fatalf("parseListen(%q) port = 0", input)
		}
	}
}

func TestBuildPolicyHonoursPrivateTargetsSwitch(t *testing.T) {
	defaultPolicy, err := buildPolicy(SecurityConfig{})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if err := defaultPolicy.CheckAddr(mustParseAddr(t, "10.1.2.3")); err == nil {
		t.Fatal("default policy allowed a private target")
	}
	if err := defaultPolicy.CheckAddr(mustParseAddr(t, "1.1.1.1")); err != nil {
		t.Fatalf("default policy rejected a global target: %v", err)
	}

	privatePolicy, err := buildPolicy(SecurityConfig{AllowPrivateTargets: true})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if err := privatePolicy.CheckAddr(mustParseAddr(t, "10.1.2.3")); err != nil {
		t.Fatalf("allow_private_targets policy rejected a private target: %v", err)
	}
	if err := privatePolicy.CheckAddr(mustParseAddr(t, "127.0.0.1")); err == nil {
		t.Fatal("allow_private_targets must not allow loopback")
	}

	allowlisted, err := buildPolicy(SecurityConfig{AllowedCIDRs: []string{"192.168.50.0/24"}})
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	if err := allowlisted.CheckAddr(mustParseAddr(t, "192.168.50.7")); err != nil {
		t.Fatalf("allowlisted target rejected: %v", err)
	}
}

func TestAgentLimitsAreAdvertised(t *testing.T) {
	agent, _ := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, func(c *Config) {
		c.NextTrace.MaxExecutionMS = 90_000
		c.NextTrace.MaxConcurrentTraces = 2
	})
	limits := agent.Limits()
	if limits.MaxHops != model.MaxMaxHops || limits.MaxQueries != model.MaxQueries {
		t.Fatalf("limits = %+v", limits)
	}
	if limits.MaxTimeoutMS != 90_000 || limits.MaxConcurrentTraces != 2 {
		t.Fatalf("limits = %+v", limits)
	}
}
