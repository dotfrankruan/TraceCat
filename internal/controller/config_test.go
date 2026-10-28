package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testAgentTokenEnv1 = "TRACECAT_TEST_AGENT_TOKEN_1"
	testAgentTokenEnv2 = "TRACECAT_TEST_AGENT_TOKEN_2"
	testAgentToken1    = "test-token-1-abcdefghijklmnop"
	testAgentToken2    = "test-token-2-abcdefghijklmnop"
)

func baseDevConfigDoc() map[string]any {
	return map[string]any{
		"listen":        "127.0.0.1:8080",
		"public_origin": "http://127.0.0.1:8080",
		"auth":          map[string]any{"mode": "dev"},
		"database":      map[string]any{"path": filepath.Join("/tmp", "tracecat-test.db"), "max_history_jobs": 200},
		"dns":           map[string]any{"timeout_ms": 4000, "max_addresses": 16},
		"agents": []any{
			map[string]any{
				"id": "node-one", "name": "Node One", "url": "http://127.0.0.1:8081",
				"token_env": testAgentTokenEnv1, "enabled": true,
			},
			map[string]any{
				"id": "node-two", "name": "Node Two", "url": "http://127.0.0.1:8082",
				"token_env": testAgentTokenEnv2, "enabled": true,
			},
		},
		"trusted_proxies": []any{},
		"log_level":       "debug",
	}
}

func baseCloudflareConfigDoc() map[string]any {
	doc := baseDevConfigDoc()
	doc["public_origin"] = "https://trace.example.com"
	doc["listen"] = "127.0.0.1:8443"
	doc["auth"] = map[string]any{
		"mode": "cloudflare",
		"cloudflare": map[string]any{
			"team_domain":            "https://team.example.cloudflareaccess.com",
			"audience":               []any{"aud-tag-1"},
			"allowed_emails":         []any{"Ops@Example.com"},
			"allowed_email_domains":  []any{"example.com"},
			"jwks_cache_ttl_seconds": 300,
		},
	}
	doc["agents"] = []any{
		map[string]any{
			"id": "node-one", "name": "Node One", "url": "https://100.64.0.10:8443",
			"token_env": testAgentTokenEnv1, "enabled": true,
		},
	}
	return doc
}

func baseLocalConfigDoc(t *testing.T, hash string) map[string]any {
	t.Helper()
	t.Setenv("TRACECAT_TEST_PASSWORD_HASH", hash)
	doc := baseDevConfigDoc()
	doc["auth"] = map[string]any{
		"mode": "local",
		"local": map[string]any{
			"password_hash_env":   "TRACECAT_TEST_PASSWORD_HASH",
			"session_ttl_seconds": 3600,
		},
	}
	return doc
}

func setAgentTokenEnv(t *testing.T) {
	t.Helper()
	t.Setenv(testAgentTokenEnv1, testAgentToken1)
	t.Setenv(testAgentTokenEnv2, testAgentToken2)
}

func writeConfigDoc(t *testing.T, doc any) string {
	t.Helper()
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal config doc: %v", err)
	}
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeRawConfig(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigValidDev(t *testing.T) {
	setAgentTokenEnv(t)
	cfg, err := LoadConfig(writeConfigDoc(t, baseDevConfigDoc()))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.Mode != AuthModeDev {
		t.Fatalf("mode = %q", cfg.Auth.Mode)
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.IsHTTPS() {
		t.Fatalf("expected https=false for loopback origin")
	}
	if cfg.Limits.MaxHops != defaultMaxHops || cfg.DNS.MaxAddresses != 16 {
		t.Fatalf("defaults not applied: %+v %+v", cfg.Limits, cfg.DNS)
	}
	if cfg.Agents[0].Token() != testAgentToken1 {
		t.Fatalf("agent token was not resolved from the environment")
	}
	if got := cfg.Agents[0].RequestTimeoutMS; got != cfg.Limits.MaxExecutionMS+15000 {
		t.Fatalf("default request timeout = %d", got)
	}
	if len(cfg.Warnings()) == 0 {
		t.Fatalf("dev mode should emit a warning")
	}
	if cfg.SessionLimits().MaxHistoryJobs != 200 {
		t.Fatalf("session limits = %+v", cfg.SessionLimits())
	}
}

func TestLoadConfigValidCloudflare(t *testing.T) {
	setAgentTokenEnv(t)
	doc := baseCloudflareConfigDoc()
	path := writeConfigDoc(t, doc)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.Mode != AuthModeCloudflare || !cfg.IsHTTPS() {
		t.Fatalf("unexpected config: %+v", cfg.Auth)
	}
	if cfg.Auth.Cloudflare.AllowedEmails[0] != "ops@example.com" {
		t.Fatalf("allowed emails not normalized: %v", cfg.Auth.Cloudflare.AllowedEmails)
	}
	if cfg.Agents[0].BaseURL() != "https://100.64.0.10:8443" {
		t.Fatalf("base url = %q", cfg.Agents[0].BaseURL())
	}
}

func TestLoadConfigValidLocal(t *testing.T) {
	setAgentTokenEnv(t)
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(writeConfigDoc(t, baseLocalConfigDoc(t, hash)))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.Mode != AuthModeLocal || cfg.Auth.Local.SessionTTLSeconds != 3600 {
		t.Fatalf("unexpected local config: %+v", cfg.Auth.Local)
	}
}

func TestLoadConfigDevPublicOriginDefault(t *testing.T) {
	setAgentTokenEnv(t)
	doc := baseDevConfigDoc()
	delete(doc, "public_origin")
	cfg, err := LoadConfig(writeConfigDoc(t, doc))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.PublicOrigin != "http://127.0.0.1:8080" {
		t.Fatalf("public origin default = %q", cfg.PublicOrigin)
	}
}

func TestLoadConfigRejectsUnknownFieldAndTrailingData(t *testing.T) {
	setAgentTokenEnv(t)
	doc := baseDevConfigDoc()
	doc["bogus_field"] = true
	if _, err := LoadConfig(writeConfigDoc(t, doc)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}

	raw, _ := json.Marshal(baseDevConfigDoc())
	path := writeRawConfig(t, string(raw)+"\n{\"listen\":\"127.0.0.1:1\"}\n")
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

func TestLoadConfigValidationErrors(t *testing.T) {
	hash := func(t *testing.T) string {
		t.Helper()
		h, err := HashPassword("correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
		return h
	}

	cases := []struct {
		name    string
		base    func() map[string]any
		mutate  func(t *testing.T, doc map[string]any)
		wantSub string
	}{
		{
			name: "dev mode non-loopback listener",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["listen"] = "10.1.2.3:8080"
				doc["public_origin"] = "http://10.1.2.3:8080"
			},
			wantSub: "loopback",
		},
		{
			name: "wildcard listen",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["listen"] = "0.0.0.0:8080"
			},
			wantSub: "wildcard",
		},
		{
			name: "empty host listen",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["listen"] = ":8080"
			},
			wantSub: "wildcard",
		},
		{
			name: "hostname listen",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["listen"] = "localhost:8080"
			},
			wantSub: "literal IP",
		},
		{
			name: "http agent to public ip",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["url"] = "http://8.8.8.8:8080"
			},
			wantSub: "cleartext http",
		},
		{
			name: "http agent to hostname",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["url"] = "http://agent.example.com"
			},
			wantSub: "cleartext http to a hostname",
		},
		{
			name: "agent url path",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["url"] = "https://100.64.0.10/v1"
			},
			wantSub: "path",
		},
		{
			name: "agent url credentials",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["url"] = "https://user:pass@100.64.0.10"
			},
			wantSub: "credentials",
		},
		{
			name: "agent url scheme",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["url"] = "ftp://100.64.0.10"
			},
			wantSub: "http or https",
		},
		{
			name: "duplicate node ids",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				agents := doc["agents"].([]any)
				agents[1].(map[string]any)["id"] = "node-one"
			},
			wantSub: "duplicate",
		},
		{
			name: "invalid node id",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["id"] = "Node-One"
			},
			wantSub: "id is invalid",
		},
		{
			name: "missing agent token env",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"].([]any)[0].(map[string]any)["token_env"] = "TRACECAT_TEST_UNSET_TOKEN"
			},
			wantSub: "not set",
		},
		{
			name: "missing agents",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["agents"] = []any{}
			},
			wantSub: "at least one",
		},
		{
			name: "all agents disabled",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				for _, a := range doc["agents"].([]any) {
					a.(map[string]any)["enabled"] = false
				}
			},
			wantSub: "enabled",
		},
		{
			name: "auth mode invalid",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["auth"].(map[string]any)["mode"] = "oauth"
			},
			wantSub: "auth.mode",
		},
		{
			name: "cloudflare missing audience",
			base: baseCloudflareConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["auth"].(map[string]any)["cloudflare"].(map[string]any)["audience"] = []any{}
			},
			wantSub: "audience",
		},
		{
			name: "cloudflare missing team domain",
			base: baseCloudflareConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				delete(doc["auth"].(map[string]any)["cloudflare"].(map[string]any), "team_domain")
			},
			wantSub: "team_domain",
		},
		{
			name: "cloudflare team domain http",
			base: baseCloudflareConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["auth"].(map[string]any)["cloudflare"].(map[string]any)["team_domain"] = "http://team.example"
			},
			wantSub: "https",
		},
		{
			name: "local without password env",
			base: func() map[string]any {
				return baseLocalConfigDoc(t, hash(t))
			},
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["auth"].(map[string]any)["local"].(map[string]any)["password_hash_env"] = "TRACECAT_TEST_UNSET_HASH"
			},
			wantSub: "not set",
		},
		{
			name: "local with malformed hash",
			base: func() map[string]any {
				return baseLocalConfigDoc(t, "not-a-pbkdf2-hash")
			},
			mutate:  func(_ *testing.T, _ map[string]any) {},
			wantSub: "valid PBKDF2",
		},
		{
			name: "cloudflare fields in dev mode",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["auth"].(map[string]any)["cloudflare"] = map[string]any{"team_domain": "https://x.example"}
			},
			wantSub: "must be empty",
		},
		{
			name: "public origin http non-loopback",
			base: func() map[string]any {
				doc := baseCloudflareConfigDoc()
				doc["public_origin"] = "http://trace.example.com"
				return doc
			},
			mutate:  func(_ *testing.T, _ map[string]any) {},
			wantSub: "https",
		},
		{
			name: "public origin with path",
			base: baseCloudflareConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["public_origin"] = "https://trace.example.com/app"
			},
			wantSub: "path",
		},
		{
			name: "unbounded trusted proxy",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["trusted_proxies"] = []any{"0.0.0.0/0"}
			},
			wantSub: "default route",
		},
		{
			name: "invalid trusted proxy",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["trusted_proxies"] = []any{"127.0.0.1"}
			},
			wantSub: "CIDR",
		},
		{
			name: "max hops too large",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["limits"] = map[string]any{"max_hops": 65}
			},
			wantSub: "max_hops",
		},
		{
			name: "max nodes per job too large",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["limits"] = map[string]any{"max_nodes_per_job": 17}
			},
			wantSub: "max_nodes_per_job",
		},
		{
			name: "dns timeout too large",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["dns"].(map[string]any)["timeout_ms"] = 10001
			},
			wantSub: "timeout_ms",
		},
		{
			name: "dns max addresses too large",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["dns"].(map[string]any)["max_addresses"] = 33
			},
			wantSub: "max_addresses",
		},
		{
			name: "history mismatch",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["limits"] = map[string]any{"max_history_jobs": 5}
			},
			wantSub: "must agree",
		},
		{
			name: "log level invalid",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["log_level"] = "verbose"
			},
			wantSub: "log_level",
		},
		{
			name: "request timeout too small for max execution",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["limits"] = map[string]any{"max_execution_ms": 120000}
				doc["agents"].([]any)[0].(map[string]any)["request_timeout_ms"] = 121000
			},
			wantSub: "request_timeout_ms",
		},
		{
			name: "database path missing",
			base: baseDevConfigDoc,
			mutate: func(_ *testing.T, doc map[string]any) {
				doc["database"].(map[string]any)["path"] = ""
			},
			wantSub: "database.path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAgentTokenEnv(t)
			doc := tc.base()
			tc.mutate(t, doc)
			_, err := LoadConfig(writeConfigDoc(t, doc))
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadConfigSecretsNeverInDocument(t *testing.T) {
	setAgentTokenEnv(t)
	doc := baseDevConfigDoc()
	doc["agents"].([]any)[0].(map[string]any)["token"] = testAgentToken1
	if _, err := LoadConfig(writeConfigDoc(t, doc)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("a token must not be accepted in the config document: %v", err)
	}
}

func TestValidateAgentURLRules(t *testing.T) {
	valid := []string{
		"https://agent.example.com",
		"https://agent.example.com:8443",
		"https://100.64.0.10:8443",
		"https://8.8.8.8:8443",
		"http://127.0.0.1:8081",
		"http://10.0.0.5:8081",
		"http://100.64.0.10:8081",
		"http://[fd7a:115c:a1e0::1]:8081",
	}
	for _, raw := range valid {
		if err := validateAgentURL(raw); err != nil {
			t.Fatalf("expected %q to be valid: %v", raw, err)
		}
	}
	invalid := []string{
		"",
		"agent.example.com",
		"https://",
		"https://agent.example.com/path",
		"https://agent.example.com?x=1",
		"https://agent.example.com#frag",
		"https://user:pass@agent.example.com",
		"http://agent.example.com",
		"http://8.8.8.8",
		"http://[2001:4860:4860::8888]",
		"ws://agent.example.com",
		"https://agent.example.com:99999",
	}
	for _, raw := range invalid {
		if err := validateAgentURL(raw); err == nil {
			t.Fatalf("expected %q to be rejected", raw)
		}
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256$210000$") {
		t.Fatalf("unexpected hash format: %q", hash)
	}
	if err := ValidatePasswordHash(hash); err != nil {
		t.Fatalf("ValidatePasswordHash: %v", err)
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword correct = %v, %v", ok, err)
	}
	ok, err = VerifyPassword("wrong password", hash)
	if err != nil || ok {
		t.Fatalf("VerifyPassword wrong = %v, %v", ok, err)
	}
	for _, bad := range []string{
		"",
		"pbkdf2-sha256$210000$onlythree",
		"pbkdf2-sha256$abc$c2FsdA$aGFzaA",
		"pbkdf2-sha256$100$c2FsdA$aGFzaA",
		"scrypt$210000$c2FsdA$aGFzaA",
		"pbkdf2-sha256$210000$!!!$aGFzaA",
	} {
		if _, err := VerifyPassword("x", bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
		if err := ValidatePasswordHash(bad); err == nil {
			t.Fatalf("expected validation error for %q", bad)
		}
	}
}

func TestHashPasswordForCLI(t *testing.T) {
	if _, err := HashPasswordForCLI(strings.NewReader("short")); err == nil {
		t.Fatal("expected short password to be rejected")
	}
	hash, err := HashPasswordForCLI(strings.NewReader("a long enough password\n"))
	if err != nil {
		t.Fatalf("HashPasswordForCLI: %v", err)
	}
	ok, err := VerifyPassword("a long enough password", hash)
	if err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
}

func TestShippedExampleConfigsLoad(t *testing.T) {
	t.Setenv("TRACECAT_AGENT_TOKEN", "local-development-token-0123456789")
	t.Setenv("TRACECAT_AGENT_TOKEN_TOKYO_1", "tokyo-token-0123456789abcdef")
	t.Setenv("TRACECAT_AGENT_TOKEN_FRANKFURT_1", "frankfurt-token-0123456789abcdef")
	t.Setenv("TRACECAT_CSRF_SECRET", "0123456789abcdef0123456789abcdef")

	dev, err := LoadConfig(filepath.Join("..", "..", "configs", "controller.dev.json"))
	if err != nil {
		t.Fatalf("controller.dev.json: %v", err)
	}
	if dev.Auth.Mode != AuthModeDev || len(dev.Agents) != 1 || dev.Agents[0].ID != "local-1" {
		t.Fatalf("unexpected dev config: %+v", dev)
	}
	if dev.Agents[0].BaseURL() != "http://127.0.0.1:9481" || dev.Agents[0].TokenEnv != "TRACECAT_AGENT_TOKEN" {
		t.Fatalf("unexpected dev agent: %+v", dev.Agents[0])
	}

	prod, err := LoadConfig(filepath.Join("..", "..", "configs", "controller.example.json"))
	if err != nil {
		t.Fatalf("controller.example.json: %v", err)
	}
	if prod.Auth.Mode != AuthModeCloudflare || len(prod.Agents) != 2 {
		t.Fatalf("unexpected example config: %+v", prod)
	}
	for _, agent := range prod.Agents {
		if !strings.HasPrefix(agent.URL, "http://100.64.") {
			t.Fatalf("example agent should use tailnet cleartext URL: %q", agent.URL)
		}
	}
	if !prod.IsHTTPS() {
		t.Fatal("example public_origin should be https")
	}
}
