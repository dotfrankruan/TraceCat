package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	testToken              = "test-agent-token-0123456789"
	testTokenEnv           = "TRACECAT_TEST_AGENT_TOKEN"
	testEnrollmentTokenEnv = "TRACECAT_TEST_ENROLLMENT_TOKEN"
	testEnrollmentSecret   = "test-enrollment-secret-0123456789abcdef"
)

var (
	fakeBuildOnce sync.Once
	fakeBuildPath string
	fakeBuildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeBuildPath != "" {
		_ = os.RemoveAll(filepath.Dir(fakeBuildPath))
	}
	os.Exit(code)
}

func buildFakeNexttrace(t *testing.T) string {
	t.Helper()
	fakeBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tracecat-agent-fake-*")
		if err != nil {
			fakeBuildErr = err
			return
		}
		out := filepath.Join(dir, "fake-nexttrace")
		cmd := exec.Command("go", "build", "-o", out, "../nexttrace/testdata/fake")
		if output, err := cmd.CombinedOutput(); err != nil {
			fakeBuildErr = fmt.Errorf("go build fake nexttrace: %v: %s", err, output)
			return
		}
		fakeBuildPath = out
	})
	if fakeBuildErr != nil {
		t.Fatalf("building fake nexttrace: %v", fakeBuildErr)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "fake-nexttrace")
	data, err := os.ReadFile(fakeBuildPath)
	if err != nil {
		t.Fatalf("reading fake binary: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatalf("writing fake binary: %v", err)
	}
	return dst
}

type fakeControl struct {
	Version          string `json:"version"`
	VersionExit      int    `json:"version_exit"`
	Help             string `json:"help"`
	HelpExit         int    `json:"help_exit"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	Exit             int    `json:"exit"`
	DelayMS          int    `json:"delay_ms"`
	LargeOutputBytes int64  `json:"large_output_bytes"`
	SpawnChild       bool   `json:"spawn_child"`
}

func newFakeNexttrace(t *testing.T, ctrl fakeControl) string {
	t.Helper()
	path := buildFakeNexttrace(t)
	data, err := json.Marshal(ctrl)
	if err != nil {
		t.Fatalf("marshalling fake control: %v", err)
	}
	if err := os.WriteFile(path+".json", data, 0o600); err != nil {
		t.Fatalf("writing fake control: %v", err)
	}
	return path
}

func testConfig(fake string) Config {
	return Config{
		NodeID:    "tokyo-1",
		Name:      "Tokyo",
		Listen:    "127.0.0.1:9481",
		Auth:      AuthConfig{TokenEnv: testTokenEnv},
		NextTrace: NextTraceConfig{Binary: fake},
		Security:  SecurityConfig{},
	}
}

func newTestAgent(t *testing.T, ctrl fakeControl) (*Agent, string) {
	t.Helper()
	return newTestAgentWithConfig(t, ctrl, nil)
}

func newTestAgentWithConfig(t *testing.T, ctrl fakeControl, mutate func(*Config), opts ...Option) (*Agent, string) {
	t.Helper()
	fake := newFakeNexttrace(t, ctrl)
	t.Setenv(testTokenEnv, testToken)
	cfg := testConfig(fake)
	if mutate != nil {
		mutate(&cfg)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, err := New(cfg, logger, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(agent.Close)
	return agent, fake
}

const testJobID = "8f0c2a1b4d5e6f708192a3b4c5d6e7f8"

// icmpOnlyHelp models an older NextTrace build without TCP/UDP/port flags.
const icmpOnlyHelp = `Usage:
  nexttrace [flags] <target>

Flags:
  -4, --ipv4              only use IPv4
  -6, --ipv6              only use IPv6
  -j, --json              output JSON
  -m, --max-hops int      maximum hops (default 30)
  -q, --queries int       number of probes per hop (default 3)
      --timeout int       probe timeout in milliseconds (default 1000)
`

// unusableHelp lacks --json so the binary cannot be used at all.
const unusableHelp = `Flags:
  -4
  -6
  -m, --max-hops int
  -q, --queries int
`

const successTraceJSON = `{
  "Hops": [
    [
      {"TTL":1,"Success":true,"Address":{"IP":"10.200.0.1"},"Rtt":2000000},
      {"TTL":1,"Success":false,"Rtt":0,"Error":null}
    ],
    [
      {"TTL":2,"Success":true,"Address":{"IP":"1.1.1.1","Domain":"one.one.one.one"},"Rtt":41000000,
       "Geo":{"country_en":"Australia","country":"澳大利亚","asnumber":"AS13335","organization":"Cloudflare","isp":"Cloudflare","prefix":"1.1.1.0/24","lat":-33.49,"lng":151.0}}
    ]
  ],
  "TraceMapUrl": "https://example.invalid/trace"
}`

func traceRequestJSON(overrides map[string]any) []byte {
	body := map[string]any{
		"schema_version": model.AgentSchemaVersion,
		"job_id":         testJobID,
		"node_id":        "tokyo-1",
		"target_ip":      "1.1.1.1",
		"family":         "ipv4",
		"protocol":       "icmp",
		"max_hops":       30,
		"queries":        3,
		"timeout_ms":     60000,
	}
	for key, value := range overrides {
		if value == nil {
			delete(body, key)
			continue
		}
		body[key] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return encoded
}

type requestOptions struct {
	token       *string
	contentType *string
	remoteAddr  *string
}

func doRequest(t *testing.T, handler http.Handler, method, path string, body []byte, opts requestOptions) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	token := testToken
	if opts.token != nil {
		token = *opts.token
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		contentType := "application/json"
		if opts.contentType != nil {
			contentType = *opts.contentType
		}
		req.Header.Set("Content-Type", contentType)
	}
	if opts.remoteAddr != nil {
		req.RemoteAddr = *opts.remoteAddr
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) model.ErrorResponse {
	t.Helper()
	var envelope model.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decoding error response %q: %v", rec.Body.String(), err)
	}
	if envelope.Error == nil {
		t.Fatalf("response %q has no error envelope", rec.Body.String())
	}
	return envelope
}

func decodeTraceResponse(t *testing.T, rec *httptest.ResponseRecorder) model.AgentTraceResponse {
	t.Helper()
	var response model.AgentTraceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding trace response %q: %v", rec.Body.String(), err)
	}
	return response
}

func waitForFileAgent(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	_ = waitForFileContentsAgent(t, path, timeout)
}

func waitForFileContentsAgent(t *testing.T, path string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
	return ""
}

type fakeRecord struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
	PID  int               `json:"pid"`
}

func readFakeRecord(t *testing.T, fake string) fakeRecord {
	t.Helper()
	data, err := os.ReadFile(fake + ".args")
	if err != nil {
		t.Fatalf("reading fake args: %v", err)
	}
	var record fakeRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decoding fake args: %v", err)
	}
	return record
}

func readFakeArgs(t *testing.T, fake string) []string {
	t.Helper()
	return readFakeRecord(t, fake).Args
}

func mustParseAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse addr %q: %v", value, err)
	}
	return addr.Unmap()
}

func containsString(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

func hasControlChars(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// staticInterfaceLister returns a fixed interface set for tests.
func staticInterfaceLister(names ...string) InterfaceLister {
	snapshot := append([]string{}, names...)
	return func() ([]string, error) {
		return append([]string{}, snapshot...), nil
	}
}
