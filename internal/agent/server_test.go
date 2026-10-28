package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func TestHealth(t *testing.T) {
	agent, fake := newTestAgent(t, fakeControl{})

	rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}

	var health model.AgentHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decoding health: %v", err)
	}
	if health.SchemaVersion != model.AgentSchemaVersion {
		t.Fatalf("schema_version = %q", health.SchemaVersion)
	}
	if health.Status != "ok" {
		t.Fatalf("status = %q, want ok", health.Status)
	}
	if health.NodeID != "tokyo-1" {
		t.Fatalf("node_id = %q", health.NodeID)
	}
	if !health.NextTrace.Available || health.NextTrace.Version != "v1.7.1" {
		t.Fatalf("nexttrace = %+v", health.NextTrace)
	}
	for _, capability := range []string{"json", "ipv4", "ipv6", "max_hops", "queries", "timeout", "tcp", "udp", "port", "device"} {
		if !containsString(health.NextTrace.Capabilities, capability) {
			t.Fatalf("capabilities %v missing %q", health.NextTrace.Capabilities, capability)
		}
	}
	if health.Limits.MaxHops != model.MaxMaxHops || health.Limits.MaxQueries != model.MaxQueries {
		t.Fatalf("limits = %+v", health.Limits)
	}
	if health.Limits.MaxConcurrentTraces != 4 || health.Limits.MaxTimeoutMS != 60_000 {
		t.Fatalf("limits = %+v", health.Limits)
	}
	if strings.Join(health.Limits.Protocols, ",") != "icmp,tcp,udp" {
		t.Fatalf("limits.protocols = %v, want [icmp tcp udp]", health.Limits.Protocols)
	}
	if _, err := time.Parse(time.RFC3339Nano, health.Time); err != nil {
		t.Fatalf("time %q is not RFC3339: %v", health.Time, err)
	}

	body := rec.Body.String()
	for _, secret := range []string{fake, testToken, testTokenEnv, "fake-nexttrace"} {
		if strings.Contains(body, secret) {
			t.Fatalf("health leaked %q: %s", secret, body)
		}
	}
}

func TestHealthDegradedWhenNextTraceUnusable(t *testing.T) {
	agent, _ := newTestAgent(t, fakeControl{
		Help: "Flags:\n  -4\n  -6\n  -m, --max-hops int\n  -q, --queries int\n",
	})
	rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var health model.AgentHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decoding health: %v", err)
	}
	if health.Status != "degraded" || health.NextTrace.Available {
		t.Fatalf("health = %+v, want degraded", health)
	}
	if health.NextTrace.Error == nil || health.NextTrace.Error.Code != model.ErrNextTraceMissing {
		t.Fatalf("nexttrace error = %+v", health.NextTrace.Error)
	}
	if len(health.Limits.Protocols) != 0 {
		t.Fatalf("degraded agent reported effective protocols %v, want none", health.Limits.Protocols)
	}
}

func TestAuthentication(t *testing.T) {
	agent, _ := newTestAgent(t, fakeControl{})

	t.Run("missing token", func(t *testing.T) {
		rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{token: strptr("")})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
		envelope := decodeAPIError(t, rec)
		if envelope.Error.Code != model.ErrUnauthorized {
			t.Fatalf("error code = %s", envelope.Error.Code)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{token: strptr("wrong-token-wrong-token")})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("wrong scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
		req.Header.Set("Authorization", "Basic "+testToken)
		rec := httptest.NewRecorder()
		agent.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("trace requires auth", func(t *testing.T) {
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{token: strptr("")})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

func strptr(value string) *string { return &value }

func TestTraceSuccess(t *testing.T) {
	agent, fake := newTestAgent(t, fakeControl{Stdout: successTraceJSON})

	rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var response model.AgentTraceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if response.SchemaVersion != model.AgentSchemaVersion || response.JobID != testJobID || response.NodeID != "tokyo-1" {
		t.Fatalf("identity fields = %+v", response)
	}
	if response.Status != model.NodeCompleted {
		t.Fatalf("status = %s, error = %+v", response.Status, response.Error)
	}
	if response.TargetIP != "1.1.1.1" || response.Family != model.FamilyIPv4 || response.Protocol != model.ProtocolICMP {
		t.Fatalf("target fields = %+v", response)
	}
	if response.NextTraceVersion != "v1.7.1" || response.ParserSchema != model.NextTraceJSONSchema {
		t.Fatalf("version/parser = %q/%q", response.NextTraceVersion, response.ParserSchema)
	}
	if response.Summary.HopCount != 2 || !response.Summary.ReachedDestination {
		t.Fatalf("summary = %+v", response.Summary)
	}
	if response.Summary.Replies != 2 || response.Summary.Probes != 3 {
		t.Fatalf("summary = %+v", response.Summary)
	}
	if response.Summary.DestinationRTTMS == nil || *response.Summary.DestinationRTTMS != 41 {
		t.Fatalf("destination rtt = %v", response.Summary.DestinationRTTMS)
	}
	if len(response.Hops) != 2 {
		t.Fatalf("hops = %d, want 2", len(response.Hops))
	}
	if response.Hops[0].Probes[1].Success || response.Hops[0].Probes[1].ErrorCode != "no_reply" {
		t.Fatalf("failed probe = %+v", response.Hops[0].Probes[1])
	}
	if response.Hops[1].Probes[0].Country != "Australia" {
		t.Fatalf("geo = %+v", response.Hops[1].Probes[0])
	}
	if response.RawResult == nil || len(response.RawResult) == 0 {
		t.Fatal("raw_result is missing")
	}
	if response.DurationMS < 0 {
		t.Fatalf("duration_ms = %d", response.DurationMS)
	}
	if response.StartedAt == "" || response.EndedAt == "" {
		t.Fatalf("timestamps = %q/%q", response.StartedAt, response.EndedAt)
	}

	wantArgs := []string{"-4", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"}
	if got := readFakeArgs(t, fake); strings.Join(got, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("argv = %v, want %v", got, wantArgs)
	}

	body := rec.Body.String()
	if strings.Contains(body, fake) || strings.Contains(body, testToken) {
		t.Fatalf("response leaked internal data: %s", body)
	}
	if strings.Contains(body, `"port"`) {
		t.Fatalf("ICMP response must omit port: %s", body)
	}
	if strings.Contains(body, `"interface"`) {
		t.Fatalf("automatic-routing response must omit interface: %s", body)
	}
}

func TestTraceRejectsInvalidRequests(t *testing.T) {
	// Raise the request budget so this table is not rate limited.
	agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, func(c *Config) {
		c.RateLimit.RequestsPerMinute = 6000
		c.RateLimit.Burst = 1000
	})

	oversized := []byte(`{"schema_version":"` + strings.Repeat("a", 70<<10) + `"}`)

	cases := []struct {
		name        string
		method      string
		path        string
		body        []byte
		opts        requestOptions
		wantStatus  int
		wantCode    model.ErrorCode
		wantHeaders map[string]string
	}{
		{name: "malformed json", method: http.MethodPost, path: "/v1/trace", body: []byte("{oops"), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "empty body", method: http.MethodPost, path: "/v1/trace", body: []byte{}, wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "unknown field", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"extra": true}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "trailing data", method: http.MethodPost, path: "/v1/trace", body: append(traceRequestJSON(nil), []byte(" {}")...), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "wrong schema", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"schema_version": "tracecat.agent.v2"}), wantStatus: 400, wantCode: model.ErrUnsupportedVersion},
		{name: "node mismatch", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"node_id": "other-1"}), wantStatus: 403, wantCode: model.ErrForbidden},
		{name: "family mismatch", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"family": "ipv6"}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "invalid protocol", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"protocol": "sctp"}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "tcp missing port", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"protocol": "tcp"}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "udp missing port", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"protocol": "udp"}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "port on icmp", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"port": 443}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "tcp port zero", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"protocol": "tcp", "port": 0}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "tcp port above max", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"protocol": "tcp", "port": 65536}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "private target", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "10.0.0.1"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "loopback target", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "127.0.0.1"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "cgnat target", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "100.64.0.1"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "documentation target", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "203.0.113.10"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "mapped ipv4 bypass", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "::ffff:1.1.1.1"}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "hostname", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "example.com"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "command injection", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "1.1.1.1; touch /tmp/pwned"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "argument injection", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "--help"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "subshell injection", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "1.1.1.1 $(id)"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "zoned address", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "fe80::1%en0"}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "whitespace target", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"target_ip": "1.1.1.1 "}), wantStatus: 422, wantCode: model.ErrTargetRejected},
		{name: "timeout above local max", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"timeout_ms": 90000}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "timeout out of range", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"timeout_ms": 200000}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "max hops out of range", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"max_hops": 0}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "queries out of range", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(map[string]any{"queries": 6}), wantStatus: 400, wantCode: model.ErrInvalidRequest},
		{name: "bad content type", method: http.MethodPost, path: "/v1/trace", body: traceRequestJSON(nil), opts: requestOptions{contentType: strptr("text/plain")}, wantStatus: 415, wantCode: model.ErrInvalidRequest},
		{name: "oversized body", method: http.MethodPost, path: "/v1/trace", body: oversized, wantStatus: 413, wantCode: model.ErrPayloadTooLarge},
		{name: "wrong method on trace", method: http.MethodGet, path: "/v1/trace", wantStatus: 405, wantCode: model.ErrInvalidRequest, wantHeaders: map[string]string{"Allow": "POST"}},
		{name: "wrong method on health", method: http.MethodPost, path: "/v1/health", wantStatus: 405, wantCode: model.ErrInvalidRequest, wantHeaders: map[string]string{"Allow": "GET"}},
		{name: "unknown path", method: http.MethodGet, path: "/v1/unknown", wantStatus: 404, wantCode: model.ErrNotFound},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := doRequest(t, agent.Handler(), tc.method, tc.path, tc.body, tc.opts)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var envelope model.ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil || envelope.Error == nil {
				t.Fatalf("response is not an error envelope: %s", rec.Body.String())
			}
			if envelope.Error.Code != tc.wantCode {
				t.Fatalf("error code = %s, want %s", envelope.Error.Code, tc.wantCode)
			}
			for header, want := range tc.wantHeaders {
				if got := rec.Header().Get(header); got != want {
					t.Fatalf("%s = %q, want %q", header, got, want)
				}
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Fatalf("X-Content-Type-Options = %q", got)
			}
		})
	}

	if _, err := os.Stat(fake + ".args"); err == nil {
		t.Fatal("nexttrace was executed for a rejected request")
	}
}

func TestTraceNextTraceUnavailable(t *testing.T) {
	agent, fake := newTestAgent(t, fakeControl{
		Help: "Flags:\n  -4\n  -6\n  -m, --max-hops int\n  -q, --queries int\n",
	})
	rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	response := decodeTraceResponse(t, rec)
	if response.Status != model.NodeFailed {
		t.Fatalf("status = %s, want failed", response.Status)
	}
	if response.Error == nil || response.Error.Code != model.ErrNextTraceMissing {
		t.Fatalf("error = %+v, want nexttrace_unavailable", response.Error)
	}
	if _, err := os.Stat(fake + ".args"); err == nil {
		t.Fatal("nexttrace was executed despite being unavailable")
	}
}

func TestTraceFailuresAreHTTP200(t *testing.T) {
	cases := []struct {
		name       string
		control    fakeControl
		mutate     func(*Config)
		wantStatus model.NodeStatus
		wantCode   model.ErrorCode
	}{
		{
			name:       "non-zero exit",
			control:    fakeControl{Exit: 2, Stderr: "SECRET-STDERR"},
			wantStatus: model.NodeFailed,
			wantCode:   model.ErrNextTraceFailed,
		},
		{
			name:       "parse error",
			control:    fakeControl{Stdout: "NextTrace starting..."},
			wantStatus: model.NodeFailed,
			wantCode:   model.ErrParseError,
		},
		{
			name:    "output too large",
			control: fakeControl{LargeOutputBytes: 1 << 20},
			mutate: func(c *Config) {
				c.NextTrace.MaxStdoutBytes = 1024
				c.NextTrace.MaxRawBytes = 512
			},
			wantStatus: model.NodeFailed,
			wantCode:   model.ErrOutputTooLarge,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			agent, _ := newTestAgentWithConfig(t, tc.control, tc.mutate)
			rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			response := decodeTraceResponse(t, rec)
			if response.Status != tc.wantStatus {
				t.Fatalf("status = %s, want %s", response.Status, tc.wantStatus)
			}
			if response.Error == nil || response.Error.Code != tc.wantCode {
				t.Fatalf("error = %+v, want %s", response.Error, tc.wantCode)
			}
			if strings.Contains(rec.Body.String(), "SECRET-STDERR") {
				t.Fatal("response leaked stderr content")
			}
			if response.RawResult != nil {
				t.Fatal("failed trace must not include raw_result")
			}
		})
	}
}

func TestTraceTimeout(t *testing.T) {
	agent, _ := newTestAgentWithConfig(t, fakeControl{
		Stdout:  successTraceJSON,
		DelayMS: 7000,
	}, func(c *Config) {
		c.NextTrace.MaxExecutionMS = 5_000
	})

	start := time.Now()
	rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(map[string]any{"timeout_ms": 5000}), requestOptions{})
	elapsed := time.Since(start)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	response := decodeTraceResponse(t, rec)
	if response.Status != model.NodeTimedOut {
		t.Fatalf("status = %s, want timed_out", response.Status)
	}
	if response.Error == nil || response.Error.Code != model.ErrTimeout {
		t.Fatalf("error = %+v, want timeout", response.Error)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("request took %v, should return promptly after the deadline", elapsed)
	}
}

func TestTraceCancelledByClient(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are POSIX-specific")
	}
	agent, fake := newTestAgentWithConfig(t, fakeControl{
		Stdout:     successTraceJSON,
		DelayMS:    30_000,
		SpawnChild: true,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/trace", strings.NewReader(string(traceRequestJSON(nil))))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		agent.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	waitForFileAgent(t, fake+".args", 3*time.Second)
	waitForFileAgent(t, fake+".child.pid", 3*time.Second)
	record := readFakeRecord(t, fake)
	if record.PID <= 0 {
		t.Fatalf("fake nexttrace did not record its pid: %+v", record)
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return after client cancellation")
	}
	response := decodeTraceResponse(t, rec)
	if response.Status != model.NodeCancelled {
		t.Fatalf("status = %s, want cancelled: %+v", response.Status, response.Error)
	}
	if response.Error == nil || response.Error.Code != model.ErrCancelled {
		t.Fatalf("error = %+v, want cancelled", response.Error)
	}

	// The whole process group must be reaped: both the fake NextTrace parent
	// and the child it spawned must be gone shortly after cancellation.
	childPID := recordChildPID(t, fake)
	assertProcessGone(t, record.PID)
	assertProcessGone(t, childPID)
}

func recordChildPID(t *testing.T, fake string) int {
	t.Helper()
	text := strings.TrimSpace(waitForFileContentsAgent(t, fake+".child.pid", 3*time.Second))
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 0 {
		t.Fatalf("invalid child pid %q", text)
	}
	return pid
}

func assertProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d is still alive after client cancellation", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTraceConcurrencyReturnsBusy(t *testing.T) {
	agent, fake := newTestAgentWithConfig(t, fakeControl{
		Stdout:  successTraceJSON,
		DelayMS: 400,
	}, func(c *Config) {
		c.NextTrace.MaxConcurrentTraces = 1
	})

	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstDone <- doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{})
	}()
	waitForFileAgent(t, fake+".args", 3*time.Second)

	second := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(map[string]any{"job_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}), requestOptions{})
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want 503: %s", second.Code, second.Body.String())
	}
	if envelope := decodeAPIError(t, second); envelope.Error.Code != model.ErrBusy {
		t.Fatalf("second error = %s, want busy", envelope.Error.Code)
	}

	first := <-firstDone
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	if response := decodeTraceResponse(t, first); response.Status != model.NodeCompleted {
		t.Fatalf("first status = %s, want completed", response.Status)
	}
}

func TestRateLimitReturns429(t *testing.T) {
	agent, _ := newTestAgentWithConfig(t, fakeControl{}, func(c *Config) {
		c.RateLimit.RequestsPerMinute = 1
		c.RateLimit.Burst = 1
	})

	first := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	second := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", second.Code)
	}
	if envelope := decodeAPIError(t, second); envelope.Error.Code != model.ErrRateLimited {
		t.Fatalf("error = %s, want rate_limited", envelope.Error.Code)
	}
	retryAfter := second.Header().Get("Retry-After")
	if seconds, err := strconv.Atoi(retryAfter); err != nil || seconds < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", retryAfter)
	}

	// The global bucket also protects against a change of source address.
	third := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{remoteAddr: strptr("198.51.100.9:1234")})
	if third.Code != http.StatusTooManyRequests {
		t.Fatalf("global rate limit did not apply: status = %d", third.Code)
	}
}

func TestResponseHeadersAndMethods(t *testing.T) {
	agent, _ := newTestAgent(t, fakeControl{})

	rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}

	unknown := doRequest(t, agent.Handler(), http.MethodGet, "/does-not-exist", nil, requestOptions{})
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", unknown.Code)
	}
	if envelope := decodeAPIError(t, unknown); envelope.Error.Code != model.ErrNotFound {
		t.Fatalf("unknown path error = %s", envelope.Error.Code)
	}
}

func TestUnauthorizedUnknownPath(t *testing.T) {
	agent, _ := newTestAgent(t, fakeControl{})
	rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/unknown", nil, requestOptions{token: strptr("")})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for unauthenticated unknown path", rec.Code)
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	fake := newFakeNexttrace(t, fakeControl{Stdout: successTraceJSON})
	t.Setenv(testTokenEnv, testToken)

	// Reserve an ephemeral loopback port, then let the Agent bind it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatalf("closing probe listener: %v", err)
	}

	cfg := testConfig(fake)
	cfg.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agent, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- agent.Run(ctx) }()

	url := "http://" + cfg.Listen + "/v1/health"
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		request, err := http.NewRequest(http.MethodGet, url, nil)
		if err == nil {
			request.Header.Set("Authorization", "Bearer "+testToken)
			response, err := client.Do(request)
			if err == nil && response.StatusCode == http.StatusOK {
				_ = response.Body.Close()
				break
			}
			if err == nil {
				_ = response.Body.Close()
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("agent did not become reachable on %s", cfg.Listen)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	if response, err := client.Get(url); err == nil {
		_ = response.Body.Close()
		t.Fatal("listener still accepts connections after shutdown")
	}
}

func TestTraceTCPAndUDP(t *testing.T) {
	cases := []struct {
		name      string
		protocol  string
		port      int
		protoFlag string
	}{
		{name: "tcp syn", protocol: "tcp", port: 443, protoFlag: "-T"},
		{name: "udp", protocol: "udp", port: model.DefaultUDPPort, protoFlag: "-U"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			agent, fake := newTestAgent(t, fakeControl{Stdout: successTraceJSON})

			rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
				traceRequestJSON(map[string]any{"protocol": tc.protocol, "port": tc.port}), requestOptions{})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			response := decodeTraceResponse(t, rec)
			if response.Status != model.NodeCompleted {
				t.Fatalf("status = %s, error = %+v", response.Status, response.Error)
			}
			if response.Protocol != model.Protocol(tc.protocol) {
				t.Fatalf("protocol = %q, want %q", response.Protocol, tc.protocol)
			}
			if response.Port == nil || *response.Port != tc.port {
				t.Fatalf("echoed port = %v, want %d", response.Port, tc.port)
			}
			if !strings.Contains(rec.Body.String(), `"port":`) {
				t.Fatalf("response omits the echoed port: %s", rec.Body.String())
			}

			wantArgs := []string{
				"-4", tc.protoFlag, "--traceroute", "--json",
				"-q", "3", "-m", "30", "--timeout", "1000",
				"-p", strconv.Itoa(tc.port), "1.1.1.1",
			}
			if got := readFakeArgs(t, fake); strings.Join(got, "\x00") != strings.Join(wantArgs, "\x00") {
				t.Fatalf("argv = %v, want %v", got, wantArgs)
			}
		})
	}
}

func TestTraceProtocolAllowlistAndCapabilities(t *testing.T) {
	t.Run("protocol disabled by config", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, func(c *Config) {
			c.NextTrace.AllowedProtocols = []string{"icmp"}
		})
		health := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
		var healthBody model.AgentHealth
		if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
			t.Fatalf("decoding health: %v", err)
		}
		if strings.Join(healthBody.Limits.Protocols, ",") != "icmp" {
			t.Fatalf("effective protocols = %v, want [icmp]", healthBody.Limits.Protocols)
		}

		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"protocol": "tcp", "port": 443}), requestOptions{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if envelope := decodeAPIError(t, rec); envelope.Error.Code != model.ErrInvalidRequest {
			t.Fatalf("error = %s, want invalid_request", envelope.Error.Code)
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed for a config-disabled protocol")
		}

		// ICMP remains usable with the same configuration.
		icmp := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace", traceRequestJSON(nil), requestOptions{})
		if icmp.Code != http.StatusOK {
			t.Fatalf("icmp status = %d, want 200: %s", icmp.Code, icmp.Body.String())
		}
	})

	t.Run("protocol unsupported by binary", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Help: icmpOnlyHelp, Stdout: successTraceJSON}, nil)
		health := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
		var healthBody model.AgentHealth
		if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil {
			t.Fatalf("decoding health: %v", err)
		}
		if strings.Join(healthBody.Limits.Protocols, ",") != "icmp" {
			t.Fatalf("effective protocols = %v, want [icmp]", healthBody.Limits.Protocols)
		}
		for _, capability := range []string{"tcp", "udp", "port"} {
			if containsString(healthBody.NextTrace.Capabilities, capability) {
				t.Fatalf("capabilities %v unexpectedly include %q", healthBody.NextTrace.Capabilities, capability)
			}
		}

		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"protocol": "udp", "port": 33494}), requestOptions{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed for a binary-unsupported protocol")
		}
	})

	t.Run("binary unusable reports terminal failure", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Help: unusableHelp}, nil)
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"protocol": "tcp", "port": 443}), requestOptions{})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		response := decodeTraceResponse(t, rec)
		if response.Status != model.NodeFailed {
			t.Fatalf("status = %s, want failed", response.Status)
		}
		if response.Error == nil || response.Error.Code != model.ErrNextTraceMissing {
			t.Fatalf("error = %+v, want nexttrace_unavailable", response.Error)
		}
		if response.Port == nil || *response.Port != 443 {
			t.Fatalf("failed tcp response should still echo the port: %v", response.Port)
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed despite being unusable")
		}
	})
}

func TestHealthInterfaces(t *testing.T) {
	t.Run("lists sorted and refreshes", func(t *testing.T) {
		names := []string{"eth1", "eth0"}
		lister := func() ([]string, error) {
			return append([]string{}, names...), nil
		}
		agent, _ := newTestAgentWithConfig(t, fakeControl{}, nil, WithInterfaceLister(lister))

		readHealth := func() model.AgentHealth {
			t.Helper()
			rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
			if rec.Code != http.StatusOK {
				t.Fatalf("health status = %d", rec.Code)
			}
			var health model.AgentHealth
			if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
				t.Fatalf("decoding health: %v", err)
			}
			return health
		}

		if got := readHealth().Interfaces; strings.Join(got, ",") != "eth0,eth1" {
			t.Fatalf("health interfaces = %v, want sorted [eth0 eth1]", got)
		}
		names = append(names, "eth2")
		if got := readHealth().Interfaces; strings.Join(got, ",") != "eth0,eth1,eth2" {
			t.Fatalf("refreshed health interfaces = %v, want [eth0 eth1 eth2]", got)
		}
	})

	t.Run("falls back to startup snapshot on refresh failure", func(t *testing.T) {
		fail := false
		lister := func() ([]string, error) {
			if fail {
				return nil, errors.New("enumeration failed")
			}
			return []string{"eth0"}, nil
		}
		agent, _ := newTestAgentWithConfig(t, fakeControl{}, nil, WithInterfaceLister(lister))
		fail = true
		rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
		if rec.Code != http.StatusOK {
			t.Fatalf("health status = %d, want 200", rec.Code)
		}
		var health model.AgentHealth
		if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
			t.Fatalf("decoding health: %v", err)
		}
		if strings.Join(health.Interfaces, ",") != "eth0" {
			t.Fatalf("health interfaces = %v, want startup snapshot [eth0]", health.Interfaces)
		}
	})

	t.Run("empty when device selection unsupported", func(t *testing.T) {
		agent, _ := newTestAgentWithConfig(t, fakeControl{Help: icmpOnlyHelp}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodGet, "/v1/health", nil, requestOptions{})
		var health model.AgentHealth
		if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
			t.Fatalf("decoding health: %v", err)
		}
		if len(health.Interfaces) != 0 {
			t.Fatalf("health interfaces = %v, want empty without -D capability", health.Interfaces)
		}
	})
}

func TestTraceInterfaceSelection(t *testing.T) {
	t.Run("icmp interface echo and argv", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0", "eth1")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"interface": "eth1"}), requestOptions{})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		response := decodeTraceResponse(t, rec)
		if response.Status != model.NodeCompleted || response.Interface != "eth1" {
			t.Fatalf("response = status %s interface %q", response.Status, response.Interface)
		}
		want := []string{"-4", "-D", "eth1", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"}
		if got := readFakeArgs(t, fake); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	})

	t.Run("tcp interface argv", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"protocol": "tcp", "port": 443, "interface": "eth0"}), requestOptions{})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		want := []string{"-4", "-T", "-D", "eth0", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "443", "1.1.1.1"}
		if got := readFakeArgs(t, fake); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	})

	t.Run("ipv6 interface argv", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{
				"target_ip": "2606:4700:4700::1111", "family": "ipv6", "interface": "eth0",
			}), requestOptions{})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		want := []string{"-6", "-D", "eth0", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "2606:4700:4700::1111"}
		if got := readFakeArgs(t, fake); strings.Join(got, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("argv = %v, want %v", got, want)
		}
	})

	t.Run("interface not in enumerated set", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"interface": "eth9"}), requestOptions{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if envelope := decodeAPIError(t, rec); envelope.Error.Code != model.ErrInvalidRequest {
			t.Fatalf("error = %s, want invalid_request", envelope.Error.Code)
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed for an unavailable interface")
		}
	})

	t.Run("malformed interface name rejected before execution", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"interface": "../../etc/passwd"}), requestOptions{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed for a malformed interface name")
		}
	})

	t.Run("device selection unsupported by binary", func(t *testing.T) {
		agent, fake := newTestAgentWithConfig(t, fakeControl{Help: icmpOnlyHelp, Stdout: successTraceJSON}, nil,
			WithInterfaceLister(staticInterfaceLister("eth0")))
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"interface": "eth0"}), requestOptions{})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed without device-selection capability")
		}
	})

	t.Run("interface enumeration failure", func(t *testing.T) {
		fail := false
		lister := func() ([]string, error) {
			if fail {
				return nil, errors.New("enumeration failed")
			}
			return []string{"eth0"}, nil
		}
		agent, fake := newTestAgentWithConfig(t, fakeControl{Stdout: successTraceJSON}, nil,
			WithInterfaceLister(lister))
		fail = true
		rec := doRequest(t, agent.Handler(), http.MethodPost, "/v1/trace",
			traceRequestJSON(map[string]any{"interface": "eth0"}), requestOptions{})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(fake + ".args"); err == nil {
			t.Fatal("nexttrace was executed despite an interface enumeration failure")
		}
	})
}
