package nexttrace

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func testRunnerFlags() Flags {
	return Flags{
		JSON: true, IPv4: true, IPv6: true,
		MaxHopsShort: true, QueriesShort: true, Timeout: true,
	}
}

func TestRunExecutesExactArgv(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture})
	runner := NewRunner(fake, Capabilities{Version: "v1.7.1", Flags: testRunnerFlags()})

	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}

	record := readRecord(t, fake+".args")
	want := []string{"-4", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"}
	if strings.Join(record.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v, want %v", record.Args, want)
	}

	// The child must see only the minimal fixed environment.
	if len(record.Env) != 5 {
		t.Fatalf("child env = %v, want exactly 5 variables", record.Env)
	}
	for _, key := range []string{"PATH", "HOME", "LANG", "LC_ALL", "NO_COLOR"} {
		if _, ok := record.Env[key]; !ok {
			t.Fatalf("child env is missing %s: %v", key, record.Env)
		}
	}

	parsed, parseErr := Parse(result.Stdout, ParseOptions{TargetIP: "1.1.1.1"})
	if parseErr != nil {
		t.Fatalf("Parse of successful run: %v", parseErr)
	}
	if parsed.Summary.HopCount != 2 {
		t.Fatalf("parsed hop count = %d, want 2", parsed.Summary.HopCount)
	}
}

func TestRunExecutesTCPArgv(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture})
	runner := NewRunner(fake, capableCapabilities())

	if _, apiErr := runner.Run(context.Background(), tcpSpec(), 5*time.Second, RunLimits{}); apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	record := readRecord(t, fake+".args")
	want := []string{"-4", "-T", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "443", "1.1.1.1"}
	if strings.Join(record.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v, want %v", record.Args, want)
	}
}

func TestRunDoesNotInheritSecrets(t *testing.T) {
	t.Setenv("TRACECAT_AGENT_TOKEN", "do-not-leak-this-token")
	fake := newFake(t, fakeControl{Stdout: groupedFixture})
	runner := NewRunner(fake, capableCapabilities())

	if _, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{}); apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	record := readRecord(t, fake+".args")
	if _, ok := record.Env["TRACECAT_AGENT_TOKEN"]; ok {
		t.Fatal("child inherited the Agent token environment variable")
	}
}

func TestRunNonZeroExit(t *testing.T) {
	fake := newFake(t, fakeControl{Exit: 3, Stderr: "SECRET-STDERR-CONTENT"})
	runner := NewRunner(fake, capableCapabilities())

	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr == nil {
		t.Fatal("Run = nil error, want nexttrace_failed")
	}
	if apiErr.Code != model.ErrNextTraceFailed {
		t.Fatalf("error code = %s, want nexttrace_failed", apiErr.Code)
	}
	if result.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", result.ExitCode)
	}
	if strings.Contains(apiErr.Message, "SECRET-STDERR-CONTENT") {
		t.Fatal("error message leaks stderr content")
	}
	if strings.Contains(apiErr.Message, fake) {
		t.Fatal("error message leaks the executable path")
	}
}

func TestRunTimesOut(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture, DelayMS: 5000})
	runner := NewRunner(fake, capableCapabilities())

	start := time.Now()
	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 150*time.Millisecond, RunLimits{})
	elapsed := time.Since(start)
	if apiErr == nil {
		t.Fatal("Run = nil error, want timeout")
	}
	if apiErr.Code != model.ErrTimeout {
		t.Fatalf("error code = %s, want timeout", apiErr.Code)
	}
	if !result.TimedOut {
		t.Fatal("result.TimedOut = false, want true")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v, should return promptly after the deadline", elapsed)
	}
}

func TestRunCancellation(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture, DelayMS: 5000})
	runner := NewRunner(fake, capableCapabilities())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	result, apiErr := runner.Run(ctx, ipv4Spec(), 30*time.Second, RunLimits{})
	elapsed := time.Since(start)
	if apiErr == nil {
		t.Fatal("Run = nil error, want cancellation")
	}
	if apiErr.Code != model.ErrCancelled {
		t.Fatalf("error code = %s, want cancelled", apiErr.Code)
	}
	if !result.Cancelled {
		t.Fatal("result.Cancelled = false, want true")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Run took %v, should return promptly after cancellation", elapsed)
	}
}

func TestRunCancellationKillsProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups are POSIX-specific")
	}
	fake := newFake(t, fakeControl{DelayMS: 30_000, SpawnChild: true})
	runner := NewRunner(fake, capableCapabilities())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, apiErr := runner.Run(ctx, ipv4Spec(), 30*time.Second, RunLimits{})
	if apiErr == nil || apiErr.Code != model.ErrCancelled {
		t.Fatalf("Run error = %v, want cancelled", apiErr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run took %v, should return without waiting on the child", elapsed)
	}

	pidText := waitForFile(t, fake+".child.pid", 3*time.Second)
	pid, err := strconv.Atoi(strings.TrimSpace(pidText))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid child pid %q", pidText)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		err := syscall.Kill(pid, 0)
		if err == syscall.ESRCH {
			return // child was killed with the group
		}
		if time.Now().After(deadline) {
			t.Fatalf("spawned child pid %d survived process-group cancellation", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRunOversizedStdout(t *testing.T) {
	fake := newFake(t, fakeControl{LargeOutputBytes: 1 << 20})
	runner := NewRunner(fake, capableCapabilities())

	start := time.Now()
	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 10*time.Second, RunLimits{MaxStdoutBytes: 1024})
	if apiErr == nil {
		t.Fatal("Run = nil error, want output_too_large")
	}
	if apiErr.Code != model.ErrOutputTooLarge {
		t.Fatalf("error code = %s, want output_too_large", apiErr.Code)
	}
	if !result.OutputTooLarge {
		t.Fatal("result.OutputTooLarge = false, want true")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run took %v, should be killed once the limit is exceeded", elapsed)
	}
}

func TestRunAlreadyCanceledContext(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture})
	runner := NewRunner(fake, capableCapabilities())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, apiErr := runner.Run(ctx, ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr == nil || apiErr.Code != model.ErrCancelled {
		t.Fatalf("Run error = %v, want cancelled", apiErr)
	}
}

func TestRunStartFailure(t *testing.T) {
	missing := t.TempDir() + "/not-there"
	runner := NewRunner(missing, capableCapabilities())
	_, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr == nil || apiErr.Code != model.ErrNextTraceFailed {
		t.Fatalf("Run error = %v, want nexttrace_failed", apiErr)
	}
	if strings.Contains(apiErr.Message, missing) {
		t.Fatal("error message leaks the executable path")
	}
}

func TestRunUnavailableCapabilities(t *testing.T) {
	fake := newFake(t, fakeControl{})
	runner := NewRunner(fake, Capabilities{})
	_, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr == nil || apiErr.Code != model.ErrNextTraceMissing {
		t.Fatalf("Run error = %v, want nexttrace_unavailable", apiErr)
	}
}

func TestRunParsesMalformedOutputAsParseError(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: "this is not json"})
	runner := NewRunner(fake, capableCapabilities())
	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	if _, parseErr := Parse(result.Stdout, ParseOptions{TargetIP: "1.1.1.1"}); parseErr == nil {
		t.Fatal("Parse = nil error, want parse_error")
	}
}

func TestBoundedBuffer(t *testing.T) {
	t.Parallel()
	buf := newBoundedBuffer(4)
	var hooked bool
	buf.SetOverflowHook(func() { hooked = true })
	n, err := buf.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("Write = %d, %v; want 8, nil", n, err)
	}
	if !buf.Overflowed() || !hooked {
		t.Fatalf("overflow = %v, hook = %v; want true,true", buf.Overflowed(), hooked)
	}
	if got := string(buf.Bytes()); got != "abcd" {
		t.Fatalf("retained = %q, want abcd", got)
	}
	// Additional writes still report success and do not grow the buffer.
	if n, _ := buf.Write([]byte("zz")); n != 2 {
		t.Fatalf("second Write = %d, want 2", n)
	}
	if len(buf.Bytes()) != 4 {
		t.Fatalf("buffer grew beyond limit: %q", buf.Bytes())
	}
}

func TestParseFixtureRoundTripThroughFake(t *testing.T) {
	fixture, err := json.Marshal(map[string]any{
		"Hops": [][]map[string]any{{
			{"TTL": 1, "Success": true, "Address": map[string]any{"IP": "1.1.1.1"}, "Rtt": 1000000},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := newFake(t, fakeControl{Stdout: string(fixture)})
	runner := NewRunner(fake, capableCapabilities())
	result, apiErr := runner.Run(context.Background(), ipv4Spec(), 5*time.Second, RunLimits{})
	if apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	if len(result.Stdout) == 0 {
		t.Fatal("runner returned empty stdout")
	}
	if _, err := os.Stat(fake + ".args"); err != nil {
		t.Fatalf("fake did not record argv: %v", err)
	}
}

func TestRunExecutesInterfaceArgv(t *testing.T) {
	fake := newFake(t, fakeControl{Stdout: groupedFixture})
	runner := NewRunner(fake, capableCapabilities())

	spec := ipv4Spec()
	spec.Interface = "eth0"
	if _, apiErr := runner.Run(context.Background(), spec, 5*time.Second, RunLimits{}); apiErr != nil {
		t.Fatalf("Run: %v", apiErr)
	}
	record := readRecord(t, fake+".args")
	want := []string{"-4", "-D", "eth0", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"}
	if strings.Join(record.Args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v, want %v", record.Args, want)
	}
}
