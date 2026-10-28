package nexttrace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"typical", "NextTrace v1.7.1 2024-05-01T00:00:00Z\n", "v1.7.1"},
		{"bare version", "NextTrace v1.7.3\n", "v1.7.3"},
		{"no leading v", "nexttrace version 1.6.0\n", "v1.6.0"},
		{"prerelease", "NextTrace v1.8.0-beta.1 built from source\n", "v1.8.0-beta.1"},
		{"noise", "NextTrace build unknown\n", ""},
		{"empty", "", ""},
		{"date is not a version", "NextTrace built 2024.05.01\n", ""},
		{"plain dotted number", "build 2024.05.01\n", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseVersion(tc.in); got != tc.want {
				t.Fatalf("parseVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	t.Parallel()
	full := parseFlags(defaultHelpForTest)
	for name, got := range map[string]bool{
		"json":       full.JSON,
		"ipv4":       full.IPv4,
		"ipv6":       full.IPv6,
		"max_hops":   full.MaxHopsShort && full.MaxHopsLong,
		"queries":    full.QueriesShort && full.QueriesLong,
		"timeout":    full.Timeout,
		"traceroute": full.Traceroute,
	} {
		if !got {
			t.Errorf("flag %s not detected in full help output", name)
		}
	}
	if !full.required() {
		t.Fatal("full help output should satisfy required flags")
	}

	// A description that mentions a flag must not be mistaken for support.
	mentionedOnly := parseFlags(`Flags:
  -4, --ipv4              only use IPv4
  -6, --ipv6              only use IPv6
  -j, --json              output JSON
  -m, --max-hops int      maximum hops (default 30)
  -q, --queries int       number of probes per hop (default 3)
                          note: --timeout is not supported by this build
`)
	if mentionedOnly.Timeout {
		t.Fatal("--timeout mentioned only in a description was treated as supported")
	}

	longOnly := parseFlags(`Flags:
  --ipv4
  --ipv6
  --json
  --max-hops int
  --queries int
`)
	if !longOnly.required() {
		t.Fatalf("long-only help should be usable, got %+v", longOnly)
	}
	if flag, ok := longOnly.maxHopsFlag(); !ok || flag != "--max-hops" {
		t.Fatalf("maxHopsFlag = %q, %v; want --max-hops", flag, ok)
	}
	if flag, ok := longOnly.queriesFlag(); !ok || flag != "--queries" {
		t.Fatalf("queriesFlag = %q, %v; want --queries", flag, ok)
	}

	missingJSON := parseFlags(`Flags:
  -4
  -6
  -m, --max-hops int
  -q, --queries int
`)
	if missingJSON.required() {
		t.Fatal("help without --json must not be considered usable")
	}
}

const defaultHelpForTest = `Usage:
  nexttrace [flags] <target>

Flags:
  -4, --ipv4              only use IPv4
  -6, --ipv6              only use IPv6
  -j, --json              output JSON
  -m, --max-hops int      maximum hops (default 30)
  -q, --queries int       number of probes per hop (default 3)
      --timeout int       probe timeout in milliseconds (default 1000)
      --traceroute        use traceroute-style probing
`

func TestDetectFakeBinary(t *testing.T) {
	fake := newFake(t, fakeControl{})

	caps, apiErr := Detect(context.Background(), fake)
	if apiErr != nil {
		t.Fatalf("Detect: %v", apiErr)
	}
	if !caps.Available() {
		t.Fatal("fake default binary should be usable")
	}
	if caps.Version != "v1.7.1" {
		t.Fatalf("version = %q, want v1.7.1", caps.Version)
	}
	wantCaps := []string{
		CapabilityIPv4, CapabilityIPv6, CapabilityJSON,
		CapabilityMaxHops, CapabilityQueries, CapabilityTimeout, CapabilityTraceroute,
	}
	got := caps.CapabilityNames()
	if strings.Join(got, ",") != strings.Join(wantCaps, ",") {
		t.Fatalf("capabilities = %v, want %v", got, wantCaps)
	}
}

func TestDetectRejectsMissingRequiredFlags(t *testing.T) {
	fake := newFake(t, fakeControl{
		Help: "Flags:\n  -4\n  -6\n  -m, --max-hops int\n  -q, --queries int\n",
	})

	caps, apiErr := Detect(context.Background(), fake)
	if apiErr == nil {
		t.Fatal("Detect should fail when --json is unsupported")
	}
	if apiErr.Code != model.ErrNextTraceMissing {
		t.Fatalf("error code = %s, want nexttrace_unavailable", apiErr.Code)
	}
	if caps.Available() {
		t.Fatal("caps must not be available when required flags are missing")
	}
	if strings.Contains(apiErr.Message, fake) || strings.Contains(apiErr.Message, filepath.Dir(fake)) {
		t.Fatalf("error message leaks the executable path: %q", apiErr.Message)
	}
}

func TestDetectRejectsBadVersionOutput(t *testing.T) {
	fake := newFake(t, fakeControl{Version: "not a version\n"})
	_, apiErr := Detect(context.Background(), fake)
	if apiErr == nil || apiErr.Code != model.ErrNextTraceMissing {
		t.Fatalf("Detect error = %v, want nexttrace_unavailable", apiErr)
	}
}

func TestDetectRejectsFailedProbe(t *testing.T) {
	fake := newFake(t, fakeControl{VersionExit: 2})
	_, apiErr := Detect(context.Background(), fake)
	if apiErr == nil || apiErr.Code != model.ErrNextTraceMissing {
		t.Fatalf("Detect error = %v, want nexttrace_unavailable", apiErr)
	}
	if strings.Contains(apiErr.Message, fake) {
		t.Fatalf("error message leaks the executable path: %q", apiErr.Message)
	}
}

func TestDetectMissingBinary(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, apiErr := Detect(context.Background(), missing)
	if apiErr == nil || apiErr.Code != model.ErrNextTraceMissing {
		t.Fatalf("Detect error = %v, want nexttrace_unavailable", apiErr)
	}
	if strings.Contains(apiErr.Message, missing) {
		t.Fatalf("error message leaks the executable path: %q", apiErr.Message)
	}
}

func TestDetectHonoursContextCancellation(t *testing.T) {
	fake := newFake(t, fakeControl{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, apiErr := Detect(ctx, fake)
	if apiErr == nil {
		t.Fatal("Detect should fail for a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Detect took %v with a cancelled context", elapsed)
	}
}

// TestDetectDoesNotUseShell verifies that a binary path containing shell
// metacharacters is executed directly rather than interpreted by a shell.
func TestDetectDoesNotUseShell(t *testing.T) {
	dir := t.TempDir()
	weird := filepath.Join(dir, "next trace; touch pwned $(id)")
	copyExecutable(t, buildFake(t), weird)

	if _, apiErr := Detect(context.Background(), weird); apiErr != nil {
		t.Fatalf("Detect with metacharacter path: %v", apiErr)
	}
	for _, name := range []string{"pwned", "trace"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("shell interpretation created %q", name)
		}
	}
}
