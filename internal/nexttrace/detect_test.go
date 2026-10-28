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
		"tcp_short":  full.TCPShort,
		"tcp_long":   full.TCPLong,
		"udp_short":  full.UDPShort,
		"udp_long":   full.UDPLong,
		"port_short": full.PortShort,
		"port_long":  full.PortLong,
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
  -T, --tcp               use TCP SYN probes
  -U, --udp               use UDP probes
  -p, --port int          destination port (default 80)
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

// realNextTraceHelp is a trimmed excerpt of NextTrace v1.7.3's --help output.
// It uses the pflag layout where a short flag and its long alias are separated
// by two spaces, the same width used before the description column. This layout
// previously defeated capability detection (JSON was reported unsupported) and
// left real Agents degraded.
const realNextTraceHelp = `usage: nexttrace [-h|--help] [-4|--ipv4] [-6|--ipv6]
                 [--mtu] [-T|--tcp] [-U|--udp] [TARGET "<value>"]

                 An open source visual route tracking CLI tool

Arguments:

  -4  --ipv4                         Use IPv4 only
  -6  --ipv6                         Use IPv6 only
  -m  --max-hops                     Set the max number of hops (max TTL to be
                                     reached). Default: 30
  -q  --queries                      Latency samples per hop. Increase to 5-10
                                     on unstable paths for a steadier view.
                                     Default: 3
  -j  --json                         Output trace results as JSON
  -C  --no-color                     Disable Colorful Output (traceroute mode
                                     is implied; --traceroute is not a flag)
      --timeout                      Per-probe timeout [ms]. Default: 1000
`

func TestParseFlagsRealNextTraceHelp(t *testing.T) {
	t.Parallel()
	flags := parseFlags(realNextTraceHelp)
	if !flags.required() {
		t.Fatalf("real NextTrace v1.7.3 help must satisfy required flags, got %+v", flags)
	}
	if !flags.JSON {
		t.Error("--json was not detected in real NextTrace help")
	}
	if !flags.IPv4 || !flags.IPv6 {
		t.Errorf("family flags not detected: ipv4=%v ipv6=%v", flags.IPv4, flags.IPv6)
	}
	if !flags.MaxHopsShort || !flags.QueriesShort || !flags.Timeout {
		t.Errorf("numeric flags not detected: %+v", flags)
	}
	// "--traceroute" appears only inside a description in this excerpt, so it
	// must not be treated as a supported flag.
	if flags.Traceroute {
		t.Error("--traceroute mentioned only in a description was treated as supported")
	}
}

func TestDetectRealNextTraceHelp(t *testing.T) {
	fake := newFake(t, fakeControl{Version: "NextTrace v1.7.3 2026-08-23T16:13:15Z\n", Help: realNextTraceHelp})
	caps, apiErr := Detect(context.Background(), fake)
	if apiErr != nil {
		t.Fatalf("Detect: %v", apiErr)
	}
	if !caps.Available() {
		t.Fatal("caps should be available for the real v1.7.3 help layout")
	}
	if caps.Version != "v1.7.3" {
		t.Fatalf("version = %q, want v1.7.3", caps.Version)
	}
}

const defaultHelpForTest = `Usage:
  nexttrace [flags] <target>

Flags:
  -4, --ipv4              only use IPv4
  -6, --ipv6              only use IPv6
  -T, --tcp               use TCP SYN probes
  -U, --udp               use UDP probes
  -p, --port int          destination port (default 80)
  -j, --json              output JSON
  -m, --max-hops int      maximum hops (default 30)
  -q, --queries int       number of probes per hop (default 3)
      --timeout int       probe timeout in milliseconds (default 1000)
      --traceroute        use traceroute-style probing
`

// TestParseFlagsRealNextTraceV173Format guards against the pflag help layout
// used by the real v1.7.3 binary, where short and long aliases are separated
// by two spaces with no comma and descriptions may wrap onto continuation
// lines.
func TestParseFlagsRealNextTraceV173Format(t *testing.T) {
	t.Parallel()
	help := `usage: nexttrace [-h|--help] [-4|--ipv4] [-6|--ipv6] [-T|--tcp] [-U|--udp]
  -4  --ipv4                         Use IPv4 only
  -6  --ipv6                         Use IPv6 only
  -T  --tcp                          Use TCP SYN for tracerouting (default
                                     dest-port is 80)
  -U  --udp                          Use UDP SYN for tracerouting (default
                                     dest-port is 33494)
  -p  --port                         Set the destination port to use. With
                                     default of 80 for "tcp", 33494 for "udp"
  -j  --json                         Output trace results as JSON
  -q  --queries                      Latency samples per hop.
                                     Default: 3
  -m  --max-hops                     Set the max number of hops. Default: 30
      --timeout <integer>            Set timeout for each probe
`
	flags := parseFlags(help)
	for name, ok := range map[string]bool{
		"tcp":      flags.TCPShort && flags.TCPLong,
		"udp":      flags.UDPShort && flags.UDPLong,
		"port":     flags.PortShort && flags.PortLong,
		"json":     flags.JSON,
		"ipv4":     flags.IPv4,
		"ipv6":     flags.IPv6,
		"max_hops": flags.MaxHopsShort && flags.MaxHopsLong,
		"queries":  flags.QueriesShort && flags.QueriesLong,
		"timeout":  flags.Timeout,
	} {
		if !ok {
			t.Fatalf("flag %s not detected in real v1.7.3 help format", name)
		}
	}
	if flags.Traceroute {
		t.Fatal("real v1.7.3 help has no --traceroute flag and none must be assumed")
	}
	caps := Capabilities{Version: "v1.7.3", Flags: flags}
	if !caps.Available() || !caps.SupportsProtocol(model.ProtocolICMP) {
		t.Fatal("real v1.7.3 layout should be usable for ICMP")
	}
	if !caps.SupportsProtocol(model.ProtocolTCP) || !caps.SupportsProtocol(model.ProtocolUDP) {
		t.Fatal("real v1.7.3 layout should support TCP and UDP")
	}
	if flag, ok := caps.Flags.tcpFlag(); !ok || flag != "-T" {
		t.Fatalf("tcpFlag = %q, %v; want -T", flag, ok)
	}
	if flag, ok := caps.Flags.portFlag(); !ok || flag != "-p" {
		t.Fatalf("portFlag = %q, %v; want -p", flag, ok)
	}
}

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
		CapabilityMaxHops, CapabilityPort, CapabilityQueries,
		CapabilityTCP, CapabilityTimeout, CapabilityTraceroute, CapabilityUDP,
	}
	got := caps.CapabilityNames()
	if strings.Join(got, ",") != strings.Join(wantCaps, ",") {
		t.Fatalf("capabilities = %v, want %v", got, wantCaps)
	}
}

func TestDetectOptionalProtocolCapabilities(t *testing.T) {
	baseHelp := `Flags:
  -4, --ipv4
  -6, --ipv6
  -j, --json
  -m, --max-hops int
  -q, --queries int
`
	t.Run("icmp-only binary", func(t *testing.T) {
		fake := newFake(t, fakeControl{Help: baseHelp})
		caps, apiErr := Detect(context.Background(), fake)
		if apiErr != nil {
			t.Fatalf("Detect: %v", apiErr)
		}
		if !caps.Available() {
			t.Fatal("an ICMP-only binary must remain usable")
		}
		if !caps.SupportsProtocol(model.ProtocolICMP) {
			t.Fatal("ICMP should be supported")
		}
		if caps.SupportsProtocol(model.ProtocolTCP) || caps.SupportsProtocol(model.ProtocolUDP) {
			t.Fatal("TCP/UDP must not be supported without their flags")
		}
		for _, unsupported := range []string{CapabilityTCP, CapabilityUDP, CapabilityPort} {
			for _, name := range caps.CapabilityNames() {
				if name == unsupported {
					t.Fatalf("capabilities %v must not include %q", caps.CapabilityNames(), unsupported)
				}
			}
		}
	})

	t.Run("tcp without port flag is not effective", func(t *testing.T) {
		fake := newFake(t, fakeControl{Help: baseHelp + `  -T, --tcp
  -U, --udp
`})
		caps, apiErr := Detect(context.Background(), fake)
		if apiErr != nil {
			t.Fatalf("Detect: %v", apiErr)
		}
		if !caps.SupportsProtocol(model.ProtocolICMP) {
			t.Fatal("ICMP should remain supported")
		}
		if caps.SupportsProtocol(model.ProtocolTCP) || caps.SupportsProtocol(model.ProtocolUDP) {
			t.Fatal("TCP/UDP require a detected port flag to be effective")
		}
		names := caps.CapabilityNames()
		if !containsString(names, CapabilityTCP) || !containsString(names, CapabilityUDP) {
			t.Fatalf("raw capabilities should still report detected protocol flags: %v", names)
		}
		if containsString(names, CapabilityPort) {
			t.Fatalf("port must not be reported without a port flag: %v", names)
		}
	})

	t.Run("long spellings only", func(t *testing.T) {
		fake := newFake(t, fakeControl{Help: baseHelp + `  --tcp
  --udp
  --port int
`})
		caps, apiErr := Detect(context.Background(), fake)
		if apiErr != nil {
			t.Fatalf("Detect: %v", apiErr)
		}
		for _, protocol := range []model.Protocol{model.ProtocolICMP, model.ProtocolTCP, model.ProtocolUDP} {
			if !caps.SupportsProtocol(protocol) {
				t.Fatalf("protocol %s should be supported with long flags", protocol)
			}
		}
		if flag, ok := caps.Flags.tcpFlag(); !ok || flag != "--tcp" {
			t.Fatalf("tcpFlag = %q, %v", flag, ok)
		}
		if flag, ok := caps.Flags.udpFlag(); !ok || flag != "--udp" {
			t.Fatalf("udpFlag = %q, %v", flag, ok)
		}
		if flag, ok := caps.Flags.portFlag(); !ok || flag != "--port" {
			t.Fatalf("portFlag = %q, %v", flag, ok)
		}
	})
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
