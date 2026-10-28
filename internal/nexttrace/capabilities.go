// Package nexttrace is the only component in TraceCat that executes the
// external NextTrace binary. It deliberately provides a small, auditable
// surface: capability detection from the installed binary, a typed argument
// constructor (never a shell), process-group supervision with bounded output,
// and a version-aware JSON parser isolated from the shared wire model.
//
// Security rules enforced here:
//   - The executable path is always a fixed absolute path supplied by the
//     Agent configuration; it is never derived from a request.
//   - Arguments are built from validated, typed values only. There is no
//     shell, no environment expansion and no string concatenation of user
//     input into a command line.
//   - The child runs with a minimal, fixed environment.
//   - Flags are detected from the installed binary's --help output; they are
//     never assumed.
package nexttrace

import (
	"context"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	// DetectionTimeout bounds each of the startup --version and --help probes.
	DetectionTimeout = 5 * time.Second
	// detectionOutputLimit bounds how much help/version text is read.
	detectionOutputLimit = 64 << 10
)

// Capability names reported by GET /v1/health. They are stable identifiers,
// not raw command-line flags.
const (
	CapabilityJSON       = "json"
	CapabilityIPv4       = "ipv4"
	CapabilityIPv6       = "ipv6"
	CapabilityMaxHops    = "max_hops"
	CapabilityQueries    = "queries"
	CapabilityTimeout    = "timeout"
	CapabilityTraceroute = "traceroute"
)

// Flags records which command-line flags were actually observed in the
// installed binary's help output. The zero value means "nothing detected".
type Flags struct {
	JSON bool
	IPv4 bool
	IPv6 bool
	// Long spellings of the family flags, used when a build only exposes
	// --ipv4/--ipv6.
	IPv4Long bool
	IPv6Long bool

	// NextTrace exposes short and long spellings; the parser records both so
	// the argument builder can use whichever spelling was verified.
	MaxHopsShort bool
	MaxHopsLong  bool
	QueriesShort bool
	QueriesLong  bool

	Timeout    bool
	Traceroute bool
}

func (f Flags) familyFlag(family model.IPFamily) (string, bool) {
	if family == model.FamilyIPv4 {
		switch {
		case f.IPv4:
			return "-4", true
		case f.IPv4Long:
			return "--ipv4", true
		}
		return "", false
	}
	switch {
	case f.IPv6:
		return "-6", true
	case f.IPv6Long:
		return "--ipv6", true
	}
	return "", false
}

func (f Flags) maxHopsFlag() (string, bool) {
	switch {
	case f.MaxHopsShort:
		return "-m", true
	case f.MaxHopsLong:
		return "--max-hops", true
	default:
		return "", false
	}
}

func (f Flags) queriesFlag() (string, bool) {
	switch {
	case f.QueriesShort:
		return "-q", true
	case f.QueriesLong:
		return "--queries", true
	default:
		return "", false
	}
}

// required reports whether every flag the Agent needs is supported.
func (f Flags) required() bool {
	_, hasIPv4 := f.familyFlag(model.FamilyIPv4)
	_, hasIPv6 := f.familyFlag(model.FamilyIPv6)
	_, hasMaxHops := f.maxHopsFlag()
	_, hasQueries := f.queriesFlag()
	return f.JSON && hasIPv4 && hasIPv6 && hasMaxHops && hasQueries
}

// Capabilities is the safe, detected description of the local NextTrace
// binary. It contains no executable path and no environment.
type Capabilities struct {
	Version string
	Flags   Flags
}

// Available reports whether the binary supports the required flags and can be
// used to run traces.
func (c Capabilities) Available() bool { return c.Flags.required() }

// CapabilityNames returns the detected capability identifiers in a stable
// (sorted) order. It includes what was detected even when the binary is not
// usable, so operators can see why it was rejected.
func (c Capabilities) CapabilityNames() []string {
	names := make([]string, 0, 7)
	if _, ok := c.Flags.familyFlag(model.FamilyIPv4); ok {
		names = append(names, CapabilityIPv4)
	}
	if _, ok := c.Flags.familyFlag(model.FamilyIPv6); ok {
		names = append(names, CapabilityIPv6)
	}
	if c.Flags.JSON {
		names = append(names, CapabilityJSON)
	}
	if _, ok := c.Flags.maxHopsFlag(); ok {
		names = append(names, CapabilityMaxHops)
	}
	if _, ok := c.Flags.queriesFlag(); ok {
		names = append(names, CapabilityQueries)
	}
	if c.Flags.Timeout {
		names = append(names, CapabilityTimeout)
	}
	if c.Flags.Traceroute {
		names = append(names, CapabilityTraceroute)
	}
	sort.Strings(names)
	return names
}

var (
	// Prefer the conventional "NextTrace v1.7.1" form.
	versionPattern = regexp.MustCompile(`(?i)\bv(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)\b`)
	// Accept "nexttrace version 1.7.1" and "NextTrace 1.7.1" without the v.
	versionFallbackPattern = regexp.MustCompile(`(?i)(?:nexttrace|version)\s*[:=]?\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)\b`)
)

// parseVersion extracts a normalized semantic version (with a leading "v")
// from `nexttrace --version` output. It returns "" when nothing recognizable
// was found. Build dates and other dotted numbers are never mistaken for a
// version.
func parseVersion(output string) string {
	if m := versionPattern.FindStringSubmatch(output); len(m) == 2 {
		return "v" + m[1]
	}
	if m := versionFallbackPattern.FindStringSubmatch(output); len(m) == 2 {
		return "v" + m[1]
	}
	return ""
}

// helpFlagSet collects flag tokens from command help output. Only definition
// lines (trimmed lines that start with "-") are considered, and the description
// part after two or more spaces is ignored, so a description that merely
// mentions a flag cannot create a false positive.
func helpFlagSet(help string) map[string]bool {
	found := make(map[string]bool)
	for _, line := range strings.Split(help, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || !strings.HasPrefix(trimmed, "-") {
			continue
		}
		if idx := strings.Index(trimmed, "  "); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		for _, token := range strings.Fields(strings.NewReplacer(",", " ", "=", " ").Replace(trimmed)) {
			found[token] = true
		}
	}
	return found
}

func parseFlags(help string) Flags {
	found := helpFlagSet(help)
	return Flags{
		JSON:         found["--json"],
		IPv4:         found["-4"],
		IPv6:         found["-6"],
		IPv4Long:     found["--ipv4"],
		IPv6Long:     found["--ipv6"],
		MaxHopsShort: found["-m"],
		MaxHopsLong:  found["--max-hops"],
		QueriesShort: found["-q"],
		QueriesLong:  found["--queries"],
		Timeout:      found["--timeout"],
		Traceroute:   found["--traceroute"],
	}
}

// Detect probes the configured NextTrace binary once at startup and returns
// its safe capability description. The returned *model.APIError is safe to
// expose to an authenticated Controller: it never contains a filesystem path,
// command output or environment value.
func Detect(ctx context.Context, binaryPath string) (Capabilities, *model.APIError) {
	var caps Capabilities
	if strings.TrimSpace(binaryPath) == "" {
		return caps, model.NewError(model.ErrNextTraceMissing, "nexttrace binary is not configured")
	}

	versionOut, probeMsg := runProbe(ctx, binaryPath, "--version")
	if probeMsg != "" {
		return caps, model.NewError(model.ErrNextTraceMissing, probeMsg)
	}
	version := parseVersion(versionOut)
	if version == "" {
		return caps, model.NewError(model.ErrNextTraceMissing, "unrecognized nexttrace version output")
	}
	caps.Version = version

	helpOut, probeMsg := runProbe(ctx, binaryPath, "--help")
	if probeMsg != "" {
		return caps, model.NewError(model.ErrNextTraceMissing, probeMsg)
	}
	caps.Flags = parseFlags(helpOut)
	if !caps.Flags.required() {
		return caps, model.NewError(model.ErrNextTraceMissing, "installed nexttrace does not support the flags TraceCat requires")
	}
	return caps, nil
}

// runProbe executes one bounded capability probe. It returns combined
// stdout/stderr text on success and a safe error message on failure.
func runProbe(ctx context.Context, binaryPath, arg string) (string, string) {
	probeCtx, cancel := context.WithTimeout(ctx, DetectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, binaryPath, arg)
	cmd.Env = minimalEnv()
	cmd.WaitDelay = time.Second
	configureProcessGroup(cmd)
	var killOnce sync.Once
	cmd.Cancel = func() error {
		killOnce.Do(func() {
			if process := cmd.Process; process != nil {
				_ = killProcessGroup(process)
			}
		})
		return nil
	}

	stdout := newBoundedBuffer(detectionOutputLimit)
	stderr := newBoundedBuffer(detectionOutputLimit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		if probeCtx.Err() != nil {
			return "", "nexttrace capability detection timed out"
		}
		return "", "nexttrace binary is not executable"
	}
	return string(stdout.Bytes()) + "\n" + string(stderr.Bytes()), ""
}
