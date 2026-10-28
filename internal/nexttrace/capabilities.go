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
	CapabilityTCP        = "tcp"
	CapabilityUDP        = "udp"
	CapabilityPort       = "port"
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

	// TCP/UDP probe flags and the destination-port flag. They are optional:
	// a binary without them remains usable for ICMP, but the corresponding
	// protocol is not advertised as effective by the Agent.
	TCPShort  bool
	TCPLong   bool
	UDPShort  bool
	UDPLong   bool
	PortShort bool
	PortLong  bool
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

func (f Flags) tcpFlag() (string, bool) {
	switch {
	case f.TCPShort:
		return "-T", true
	case f.TCPLong:
		return "--tcp", true
	default:
		return "", false
	}
}

func (f Flags) udpFlag() (string, bool) {
	switch {
	case f.UDPShort:
		return "-U", true
	case f.UDPLong:
		return "--udp", true
	default:
		return "", false
	}
}

func (f Flags) portFlag() (string, bool) {
	switch {
	case f.PortShort:
		return "-p", true
	case f.PortLong:
		return "--port", true
	default:
		return "", false
	}
}

// protocolFlag returns the flag that selects protocol p. ICMP is NextTrace's
// default mode and intentionally has no protocol flag.
func (f Flags) protocolFlag(protocol model.Protocol) (string, bool) {
	switch protocol {
	case model.ProtocolICMP:
		return "", true
	case model.ProtocolTCP:
		return f.tcpFlag()
	case model.ProtocolUDP:
		return f.udpFlag()
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

// SupportsProtocol reports whether the binary can execute protocol p safely
// with the flags TraceCat needs. ICMP needs only the required base flags; TCP
// and UDP additionally need both their protocol flag and the destination-port
// flag so the Agent can always append a validated `-p <port>`.
func (c Capabilities) SupportsProtocol(protocol model.Protocol) bool {
	if !c.Available() {
		return false
	}
	switch protocol {
	case model.ProtocolICMP:
		return true
	case model.ProtocolTCP:
		_, hasTCP := c.Flags.tcpFlag()
		_, hasPort := c.Flags.portFlag()
		return hasTCP && hasPort
	case model.ProtocolUDP:
		_, hasUDP := c.Flags.udpFlag()
		_, hasPort := c.Flags.portFlag()
		return hasUDP && hasPort
	default:
		return false
	}
}

// SupportedProtocols returns the protocols the binary itself can execute, in
// the canonical icmp/tcp/udp order.
func (c Capabilities) SupportedProtocols() []model.Protocol {
	protocols := make([]model.Protocol, 0, 3)
	for _, protocol := range []model.Protocol{model.ProtocolICMP, model.ProtocolTCP, model.ProtocolUDP} {
		if c.SupportsProtocol(protocol) {
			protocols = append(protocols, protocol)
		}
	}
	return protocols
}

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
	if _, ok := c.Flags.tcpFlag(); ok {
		names = append(names, CapabilityTCP)
	}
	if _, ok := c.Flags.udpFlag(); ok {
		names = append(names, CapabilityUDP)
	}
	if _, ok := c.Flags.portFlag(); ok {
		names = append(names, CapabilityPort)
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
		trimmed = flagDefinitionPrefix(trimmed)
		for _, token := range strings.Fields(strings.NewReplacer(",", " ", "=", " ").Replace(trimmed)) {
			found[token] = true
		}
	}
	return found
}

// flagDefinitionPrefix returns the flag-definition part of one help line.
// Real NextTrace (pflag) help separates a short flag from its long alias with
// two spaces too, for example:
//
//	-j  --json                         Output trace results as JSON
//
// so a run of two or more spaces only terminates the definition when the text
// after it does not start with another flag. This keeps both "-j" and
// "--json" detectable while still discarding the description column.
func flagDefinitionPrefix(line string) string {
	for i := 0; i < len(line); {
		if line[i] != ' ' {
			i++
			continue
		}
		j := i
		for j < len(line) && line[j] == ' ' {
			j++
		}
		if j-i >= 2 {
			rest := strings.TrimSpace(line[j:])
			if rest == "" || !strings.HasPrefix(rest, "-") {
				return strings.TrimSpace(line[:i])
			}
		}
		i = j
	}
	return strings.TrimSpace(line)
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
		TCPShort:     found["-T"],
		TCPLong:      found["--tcp"],
		UDPShort:     found["-U"],
		UDPLong:      found["--udp"],
		PortShort:    found["-p"],
		PortLong:     found["--port"],
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
