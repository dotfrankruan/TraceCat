package nexttrace

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	// MinProbeTimeoutMS and MaxProbeTimeoutMS bound the per-probe timeout the
	// Agent passes to NextTrace (a fixed Agent setting, not a request field).
	MinProbeTimeoutMS = 100
	MaxProbeTimeoutMS = 60_000
)

// Spec is the complete, already-validated description of one NextTrace
// invocation. Construction is typed: callers cannot inject flags, whitespace,
// extra arguments or a hostname.
type Spec struct {
	// Addr must be a normalized (unmapped, zone-free) numeric IP literal.
	Addr netip.Addr
	// Family must match Addr.
	Family model.IPFamily
	// Protocol is one of the fixed TraceCat protocols. ICMP is the default
	// probe mode; TCP and UDP require Port.
	Protocol model.Protocol
	// Port is the destination port for TCP/UDP probes. It must be nil for
	// ICMP and is always a bounded integer (model.ValidatePortForProtocol).
	Port *int
	// Interface optionally selects a source network interface by name. Empty
	// means automatic routing. The Agent validates the name against its live
	// enumerated interface set before execution.
	Interface string
	// MaxHops is the maximum TTL to probe.
	MaxHops int
	// Queries is the number of probes per TTL.
	Queries int
	// ProbeTimeoutMS is the per-probe timeout in milliseconds.
	ProbeTimeoutMS int
}

// BuildArgs constructs the exact argument vector for spec using only flags
// that were verified present in the installed binary's help output.
//
// The argument vector is deterministic and follows this shape:
//
//	<family> [<protocol-flag>] [-D <interface>] [--traceroute] --json <queries-flag> <queries> <max-hops-flag> <max-hops> [--timeout <ms>] [-p <port>] <target>
//
// ICMP has no protocol flag (it is NextTrace's default). TCP maps to the
// detected -T/--tcp flag, UDP to -U/--udp, and both additionally require the
// detected port flag so a validated destination port is always supplied.
//
// The target is always the last argument and is the canonical string form of
// the normalized address. After construction the vector is checked against the
// allowlist again; a mismatch is a programming error and is reported instead of
// executing anything.
func (c Capabilities) BuildArgs(spec Spec) ([]string, error) {
	if !c.Available() {
		return nil, fmt.Errorf("nexttrace does not support the required command-line flags")
	}

	addr := spec.Addr.Unmap()
	if !addr.IsValid() {
		return nil, fmt.Errorf("target address is invalid")
	}
	if addr != spec.Addr || addr.Zone() != "" {
		return nil, fmt.Errorf("target address must be a normalized IP literal")
	}
	if spec.Family != model.FamilyOf(addr) {
		return nil, fmt.Errorf("target family does not match the address")
	}
	if !spec.Protocol.Valid() {
		return nil, fmt.Errorf("unsupported probe protocol")
	}
	if err := model.ValidatePortForProtocol(spec.Protocol, spec.Port); err != nil {
		return nil, fmt.Errorf("invalid protocol/port combination")
	}
	if !c.SupportsProtocol(spec.Protocol) {
		return nil, fmt.Errorf("nexttrace does not support the requested protocol")
	}
	if spec.Interface != "" {
		if err := model.ValidateInterfaceName(spec.Interface); err != nil {
			return nil, fmt.Errorf("invalid network interface name")
		}
		if _, ok := c.Flags.deviceFlag(); !ok {
			return nil, fmt.Errorf("nexttrace does not support source-device selection")
		}
	}
	if spec.MaxHops < model.MinMaxHops || spec.MaxHops > model.MaxMaxHops {
		return nil, fmt.Errorf("max hops is out of range")
	}
	if spec.Queries < model.MinQueries || spec.Queries > model.MaxQueries {
		return nil, fmt.Errorf("queries is out of range")
	}
	if spec.ProbeTimeoutMS < MinProbeTimeoutMS || spec.ProbeTimeoutMS > MaxProbeTimeoutMS {
		return nil, fmt.Errorf("probe timeout is out of range")
	}

	maxHopsFlag, ok := c.Flags.maxHopsFlag()
	if !ok {
		return nil, fmt.Errorf("nexttrace does not support a max-hops flag")
	}
	queriesFlag, ok := c.Flags.queriesFlag()
	if !ok {
		return nil, fmt.Errorf("nexttrace does not support a queries flag")
	}

	familyFlag, ok := c.Flags.familyFlag(spec.Family)
	if !ok {
		return nil, fmt.Errorf("nexttrace does not support a family flag")
	}
	protocolFlag, ok := c.Flags.protocolFlag(spec.Protocol)
	if !ok {
		return nil, fmt.Errorf("nexttrace does not support the requested protocol flag")
	}

	args := make([]string, 0, 15)
	args = append(args, familyFlag)
	if protocolFlag != "" {
		args = append(args, protocolFlag)
	}
	if spec.Interface != "" {
		deviceFlag, ok := c.Flags.deviceFlag()
		if !ok {
			return nil, fmt.Errorf("nexttrace does not support source-device selection")
		}
		args = append(args, deviceFlag, spec.Interface)
	}
	if c.Flags.Traceroute {
		args = append(args, "--traceroute")
	}
	args = append(args, "--json")
	args = append(args, queriesFlag, strconv.Itoa(spec.Queries))
	args = append(args, maxHopsFlag, strconv.Itoa(spec.MaxHops))
	if c.Flags.Timeout {
		args = append(args, "--timeout", strconv.Itoa(spec.ProbeTimeoutMS))
	}
	if spec.Protocol.RequiresPort() {
		portFlag, ok := c.Flags.portFlag()
		if !ok {
			return nil, fmt.Errorf("nexttrace does not support a destination-port flag")
		}
		args = append(args, portFlag, strconv.Itoa(*spec.Port))
	}
	args = append(args, addr.String())

	if err := assertArgv(c, spec, args, addr); err != nil {
		return nil, err
	}
	return args, nil
}

// assertArgv re-checks a constructed vector against the allowlist. Every
// element must be an expected flag, a validated numeric value, or the exact
// canonical target in the final position.
func assertArgv(c Capabilities, spec Spec, argv []string, addr netip.Addr) error {
	allowed := map[string]bool{
		"-4":                              true,
		"-6":                              true,
		"--ipv4":                          true,
		"--ipv6":                          true,
		"--json":                          true,
		"--traceroute":                    true,
		"--timeout":                       true,
		"-m":                              true,
		"--max-hops":                      true,
		"-q":                              true,
		"--queries":                       true,
		"-T":                              true,
		"--tcp":                           true,
		"-U":                              true,
		"--udp":                           true,
		"-p":                              true,
		"--port":                          true,
		"-D":                              true,
		"--dev":                           true,
		spec.Interface:                    true,
		strconv.Itoa(spec.MaxHops):        true,
		strconv.Itoa(spec.Queries):        true,
		strconv.Itoa(spec.ProbeTimeoutMS): true,
	}
	if spec.Port != nil {
		allowed[strconv.Itoa(*spec.Port)] = true
	}
	if spec.Interface == "" {
		delete(allowed, "")
	}
	if len(argv) == 0 {
		return fmt.Errorf("empty argument vector")
	}
	familyFlag, ok := c.Flags.familyFlag(spec.Family)
	if !ok || argv[0] != familyFlag {
		return fmt.Errorf("argument vector does not start with the expected family flag")
	}
	protocolFlag, ok := c.Flags.protocolFlag(spec.Protocol)
	if !ok {
		return fmt.Errorf("protocol flag was not detected")
	}
	if protocolFlag == "" {
		if len(argv) < 2 || argv[1] == "-T" || argv[1] == "--tcp" || argv[1] == "-U" || argv[1] == "--udp" {
			return fmt.Errorf("icmp argument vector must not carry a protocol flag")
		}
	} else if len(argv) < 2 || argv[1] != protocolFlag {
		return fmt.Errorf("argument vector does not carry the expected protocol flag")
	}
	devicePosition := 1
	if protocolFlag != "" {
		devicePosition = 2
	}
	if spec.Interface != "" {
		deviceFlag, ok := c.Flags.deviceFlag()
		if !ok || len(argv) <= devicePosition+1 || argv[devicePosition] != deviceFlag || argv[devicePosition+1] != spec.Interface {
			return fmt.Errorf("argument vector does not carry the expected source-device pair")
		}
	} else if containsArg(argv, "-D") || containsArg(argv, "--dev") {
		return fmt.Errorf("automatic routing must not carry a source-device flag")
	}
	if target := argv[len(argv)-1]; target != addr.String() {
		return fmt.Errorf("target must be the final argument and must equal the normalized address")
	}
	for i, arg := range argv {
		if arg == "" {
			return fmt.Errorf("empty argument")
		}
		if strings.ContainsAny(arg, "\x00\n\r\t") {
			return fmt.Errorf("argument contains control characters")
		}
		if i == len(argv)-1 {
			continue
		}
		if !allowed[arg] {
			return fmt.Errorf("argument is outside the allowlist")
		}
	}
	if !c.Flags.Traceroute && containsArg(argv, "--traceroute") {
		return fmt.Errorf("traceroute flag was not detected")
	}
	if !c.Flags.Timeout && containsArg(argv, "--timeout") {
		return fmt.Errorf("timeout flag was not detected")
	}
	if spec.Protocol.RequiresPort() {
		portFlag, ok := c.Flags.portFlag()
		if !ok || spec.Port == nil {
			return fmt.Errorf("tcp/udp probe is missing its destination port")
		}
		// The port pair is immediately before the target.
		if len(argv) < 3 || argv[len(argv)-3] != portFlag || argv[len(argv)-2] != strconv.Itoa(*spec.Port) {
			return fmt.Errorf("tcp/udp probe does not carry the expected destination port pair")
		}
	} else if containsArg(argv, "-p") || containsArg(argv, "--port") {
		return fmt.Errorf("icmp probe must not carry a destination port")
	}
	return nil
}

func containsArg(argv []string, want string) bool {
	for _, arg := range argv {
		if arg == want {
			return true
		}
	}
	return false
}

// minimalEnv returns the fixed, minimal environment used for every NextTrace
// invocation. No TraceCat configuration, token or unrelated environment
// variable is inherited.
func minimalEnv() []string {
	home := os.Getenv("HOME")
	if home == "" || strings.ContainsAny(home, "\x00\n\r") {
		home = "/"
	}
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + home,
		"LANG=C",
		"LC_ALL=C",
		"NO_COLOR=1",
	}
}
