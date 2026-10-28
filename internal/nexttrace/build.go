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
	// Protocol is restricted to the protocols the MVP supports.
	Protocol model.Protocol
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
//	<family> [--traceroute] --json <queries-flag> <queries> <max-hops-flag> <max-hops> [--timeout <ms>] <target>
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
	if spec.Protocol != model.ProtocolICMP {
		return nil, fmt.Errorf("unsupported probe protocol")
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

	args := make([]string, 0, 10)
	args = append(args, familyFlag)
	if c.Flags.Traceroute {
		args = append(args, "--traceroute")
	}
	args = append(args, "--json")
	args = append(args, queriesFlag, strconv.Itoa(spec.Queries))
	args = append(args, maxHopsFlag, strconv.Itoa(spec.MaxHops))
	if c.Flags.Timeout {
		args = append(args, "--timeout", strconv.Itoa(spec.ProbeTimeoutMS))
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
		strconv.Itoa(spec.MaxHops):        true,
		strconv.Itoa(spec.Queries):        true,
		strconv.Itoa(spec.ProbeTimeoutMS): true,
	}
	if len(argv) == 0 {
		return fmt.Errorf("empty argument vector")
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
