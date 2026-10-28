package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/model"
)

// InterfacesConfig is the optional top-level `interfaces` configuration
// section. Exclude patterns extend the built-in virtual/container exclusions;
// Include names force an interface back into the eligible set (it must still
// exist, be up, non-loopback and have a usable non-link-local address).
type InterfacesConfig struct {
	Exclude []string `json:"exclude"`
	Include []string `json:"include"`
}

// defaultExcludedInterfacePatterns keeps virtual, container, bridge and
// loopback interfaces out of the Agent's selectable set by default. Each entry
// is matched with path.Match against the interface name.
var defaultExcludedInterfacePatterns = []string{
	"lo",
	"docker*",
	"veth*",
	"br-*",
	"virbr*",
	"cni*",
	"flannel*",
	"calico*",
	"podman*",
	"lxc*",
	"lxd*",
	"kube*",
}

// interfacePatternRE bounds administrator exclude patterns. Only '*', letters,
// digits, '_', '.', ':' and '-' are accepted; patterns never contain shell
// metacharacters because they are only used for local name matching.
var interfacePatternRE = regexp.MustCompile(`^[A-Za-z0-9_.:*-]{1,64}$`)

// netInterface is the injectable subset of net.Interface used for enumeration.
type netInterface struct {
	Name     string
	Up       bool
	Loopback bool
	Addrs    []netip.Addr
}

// interfaceSource returns a snapshot of the host's interfaces, including
// their up/loopback flags and addresses. It is injectable for tests.
type interfaceSource func() ([]netInterface, error)

// systemInterfaceSource reads the real host interfaces.
func systemInterfaceSource() ([]netInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]netInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		item := netInterface{
			Name:     iface.Name,
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, raw := range addrs {
			switch value := raw.(type) {
			case *net.IPNet:
				if addr, ok := netip.AddrFromSlice(value.IP); ok {
					item.Addrs = append(item.Addrs, addr.Unmap())
				}
			case *net.IPAddr:
				if addr, ok := netip.AddrFromSlice(value.IP); ok {
					item.Addrs = append(item.Addrs, addr.Unmap())
				}
			}
		}
		out = append(out, item)
	}
	return out, nil
}

// validateInterfacesConfig validates the administrator interface section.
func validateInterfacesConfig(cfg InterfacesConfig) error {
	seenExclude := make(map[string]struct{}, len(cfg.Exclude))
	for _, pattern := range cfg.Exclude {
		if pattern != strings.TrimSpace(pattern) || !interfacePatternRE.MatchString(pattern) {
			return fmt.Errorf("invalid exclude pattern %q", pattern)
		}
		if _, duplicate := seenExclude[pattern]; duplicate {
			return fmt.Errorf("duplicate exclude pattern %q", pattern)
		}
		seenExclude[pattern] = struct{}{}
	}

	seenInclude := make(map[string]struct{}, len(cfg.Include))
	for _, name := range cfg.Include {
		if name != strings.TrimSpace(name) || name == "" {
			return fmt.Errorf("invalid include interface name %q", name)
		}
		if err := model.ValidateInterfaceName(name); err != nil {
			return fmt.Errorf("invalid include interface name %q", name)
		}
		if _, duplicate := seenInclude[name]; duplicate {
			return fmt.Errorf("duplicate include interface name %q", name)
		}
		seenInclude[name] = struct{}{}
	}
	return nil
}

// enumerateInterfaces applies the eligibility rules and returns a sorted,
// stable interface-name list. Include overrides default/config exclusions but
// still requires an existing, up, non-loopback interface with a usable
// address; a missing or unusable explicitly included interface is an error so
// misconfiguration fails startup rather than silently disappearing.
func enumerateInterfaces(cfg InterfacesConfig, source interfaceSource) ([]string, error) {
	if source == nil {
		return nil, errors.New("interface source is not configured")
	}
	interfaces, err := source()
	if err != nil {
		return nil, err
	}

	patterns := make([]string, 0, len(defaultExcludedInterfacePatterns)+len(cfg.Exclude))
	patterns = append(patterns, defaultExcludedInterfacePatterns...)
	patterns = append(patterns, cfg.Exclude...)

	included := make(map[string]struct{}, len(cfg.Include))
	for _, name := range cfg.Include {
		included[name] = struct{}{}
	}

	seen := make(map[string]struct{}, len(interfaces))
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		seen[iface.Name] = struct{}{}
		_, forced := included[iface.Name]

		if forced {
			switch {
			case !iface.Up:
				return nil, fmt.Errorf("included interface %q is not up", iface.Name)
			case iface.Loopback:
				return nil, fmt.Errorf("included interface %q is a loopback interface", iface.Name)
			case !hasUsableAddress(iface.Addrs):
				return nil, fmt.Errorf("included interface %q has no usable non-link-local address", iface.Name)
			}
			names = append(names, iface.Name)
			continue
		}

		if !iface.Up || iface.Loopback || !hasUsableAddress(iface.Addrs) {
			continue
		}
		if matchesAnyInterfacePattern(patterns, iface.Name) {
			continue
		}
		names = append(names, iface.Name)
	}

	for _, name := range cfg.Include {
		if _, ok := seen[name]; !ok {
			return nil, fmt.Errorf("included interface %q does not exist", name)
		}
	}

	sort.Strings(names)
	return names, nil
}

// hasUsableAddress reports whether an interface has at least one non-link-local
// unicast address. Loopback interfaces are filtered separately.
func hasUsableAddress(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
			continue
		}
		return true
	}
	return false
}

func matchesAnyInterfacePattern(patterns []string, name string) bool {
	for _, pattern := range patterns {
		matched, err := path.Match(pattern, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}
