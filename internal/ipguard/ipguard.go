// Package ipguard implements the destination IP allow/deny policy that is
// enforced independently by the Controller and by every Agent.
//
// Design rules:
//   - Only globally routable unicast destinations are allowed by default.
//   - Loopback, link-local, multicast, unspecified, private, CGNAT, benchmark,
//     documentation, transition-mechanism and other special-use ranges are
//     rejected.
//   - IPv4-mapped IPv6 addresses are unmapped and classified as IPv4 so they
//     cannot be used to bypass IPv4 policy.
//   - An administrator may configure an explicit CIDR allowlist for trusted
//     private-network testing. This allowlist is the only way to reach
//     non-global addresses, and it is evaluated before the default deny rules.
//
// The package has no side effects and no configuration beyond the allowlist;
// it is intentionally small so it can be audited.
package ipguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Reason explains why an address was rejected (or that it was allowed).
type Reason string

const (
	ReasonAllowed       Reason = "allowed"
	ReasonAllowedByList Reason = "allowed_by_allowlist"
	ReasonInvalid       Reason = "invalid_address"
	ReasonUnspecified   Reason = "unspecified_address"
	ReasonLoopback      Reason = "loopback_address"
	ReasonPrivate       Reason = "private_address"
	ReasonLinkLocal     Reason = "link_local_address"
	ReasonMulticast     Reason = "multicast_address"
	ReasonCGNAT         Reason = "cgnat_address"
	ReasonReserved      Reason = "reserved_address"
	ReasonDocumentation Reason = "documentation_address"
	ReasonBenchmark     Reason = "benchmark_address"
	ReasonTransition    Reason = "transition_address"
	ReasonNotGlobal     Reason = "not_globally_routable"
	ReasonZone          Reason = "zoned_address"
	ReasonInvalidCIDR   Reason = "invalid_allowlist_cidr"
	ReasonDefaultRoute  Reason = "allowlist_default_route"
)

// Rejection is returned by Policy.Check for disallowed destinations.
type Rejection struct {
	Addr   netip.Addr
	Reason Reason
}

// Error implements the error interface. The message is safe to show to an
// authenticated user: it contains only the normalized IP and a reason token.
func (r *Rejection) Error() string {
	return fmt.Sprintf("destination %s rejected: %s", r.Addr, r.Reason)
}

var (
	// TailscaleCGNAT is the IPv4 range Tailscale assigns to nodes.
	TailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")
	// TailscaleULA is the IPv6 range Tailscale assigns to nodes.
	TailscaleULA = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// v4Denied lists IPv4 special-use ranges that must not be traced by default.
// Ranges that are already covered by netip classification (loopback, private,
// link-local, multicast) are listed for completeness and documentation value.
var v4Denied = []struct {
	prefix netip.Prefix
	reason Reason
}{
	{netip.MustParsePrefix("0.0.0.0/8"), ReasonUnspecified},         // "this network"
	{netip.MustParsePrefix("10.0.0.0/8"), ReasonPrivate},            // RFC1918
	{netip.MustParsePrefix("100.64.0.0/10"), ReasonCGNAT},           // shared address space / Tailscale
	{netip.MustParsePrefix("127.0.0.0/8"), ReasonLoopback},          // loopback
	{netip.MustParsePrefix("169.254.0.0/16"), ReasonLinkLocal},      // link-local
	{netip.MustParsePrefix("172.16.0.0/12"), ReasonPrivate},         // RFC1918
	{netip.MustParsePrefix("192.0.0.0/24"), ReasonReserved},         // IETF protocol assignments
	{netip.MustParsePrefix("192.0.2.0/24"), ReasonDocumentation},    // TEST-NET-1
	{netip.MustParsePrefix("192.88.99.0/24"), ReasonTransition},     // 6to4 relay anycast
	{netip.MustParsePrefix("192.168.0.0/16"), ReasonPrivate},        // RFC1918
	{netip.MustParsePrefix("198.18.0.0/15"), ReasonBenchmark},       // benchmarking
	{netip.MustParsePrefix("198.51.100.0/24"), ReasonDocumentation}, // TEST-NET-2
	{netip.MustParsePrefix("203.0.113.0/24"), ReasonDocumentation},  // TEST-NET-3
	{netip.MustParsePrefix("224.0.0.0/4"), ReasonMulticast},         // multicast
	{netip.MustParsePrefix("240.0.0.0/4"), ReasonReserved},          // reserved + limited broadcast
}

// v6Denied lists IPv6 special-use ranges that must not be traced by default.
var v6Denied = []struct {
	prefix netip.Prefix
	reason Reason
}{
	{netip.MustParsePrefix("::/128"), ReasonUnspecified},
	{netip.MustParsePrefix("::1/128"), ReasonLoopback},
	{netip.MustParsePrefix("64:ff9b::/96"), ReasonTransition},   // NAT64 well-known prefix embeds IPv4
	{netip.MustParsePrefix("64:ff9b:1::/48"), ReasonTransition}, // local-use NAT64
	{netip.MustParsePrefix("100::/64"), ReasonReserved},         // discard-only
	{netip.MustParsePrefix("2001::/32"), ReasonTransition},      // Teredo embeds IPv4
	{netip.MustParsePrefix("2001:2::/48"), ReasonBenchmark},     // benchmarking
	{netip.MustParsePrefix("2001:10::/28"), ReasonReserved},     // ORCHID
	{netip.MustParsePrefix("2001:20::/28"), ReasonReserved},     // ORCHIDv2
	{netip.MustParsePrefix("2001:db8::/32"), ReasonDocumentation},
	{netip.MustParsePrefix("2002::/16"), ReasonTransition},    // 6to4 embeds IPv4
	{netip.MustParsePrefix("3fff::/20"), ReasonDocumentation}, // RFC 9637 documentation
	{netip.MustParsePrefix("5f00::/8"), ReasonReserved},       // SRv6 SIDs
	{netip.MustParsePrefix("fc00::/7"), ReasonPrivate},        // unique local
	{netip.MustParsePrefix("fe80::/10"), ReasonLinkLocal},     // link-local unicast
	{netip.MustParsePrefix("ff00::/8"), ReasonMulticast},      // multicast
}

// Policy is an immutable destination policy. The zero value denies all
// non-global destinations and allows globally routable unicast addresses.
type Policy struct {
	allow []netip.Prefix
}

// NewPolicy builds a policy from administrator-supplied CIDR strings. Empty
// input yields the default policy (global unicast only). Default routes
// (0.0.0.0/0 and ::/0) are rejected: an allowlist must be explicit, not a
// blanket bypass.
func NewPolicy(cidrs []string) (Policy, error) {
	var p Policy
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			return Policy{}, fmt.Errorf("%w: empty entry", ErrInvalidPolicy)
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return Policy{}, fmt.Errorf("%w: %q: %v", ErrInvalidPolicy, s, err)
		}
		if prefix.Bits() == 0 {
			return Policy{}, fmt.Errorf("%w: %q is a default route; configure explicit ranges instead",
				ErrInvalidPolicy, prefix)
		}
		p.allow = append(p.allow, prefix.Masked())
	}
	return p, nil
}

// ErrInvalidPolicy is returned by NewPolicy for malformed allowlist entries.
var ErrInvalidPolicy = errors.New("invalid target policy")

// Allowlist returns a copy of the configured allowlist prefixes.
func (p Policy) Allowlist() []netip.Prefix {
	out := make([]netip.Prefix, len(p.allow))
	copy(out, p.allow)
	return out
}

// NormalizeIP parses s as an IP literal and returns its canonical form. It
// rejects zone identifiers (`fe80::1%eth0`), whitespace, bracketed forms and
// any non-literal input. IPv4-mapped IPv6 addresses are unmapped to IPv4.
// NormalizeIP does not apply the destination policy.
func NormalizeIP(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, &Rejection{Reason: ReasonInvalid}
	}
	if s != strings.TrimSpace(s) {
		return netip.Addr{}, &Rejection{Reason: ReasonInvalid}
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, &Rejection{Reason: ReasonInvalid}
	}
	if addr.Zone() != "" {
		return netip.Addr{}, &Rejection{Addr: addr, Reason: ReasonZone}
	}
	return addr.Unmap(), nil
}

// Check parses s as an IP literal, normalizes it and applies the destination
// policy. It returns the normalized address on success.
func (p Policy) Check(s string) (netip.Addr, error) {
	addr, err := NormalizeIP(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if err := p.CheckAddr(addr); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// CheckAddr applies the destination policy to an already parsed address.
// addr must not carry a zone. IPv4-mapped IPv6 addresses are unmapped first.
func (p Policy) CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return &Rejection{Reason: ReasonInvalid}
	}
	if addr.Zone() != "" {
		return &Rejection{Addr: addr, Reason: ReasonZone}
	}
	addr = addr.Unmap()

	for _, prefix := range p.allow {
		if prefix.Contains(addr) {
			return nil
		}
	}

	if addr.Is4() {
		for _, rule := range v4Denied {
			if rule.prefix.Contains(addr) {
				return &Rejection{Addr: addr, Reason: rule.reason}
			}
		}
		switch {
		case addr.IsUnspecified():
			return &Rejection{Addr: addr, Reason: ReasonUnspecified}
		case addr.IsLoopback():
			return &Rejection{Addr: addr, Reason: ReasonLoopback}
		case addr.IsPrivate():
			return &Rejection{Addr: addr, Reason: ReasonPrivate}
		case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
			return &Rejection{Addr: addr, Reason: ReasonLinkLocal}
		case addr.IsMulticast():
			return &Rejection{Addr: addr, Reason: ReasonMulticast}
		case !addr.IsGlobalUnicast():
			return &Rejection{Addr: addr, Reason: ReasonNotGlobal}
		}
		return nil
	}

	for _, rule := range v6Denied {
		if rule.prefix.Contains(addr) {
			return &Rejection{Addr: addr, Reason: rule.reason}
		}
	}
	switch {
	case addr.IsUnspecified():
		return &Rejection{Addr: addr, Reason: ReasonUnspecified}
	case addr.IsLoopback():
		return &Rejection{Addr: addr, Reason: ReasonLoopback}
	case addr.IsPrivate():
		return &Rejection{Addr: addr, Reason: ReasonPrivate}
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return &Rejection{Addr: addr, Reason: ReasonLinkLocal}
	case addr.IsMulticast():
		return &Rejection{Addr: addr, Reason: ReasonMulticast}
	case !addr.IsGlobalUnicast():
		return &Rejection{Addr: addr, Reason: ReasonNotGlobal}
	case !globalUnicastV6.Contains(addr):
		// Only the currently allocated global-unicast block is reachable;
		// anything else is reserved for future use.
		return &Rejection{Addr: addr, Reason: ReasonReserved}
	}
	return nil
}

// IsTailscaleAddr reports whether addr is in a Tailscale-assigned range
// (IPv4 CGNAT or the Tailscale IPv6 ULA). It is used for bind-address and
// cleartext-transport checks, not for destination policy.
func IsTailscaleAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return TailscaleCGNAT.Contains(addr) || TailscaleULA.Contains(addr)
}

// IsNonPublic reports whether addr is not a globally routable unicast address.
// It is used to decide whether cleartext HTTP to an Agent is acceptable.
func IsNonPublic(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	if IsTailscaleAddr(addr) {
		return true
	}
	if addr.Is4() {
		return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsUnspecified() || !addr.IsGlobalUnicast() || isV4Special(addr)
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsUnspecified() || !addr.IsGlobalUnicast() || isV6Special(addr)
}

func isV4Special(addr netip.Addr) bool {
	for _, rule := range v4Denied {
		if rule.prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isV6Special(addr netip.Addr) bool {
	for _, rule := range v6Denied {
		if rule.prefix.Contains(addr) {
			return true
		}
	}
	return false
}
