package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
)

// parseListen parses the configured host:port bind address. Only numeric,
// non-wildcard, non-multicast IP literals are accepted: hostnames are never
// resolved for the listening socket.
func parseListen(raw string) (netip.Addr, uint16, error) {
	if strings.TrimSpace(raw) == "" {
		return netip.Addr{}, 0, errors.New("listen address is required")
	}
	host, portText, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.Addr{}, 0, errors.New("listen address must be a numeric IP and port, for example 100.64.0.5:9480")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return netip.Addr{}, 0, errors.New("wildcard binds are refused; configure an explicit local address")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, errors.New("listen host must be a numeric IP address (hostnames are not accepted)")
	}
	if addr.Zone() != "" {
		return netip.Addr{}, 0, errors.New("zoned listen addresses are not accepted")
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return netip.Addr{}, 0, errors.New("wildcard binds are refused; configure an explicit local address")
	}
	if addr.IsMulticast() {
		return netip.Addr{}, 0, errors.New("multicast listen addresses are not accepted")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, errors.New("listen port must be between 1 and 65535")
	}
	return addr, uint16(port), nil
}

// ListenAddr returns the normalized bind address and port.
func (c *Config) ListenAddr() (netip.Addr, uint16, error) {
	return parseListen(c.Listen)
}

// validateBindWith checks that the configured address is assigned to a local
// interface and satisfies the generic bind policy: loopback, RFC1918, CGNAT,
// ULA, Tailscale and other non-public addresses are accepted; a globally
// routable address requires security.allow_public_bind=true. Interface
// addresses are caller-supplied so the rule can be unit tested without
// touching the host.
func (c *Config) validateBindWith(assigned []netip.Addr) error {
	addr, _, err := parseListen(c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	found := false
	for _, candidate := range assigned {
		if candidate.Unmap() == addr {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("listen address %s is not assigned to any local interface", addr)
	}
	if ipguard.IsNonPublic(addr) {
		return nil
	}
	if !c.Security.AllowPublicBind {
		return fmt.Errorf("listen address %s is globally routable; set security.allow_public_bind=true to bind a public address", addr)
	}
	return nil
}

// interfaceAddrs returns all currently assigned local unicast addresses.
func interfaceAddrs() ([]netip.Addr, error) {
	items, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(items))
	for _, item := range items {
		switch value := item.(type) {
		case *net.IPNet:
			if addr, ok := netip.AddrFromSlice(value.IP); ok {
				addrs = append(addrs, addr.Unmap())
			}
		case *net.IPAddr:
			if addr, ok := netip.AddrFromSlice(value.IP); ok {
				addrs = append(addrs, addr.Unmap())
			}
		}
	}
	return addrs, nil
}
