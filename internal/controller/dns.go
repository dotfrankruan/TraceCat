package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

// resolverWarning is the mandatory CDN/GeoDNS caveat attached to every domain
// resolution result (see docs/API.md §2.6).
const resolverWarning = "Agents trace the centrally resolved IP. For CDN and GeoDNS services, paths may differ from resolving the hostname locally on each Agent."

// Resolver is the narrow DNS lookup surface the Controller needs. It exists so
// tests can inject deterministic answers without touching global net state.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// NewNetResolver returns the production resolver. An empty server uses the
// system resolver; otherwise queries are sent to the configured host:port.
func NewNetResolver(server string) Resolver {
	if strings.TrimSpace(server) == "" {
		return net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Force UDP to the configured server for deterministic behavior.
			return dialer.DialContext(ctx, "udp", server)
		},
	}
}

// ResolverService validates user targets and performs policy-filtered DNS
// resolution. It never exposes resolver internals to callers.
type ResolverService struct {
	resolver     Resolver
	policy       ipguard.Policy
	timeout      time.Duration
	maxAddresses int
}

// NewResolverService builds the resolver service.
func NewResolverService(resolver Resolver, policy ipguard.Policy, timeout time.Duration, maxAddresses int) *ResolverService {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = defaultDNSTimeoutMS * time.Millisecond
	}
	if maxAddresses <= 0 {
		maxAddresses = defaultDNSMaxAddresses
	}
	return &ResolverService{resolver: resolver, policy: policy, timeout: timeout, maxAddresses: maxAddresses}
}

// Resolve accepts an IP literal or a domain and returns the selectable numeric
// destinations. Errors are stable API errors suitable for the wire.
func (s *ResolverService) Resolve(ctx context.Context, raw string) (*model.ResolveResponse, *model.APIError) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, model.NewError(model.ErrInvalidRequest, "target is required")
	}
	if len(input) > 260 {
		return nil, model.NewError(model.ErrInvalidRequest, "target is too long")
	}
	if !utf8.ValidString(input) {
		return nil, model.NewError(model.ErrInvalidRequest, "target is not valid UTF-8")
	}
	for _, r := range input {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return nil, model.NewError(model.ErrInvalidRequest, "target contains invalid characters")
		}
	}

	// Bracketed IPv6 literal. Brackets are only legal around an IPv6 literal.
	literal := input
	if strings.HasPrefix(input, "[") || strings.HasSuffix(input, "]") {
		if !strings.HasPrefix(input, "[") || !strings.HasSuffix(input, "]") || len(input) < 3 {
			return nil, model.NewError(model.ErrInvalidRequest, "target has an invalid bracket form")
		}
		literal = input[1 : len(input)-1]
		if !strings.Contains(literal, ":") {
			return nil, model.NewError(model.ErrInvalidRequest, "brackets are only valid around an IPv6 address")
		}
	} else if strings.ContainsAny(input, "[]") {
		return nil, model.NewError(model.ErrInvalidRequest, "target has an invalid bracket form")
	}

	if addr, err := netip.ParseAddr(literal); err == nil {
		addr = addr.Unmap()
		if addr.Zone() != "" {
			return nil, model.NewError(model.ErrInvalidRequest, "target must not contain a zone identifier")
		}
		if err := s.policy.CheckAddr(addr); err != nil {
			return nil, model.NewError(model.ErrTargetRejected, err.Error())
		}
		return &model.ResolveResponse{
			Input: input,
			Kind:  "ip",
			Addresses: []model.ResolvedAddress{
				{IP: addr.String(), Family: model.FamilyOf(addr)},
			},
			RequiresSelection: false,
		}, nil
	}

	// Everything else must be a valid domain name. This rejects URLs, shell
	// fragments, host:port pairs and malformed/numeric fake IPv4 literals.
	ascii, apiErr := validateDomainTarget(input)
	if apiErr != nil {
		return nil, apiErr
	}

	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	type lookupResult struct {
		addrs []netip.Addr
		err   error
	}
	results := make(chan lookupResult, 2)
	go func() {
		addrs, err := s.resolver.LookupNetIP(lookupCtx, "ip4", ascii)
		results <- lookupResult{addrs: addrs, err: err}
	}()
	go func() {
		addrs, err := s.resolver.LookupNetIP(lookupCtx, "ip6", ascii)
		results <- lookupResult{addrs: addrs, err: err}
	}()

	var (
		rawAddrs []netip.Addr
		firstErr error
		errCount int
	)
	for i := 0; i < 2; i++ {
		res := <-results
		if res.err != nil {
			errCount++
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		rawAddrs = append(rawAddrs, res.addrs...)
	}

	filtered, truncated := s.filterAndSort(rawAddrs)
	if len(filtered) == 0 {
		// An error that prevented us from learning addresses is a lookup
		// failure; a successful lookup with no usable (or no policy-allowed)
		// addresses is no_addresses.
		if len(rawAddrs) == 0 && errCount > 0 {
			if errors.Is(firstErr, context.DeadlineExceeded) || errors.Is(lookupCtx.Err(), context.DeadlineExceeded) {
				return nil, model.NewError(model.ErrDNSError, "DNS lookup timed out")
			}
			if errors.Is(firstErr, context.Canceled) || errors.Is(lookupCtx.Err(), context.Canceled) {
				return nil, model.NewError(model.ErrDNSError, "DNS lookup was cancelled")
			}
			return nil, model.NewError(model.ErrDNSError, "DNS lookup failed")
		}
		return nil, model.NewError(model.ErrNoAddresses, "domain has no usable A or AAAA records")
	}

	addresses := make([]model.ResolvedAddress, 0, len(filtered))
	for _, addr := range filtered {
		addresses = append(addresses, model.ResolvedAddress{IP: addr.String(), Family: model.FamilyOf(addr)})
	}
	return &model.ResolveResponse{
		Input:             input,
		Kind:              "domain",
		Addresses:         addresses,
		RequiresSelection: len(addresses) > 1,
		Truncated:         truncated,
		Warnings:          []string{resolverWarning},
	}, nil
}

// validateDomainTarget normalizes and validates a domain target, returning its
// ASCII (punycode) form.
func validateDomainTarget(input string) (string, *model.APIError) {
	name := input
	// A single trailing dot is a valid absolute DNS name; normalize it away.
	if strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" {
		return "", model.NewError(model.ErrInvalidRequest, "target is required")
	}
	for _, r := range name {
		if r > unicode.MaxASCII {
			// Non-ASCII is allowed for IDN; idna validates it below.
			continue
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-':
		default:
			return "", model.NewError(model.ErrInvalidRequest, "target must be an IP address or a domain name")
		}
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", model.NewError(model.ErrInvalidRequest, "target must be an IP address or a domain name")
	}
	allNumeric := true
	for _, label := range labels {
		if label == "" {
			return "", model.NewError(model.ErrInvalidRequest, "target contains an empty DNS label")
		}
		if strings.Trim(label, "0123456789") != "" {
			allNumeric = false
		}
	}
	if allNumeric {
		return "", model.NewError(model.ErrInvalidRequest, "target looks like an invalid IP address")
	}

	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", model.NewError(model.ErrInvalidRequest, "target is not a valid domain name")
	}
	ascii = strings.ToLower(ascii)
	if ascii == "" || len(ascii) > 253 {
		return "", model.NewError(model.ErrInvalidRequest, "target is not a valid domain name")
	}
	asciiLabels := strings.Split(ascii, ".")
	if len(asciiLabels) < 2 {
		return "", model.NewError(model.ErrInvalidRequest, "target must be an IP address or a domain name")
	}
	for _, label := range asciiLabels {
		if len(label) == 0 || len(label) > 63 {
			return "", model.NewError(model.ErrInvalidRequest, "target is not a valid domain name")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", model.NewError(model.ErrInvalidRequest, "target is not a valid domain name")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}
			return "", model.NewError(model.ErrInvalidRequest, "target is not a valid domain name")
		}
	}
	return ascii, nil
}

// filterAndSort unmaps, deduplicates, policy-filters and orders addresses
// (IPv4 first, then IPv6), capping at the configured maximum.
func (s *ResolverService) filterAndSort(addrs []netip.Addr) ([]netip.Addr, bool) {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	var v4, v6 []netip.Addr
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		if addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if _, dup := seen[addr]; dup {
			continue
		}
		if err := s.policy.CheckAddr(addr); err != nil {
			continue
		}
		seen[addr] = struct{}{}
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Less(v6[j]) })
	all := append(v4, v6...)
	truncated := false
	if len(all) > s.maxAddresses {
		all = all[:s.maxAddresses]
		truncated = true
	}
	return all, truncated
}

// ParseTargetIP validates a user-supplied numeric target IP for the job API.
// The Controller never trusts a previous /resolve call.
func ParseTargetIP(policy ipguard.Policy, raw string) (netip.Addr, *model.APIError) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, model.NewError(model.ErrInvalidRequest, "target_ip is required")
	}
	addr, err := policy.Check(s)
	if err != nil {
		var rejection *ipguard.Rejection
		if errors.As(err, &rejection) {
			return netip.Addr{}, model.NewError(model.ErrTargetRejected, rejection.Error())
		}
		return netip.Addr{}, model.NewError(model.ErrTargetRejected, "destination rejected")
	}
	return addr, nil
}

// targetIPFamily is a small helper used by job validation.
func targetIPFamily(addr netip.Addr) model.IPFamily { return model.FamilyOf(addr) }
