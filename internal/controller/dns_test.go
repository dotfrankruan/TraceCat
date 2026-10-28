package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/model"
)

type fakeResolver struct {
	mu    sync.Mutex
	calls []string
	fn    func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.calls = append(f.calls, network+":"+host)
	f.mu.Unlock()
	if f.fn == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return f.fn(ctx, network, host)
}

func (f *fakeResolver) callHosts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newTestResolverService(resolver Resolver, timeout time.Duration, maxAddresses int) *ResolverService {
	policy, err := ipguard.NewPolicy(nil)
	if err != nil {
		panic(err)
	}
	return NewResolverService(resolver, policy, timeout, maxAddresses)
}

func mustAddrs(t *testing.T, addrs ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			t.Fatalf("parse %q: %v", a, err)
		}
		out = append(out, addr)
	}
	return out
}

func TestResolveLiteralIPs(t *testing.T) {
	svc := newTestResolverService(&fakeResolver{}, time.Second, 16)
	cases := []struct {
		name   string
		input  string
		wantIP string
		family model.IPFamily
	}{
		{"ipv4", "8.8.8.8", "8.8.8.8", model.FamilyIPv4},
		{"ipv6", "2606:4700:4700::1111", "2606:4700:4700::1111", model.FamilyIPv6},
		{"bracketed ipv6", "[2606:4700:4700::1111]", "2606:4700:4700::1111", model.FamilyIPv6},
		{"mapped ipv6", "::ffff:8.8.8.8", "8.8.8.8", model.FamilyIPv4},
		{"padded ipv4", " 8.8.8.8 ", "8.8.8.8", model.FamilyIPv4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.Resolve(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if resp.Kind != "ip" || len(resp.Addresses) != 1 {
				t.Fatalf("unexpected response: %+v", resp)
			}
			if resp.Addresses[0].IP != tc.wantIP || resp.Addresses[0].Family != tc.family {
				t.Fatalf("unexpected address: %+v", resp.Addresses[0])
			}
			if resp.RequiresSelection || resp.Truncated {
				t.Fatalf("literal IP must not require selection: %+v", resp)
			}
		})
	}

	for _, rejected := range []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "2001:db8::1", "fc00::1", "fe80::1", "::1"} {
		resp, err := svc.Resolve(context.Background(), rejected)
		if err == nil {
			t.Fatalf("expected %q to be rejected, got %+v", rejected, resp)
		}
		if err.Code != model.ErrTargetRejected {
			t.Fatalf("expected target_rejected for %q, got %v", rejected, err.Code)
		}
	}
}

func TestResolveDomainMultipleSortedAndDeduped(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		switch network {
		case "ip4":
			return mustAddrs(t, "8.8.8.8", "1.1.1.1", "8.8.8.8"), nil
		case "ip6":
			return mustAddrs(t, "2606:4700:4700::1111", "::ffff:8.8.8.8"), nil
		}
		return nil, errors.New("unexpected network")
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	resp, err := svc.Resolve(context.Background(), "Example.COM")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp.Kind != "domain" || !resp.RequiresSelection || resp.Truncated {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Addresses) != 3 {
		t.Fatalf("expected 3 deduped addresses, got %+v", resp.Addresses)
	}
	want := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for i, addr := range resp.Addresses {
		if addr.IP != want[i] {
			t.Fatalf("address %d = %q, want %q", i, addr.IP, want[i])
		}
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "CDN and GeoDNS") {
		t.Fatalf("missing CDN warning: %+v", resp.Warnings)
	}
	for _, call := range resolver.callHosts() {
		if call != "ip4:example.com" && call != "ip6:example.com" {
			t.Fatalf("unexpected resolver call %q", call)
		}
	}
}

func TestResolveSingleResultNoSelection(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		if network == "ip4" {
			return mustAddrs(t, "93.184.216.34"), nil
		}
		return nil, nil
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	resp, err := svc.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resp.RequiresSelection || len(resp.Addresses) != 1 {
		t.Fatalf("single result must not require selection: %+v", resp)
	}
}

func TestResolveIDN(t *testing.T) {
	var (
		mu       sync.Mutex
		lookedUp string
	)
	resolver := &fakeResolver{fn: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		mu.Lock()
		lookedUp = host
		mu.Unlock()
		if network == "ip4" {
			return mustAddrs(t, "93.184.216.34"), nil
		}
		return nil, nil
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	resp, err := svc.Resolve(context.Background(), "bücher.example")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	mu.Lock()
	got := lookedUp
	mu.Unlock()
	if got != "xn--bcher-kva.example" {
		t.Fatalf("IDN was not converted: %q", got)
	}
	if resp.Input != "bücher.example" {
		t.Fatalf("input should be echoed: %q", resp.Input)
	}
}

func TestResolveNoAddresses(t *testing.T) {
	resolver := &fakeResolver{fn: func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, nil
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	_, err := svc.Resolve(context.Background(), "example.com")
	if err == nil || err.Code != model.ErrNoAddresses {
		t.Fatalf("expected no_addresses, got %v", err)
	}
}

func TestResolvePolicyFilteredDomains(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		if network == "ip4" {
			return mustAddrs(t, "10.0.0.1", "192.168.1.1", "127.0.0.1", "8.8.8.8"), nil
		}
		return mustAddrs(t, "2001:db8::1", "fc00::1", "2606:4700:4700::1111"), nil
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	resp, err := svc.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Addresses) != 2 || resp.Addresses[0].IP != "8.8.8.8" || resp.Addresses[1].IP != "2606:4700:4700::1111" {
		t.Fatalf("policy filtering failed: %+v", resp.Addresses)
	}

	// All addresses filtered out by policy => no_addresses.
	allPrivate := &fakeResolver{fn: func(context.Context, string, string) ([]netip.Addr, error) {
		return mustAddrs(t, "10.0.0.1", "fc00::1"), nil
	}}
	svc = newTestResolverService(allPrivate, time.Second, 16)
	_, err = svc.Resolve(context.Background(), "internal.example")
	if err == nil || err.Code != model.ErrNoAddresses {
		t.Fatalf("expected no_addresses after policy filtering, got %v", err)
	}
}

func TestResolveResolverFailure(t *testing.T) {
	resolver := &fakeResolver{fn: func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	_, err := svc.Resolve(context.Background(), "example.com")
	if err == nil || err.Code != model.ErrDNSError {
		t.Fatalf("expected dns_failure, got %v", err)
	}
}

func TestResolvePartialResolverFailureStillSucceeds(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		if network == "ip4" {
			return mustAddrs(t, "8.8.8.8"), nil
		}
		return nil, errors.New("aaaa lookup failed")
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	resp, err := svc.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Addresses) != 1 || resp.Addresses[0].IP != "8.8.8.8" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestResolveTimeout(t *testing.T) {
	resolver := &fakeResolver{fn: func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	svc := newTestResolverService(resolver, 50*time.Millisecond, 16)
	start := time.Now()
	_, err := svc.Resolve(context.Background(), "example.com")
	if err == nil || err.Code != model.ErrDNSError {
		t.Fatalf("expected dns_failure, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout was not bounded")
	}
}

func TestResolveMaxAddressesTruncation(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, _ string) ([]netip.Addr, error) {
		if network == "ip4" {
			return mustAddrs(t, "8.8.8.8", "1.1.1.1", "9.9.9.9"), nil
		}
		return mustAddrs(t, "2606:4700:4700::1111"), nil
	}}
	svc := newTestResolverService(resolver, time.Second, 2)
	resp, err := svc.Resolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Addresses) != 2 || !resp.Truncated {
		t.Fatalf("expected truncation to 2: %+v", resp)
	}
}

func TestResolveInvalidTargets(t *testing.T) {
	svc := newTestResolverService(&fakeResolver{}, time.Second, 16)
	invalid := []string{
		"",
		"   ",
		"http://example.com",
		"https://example.com/path",
		"example.com;rm -rf /",
		"example.com|cat",
		"example.com$(id)",
		"user@example.com",
		"example.com:443",
		"999.1.1.1",
		"1.2.3.999",
		"256.1.1.1",
		"localhost",
		"single",
		"exa\nmple.com",
		"exa mple.com",
		"example..com",
		".example.com",
		"-bad.example",
		"bad-.example",
		"foo_bar.example",
		"[not-ipv6]",
		"[8.8.8.8]",
		"2001:db8::1%eth0",
	}
	for _, input := range invalid {
		t.Run(strings.ReplaceAll(input, "/", "_"), func(t *testing.T) {
			resp, err := svc.Resolve(context.Background(), input)
			if err == nil {
				t.Fatalf("expected rejection for %q, got %+v", input, resp)
			}
			if err.Code != model.ErrInvalidRequest && err.Code != model.ErrTargetRejected {
				t.Fatalf("expected invalid_request/target_rejected for %q, got %v", input, err.Code)
			}
		})
	}
}

func TestResolveTrailingDot(t *testing.T) {
	resolver := &fakeResolver{fn: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if host != "example.com" {
			t.Fatalf("unexpected lookup host %q", host)
		}
		if network == "ip4" {
			return mustAddrs(t, "8.8.8.8"), nil
		}
		return nil, nil
	}}
	svc := newTestResolverService(resolver, time.Second, 16)
	if _, err := svc.Resolve(context.Background(), "example.com."); err != nil {
		t.Fatalf("trailing dot should be accepted: %v", err)
	}
}

func TestParseTargetIPRejectsPrivate(t *testing.T) {
	policy, err := ipguard.NewPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, apiErr := ParseTargetIP(policy, "10.1.2.3"); apiErr == nil || apiErr.Code != model.ErrTargetRejected {
		t.Fatalf("expected target_rejected, got %v", apiErr)
	}
	addr, apiErr := ParseTargetIP(policy, "::ffff:8.8.8.8")
	if apiErr != nil {
		t.Fatalf("ParseTargetIP: %v", apiErr)
	}
	if addr.String() != "8.8.8.8" {
		t.Fatalf("mapped address not unmapped: %s", addr)
	}
}
