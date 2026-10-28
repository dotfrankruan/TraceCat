package ipguard

import (
	"errors"
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestPolicyCheckAllowed(t *testing.T) {
	p, err := NewPolicy(nil)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
		"::ffff:1.1.1.1", // IPv4-mapped global address is unmapped and allowed
	}
	for _, in := range allowed {
		addr, err := p.Check(in)
		if err != nil {
			t.Errorf("Check(%q) = error %v, want allowed", in, err)
			continue
		}
		if !addr.Is4() && !addr.Is6() {
			t.Errorf("Check(%q) returned invalid addr", in)
		}
	}
}

func TestPolicyCheckIPv4Denied(t *testing.T) {
	p, _ := NewPolicy(nil)
	cases := []struct {
		ip     string
		reason Reason
	}{
		{"0.0.0.0", ReasonUnspecified},
		{"0.1.2.3", ReasonUnspecified},
		{"127.0.0.1", ReasonLoopback},
		{"127.255.255.254", ReasonLoopback},
		{"10.0.0.1", ReasonPrivate},
		{"172.16.5.4", ReasonPrivate},
		{"192.168.1.1", ReasonPrivate},
		{"169.254.169.254", ReasonLinkLocal},
		{"100.64.0.1", ReasonCGNAT},
		{"100.100.100.200", ReasonCGNAT},
		{"192.0.0.9", ReasonReserved},
		{"192.0.2.1", ReasonDocumentation},
		{"198.51.100.1", ReasonDocumentation},
		{"203.0.113.10", ReasonDocumentation},
		{"198.18.0.1", ReasonBenchmark},
		{"198.19.255.254", ReasonBenchmark},
		{"192.88.99.1", ReasonTransition},
		{"224.0.0.1", ReasonMulticast},
		{"239.255.255.250", ReasonMulticast},
		{"240.0.0.1", ReasonReserved},
		{"255.255.255.255", ReasonReserved},
	}
	for _, tc := range cases {
		_, err := p.Check(tc.ip)
		if err == nil {
			t.Errorf("Check(%q) = allowed, want rejected (%s)", tc.ip, tc.reason)
			continue
		}
		var rej *Rejection
		if !errors.As(err, &rej) {
			t.Errorf("Check(%q) error type = %T, want *Rejection", tc.ip, err)
			continue
		}
		if rej.Reason != tc.reason {
			t.Errorf("Check(%q) reason = %s, want %s", tc.ip, rej.Reason, tc.reason)
		}
	}
}

func TestPolicyCheckIPv6Denied(t *testing.T) {
	p, _ := NewPolicy(nil)
	cases := []struct {
		ip     string
		reason Reason
	}{
		{"::", ReasonUnspecified},
		{"::1", ReasonLoopback},
		{"fd00::1", ReasonPrivate},
		{"fd7a:115c:a1e0::1", ReasonPrivate},
		{"fe80::1", ReasonLinkLocal},
		{"ff02::1", ReasonMulticast},
		{"2001:db8::1", ReasonDocumentation},
		{"2001::1", ReasonTransition},
		{"2002::1", ReasonTransition},
		{"2001:2::1", ReasonBenchmark},
		{"64:ff9b::1.1.1.1", ReasonTransition},
		{"64:ff9b:1::1", ReasonTransition},
		{"100::1", ReasonReserved},
		{"3fff::1", ReasonDocumentation},
		{"5f00::1", ReasonReserved},
		{"4000::1", ReasonReserved}, // global-unicast bit set but outside 2000::/3
		{"::ffff:127.0.0.1", ReasonLoopback},
		{"::ffff:10.1.2.3", ReasonPrivate},
		{"::ffff:192.168.0.1", ReasonPrivate},
		{"::ffff:169.254.1.1", ReasonLinkLocal},
		{"::ffff:0.0.0.0", ReasonUnspecified},
	}
	for _, tc := range cases {
		_, err := p.Check(tc.ip)
		if err == nil {
			t.Errorf("Check(%q) = allowed, want rejected (%s)", tc.ip, tc.reason)
			continue
		}
		var rej *Rejection
		if !errors.As(err, &rej) {
			t.Errorf("Check(%q) error type = %T, want *Rejection", tc.ip, err)
			continue
		}
		if rej.Reason != tc.reason {
			t.Errorf("Check(%q) reason = %s, want %s", tc.ip, rej.Reason, tc.reason)
		}
	}
}

func TestPolicyCheckInvalidInput(t *testing.T) {
	p, _ := NewPolicy(nil)
	invalid := []string{
		"",
		" ",
		"example.com",
		"1.1.1.1:443",
		"http://1.1.1.1/",
		"1.1.1.1; touch /tmp/pwned",
		"1.1.1.1 $(id)",
		"1.1.1.1`id`",
		"0177.0.0.1",      // octal-looking dotted quad is not a valid netip.Addr
		"0x7f.0.0.1",      // hex-looking
		"1.1.1.1 ",        // trailing whitespace
		" 1.1.1.1",        // leading whitespace
		"1.1.1.1\n",       // newline injection
		"[2606:4700::1]",  // brackets are not part of a literal
		"fe80::1%lo0",     // zone identifiers are rejected
		"[fe80::1%25lo0]", // URL-escaped zone
		"999.999.999.999", // invalid IPv4
		"1.1.1",           // incomplete IPv4 is not an IP literal
		"--help",          // argument injection attempt
		"-4",
		"1.1.1.1\nX-Injected: 1",
		"example.com/../etc/passwd",
		"๑๑๑.๑๑๑.๑๑๑.๑๑๑", // Unicode digits
	}
	for _, in := range invalid {
		if _, err := p.Check(in); err == nil {
			t.Errorf("Check(%q) = allowed, want rejected", in)
		}
	}
}

func TestPolicyAllowlist(t *testing.T) {
	p, err := NewPolicy([]string{"192.168.50.0/24", "127.0.0.1/32", "fd00:dead:beef::/48"})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	allowed := []string{"192.168.50.7", "127.0.0.1", "fd00:dead:beef::1"}
	for _, in := range allowed {
		if _, err := p.Check(in); err != nil {
			t.Errorf("Check(%q) = %v, want allowed by allowlist", in, err)
		}
	}
	stillDenied := []string{"192.168.51.1", "10.0.0.1", "fd00:dead:beee::1", "::1"}
	for _, in := range stillDenied {
		if _, err := p.Check(in); err == nil {
			t.Errorf("Check(%q) = allowed, want rejected", in)
		}
	}
	if got := len(p.Allowlist()); got != 3 {
		t.Errorf("Allowlist length = %d, want 3", got)
	}
}

func TestNewPolicyRejectsDefaultRoute(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "", "not-a-cidr", "1.1.1.1", "300.0.0.0/8"} {
		if _, err := NewPolicy([]string{cidr}); err == nil {
			t.Errorf("NewPolicy(%q) = nil error, want rejection", cidr)
		}
	}
	if _, err := NewPolicy([]string{"0.0.0.0/0", "192.168.0.0/16"}); err == nil {
		t.Error("NewPolicy with default route alongside a valid CIDR = nil error, want rejection")
	}
}

func TestIsTailscaleAddr(t *testing.T) {
	cases := map[string]bool{
		"100.64.0.1":        true,
		"100.127.255.254":   true,
		"100.128.0.1":       false,
		"10.0.0.1":          false,
		"fd7a:115c:a1e0::1": true,
		"fd00::1":           false,
		"1.1.1.1":           false,
	}
	for ip, want := range cases {
		if got := IsTailscaleAddr(mustAddr(t, ip)); got != want {
			t.Errorf("IsTailscaleAddr(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestIsNonPublic(t *testing.T) {
	cases := map[string]bool{
		"1.1.1.1":         false,
		"2606:4700::1111": false,
		"127.0.0.1":       true,
		"10.1.2.3":        true,
		"100.64.0.5":      true,
		"192.168.1.1":     true,
		"169.254.1.1":     true,
		"2001:db8::1":     true,
		"fd00::1":         true,
		"fe80::1":         true,
		"::ffff:10.0.0.1": true,
	}
	for ip, want := range cases {
		if got := IsNonPublic(mustAddr(t, ip)); got != want {
			t.Errorf("IsNonPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.1.1.1", "1.1.1.1"},
		{"::ffff:1.1.1.1", "1.1.1.1"},
		{"2606:4700:4700:0000:0000:0000:0000:1111", "2606:4700:4700::1111"},
	}
	for _, tc := range cases {
		got, err := NormalizeIP(tc.in)
		if err != nil {
			t.Errorf("NormalizeIP(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("NormalizeIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
