package nexttrace

import (
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dotfrankruan/tracecat/internal/model"
)

func TestBuildArgsExactVectors(t *testing.T) {
	t.Parallel()
	v6 := mustAddr("2606:4700:4700::1111")

	cases := []struct {
		name  string
		flags Flags
		spec  Spec
		want  []string
	}{
		{
			name: "ipv4 v1.7.1 example",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
			},
			spec: ipv4Spec(),
			want: []string{"-4", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"},
		},
		{
			name: "ipv6 with traceroute and limits",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true,
				Timeout: true, Traceroute: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: protocolICMP,
				MaxHops: 64, Queries: 5, ProbeTimeoutMS: 3000,
			},
			want: []string{"-6", "--traceroute", "--json", "-q", "5", "-m", "64", "--timeout", "3000", "2606:4700:4700::1111"},
		},
		{
			name: "ipv6 v1.7.1 example",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: protocolICMP,
				MaxHops: 30, Queries: 3, ProbeTimeoutMS: 1000,
			},
			want: []string{"-6", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "2606:4700:4700::1111"},
		},
		{
			name: "ipv4 icmp with source interface",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
				DeviceShort: true,
			},
			spec: func() Spec {
				spec := ipv4Spec()
				spec.Interface = "eth0"
				return spec
			}(),
			want: []string{"-4", "-D", "eth0", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "1.1.1.1"},
		},
		{
			name: "ipv4 tcp with source interface and traceroute",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
				TCPShort: true, UDPShort: true, PortShort: true,
				DeviceShort: true, Traceroute: true,
			},
			spec: func() Spec {
				spec := tcpSpec()
				spec.Interface = "eth0"
				return spec
			}(),
			want: []string{"-4", "-T", "-D", "eth0", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "443", "1.1.1.1"},
		},
		{
			name: "ipv6 udp with long device flag",
			flags: Flags{
				JSON: true, IPv4Long: true, IPv6Long: true,
				MaxHopsLong: true, QueriesLong: true, Timeout: true,
				UDPLong: true, PortLong: true, DeviceLong: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: model.ProtocolUDP,
				Port: intPtr(model.DefaultUDPPort), Interface: "eth0",
				MaxHops: 16, Queries: 2, ProbeTimeoutMS: 500,
			},
			want: []string{"--ipv6", "--udp", "--dev", "eth0", "--json", "--queries", "2", "--max-hops", "16", "--timeout", "500", "--port", "33494", "2606:4700:4700::1111"},
		},
		{
			name: "ipv4 tcp with destination port",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
				TCPShort: true, UDPShort: true, PortShort: true,
			},
			spec: tcpSpec(),
			want: []string{"-4", "-T", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "443", "1.1.1.1"},
		},
		{
			name: "ipv4 udp with destination port and traceroute",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
				TCPShort: true, UDPShort: true, PortShort: true, Traceroute: true,
			},
			spec: udpSpec(),
			want: []string{"-4", "-U", "--traceroute", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "33494", "1.1.1.1"},
		},
		{
			name: "ipv6 udp with destination port",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true, Timeout: true,
				TCPShort: true, UDPShort: true, PortShort: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: model.ProtocolUDP,
				Port: intPtr(model.DefaultUDPPort), MaxHops: 30, Queries: 3, ProbeTimeoutMS: 1000,
			},
			want: []string{"-6", "-U", "--json", "-q", "3", "-m", "30", "--timeout", "1000", "-p", "33494", "2606:4700:4700::1111"},
		},
		{
			name: "ipv6 tcp with long flag spellings",
			flags: Flags{
				JSON: true, IPv4Long: true, IPv6Long: true,
				MaxHopsLong: true, QueriesLong: true, Timeout: true,
				TCPLong: true, UDPLong: true, PortLong: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: model.ProtocolTCP,
				Port: intPtr(80), MaxHops: 16, Queries: 2, ProbeTimeoutMS: 500,
			},
			want: []string{"--ipv6", "--tcp", "--json", "--queries", "2", "--max-hops", "16", "--timeout", "500", "--port", "80", "2606:4700:4700::1111"},
		},
		{
			name: "no timeout capability",
			flags: Flags{
				JSON: true, IPv4: true, IPv6: true,
				MaxHopsShort: true, QueriesShort: true,
			},
			spec: ipv4Spec(),
			want: []string{"-4", "--json", "-q", "3", "-m", "30", "1.1.1.1"},
		},
		{
			name: "long flag spellings only",
			flags: Flags{
				JSON: true, IPv4Long: true, IPv6Long: true,
				MaxHopsLong: true, QueriesLong: true, Timeout: true,
			},
			spec: Spec{
				Addr: v6, Family: model.FamilyIPv6, Protocol: protocolICMP,
				MaxHops: 16, Queries: 2, ProbeTimeoutMS: 500,
			},
			want: []string{"--ipv6", "--json", "--queries", "2", "--max-hops", "16", "--timeout", "500", "2606:4700:4700::1111"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caps := Capabilities{Version: "v1.7.1", Flags: tc.flags}
			got, err := caps.BuildArgs(tc.spec)
			if err != nil {
				t.Fatalf("BuildArgs: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("argv = %v, want %v", got, tc.want)
			}
			assertSafeArgv(t, got)
		})
	}
}

func TestBuildArgsTargetIsLastAndCanonical(t *testing.T) {
	t.Parallel()
	caps := capableCapabilities()
	for _, in := range []string{
		"1.1.1.1",
		"2606:4700:4700:0:0:0:0:1111",
		"2001:4860:4860::8888",
		"::ffff:1.1.1.1",
	} {
		addr := mustAddr(in)
		spec := Spec{
			Addr: addr, Family: model.FamilyOf(addr), Protocol: protocolICMP,
			MaxHops: 30, Queries: 3, ProbeTimeoutMS: 1000,
		}
		argv, err := caps.BuildArgs(spec)
		if err != nil {
			t.Fatalf("BuildArgs(%q): %v", in, err)
		}
		if last := argv[len(argv)-1]; last != addr.String() {
			t.Fatalf("last arg = %q, want canonical %q", last, addr.String())
		}
		if addr.String() == in && netip.MustParseAddr(in).Unmap().String() != in {
			t.Fatalf("test fixture %q is not canonical", in)
		}
	}
}

func TestBuildArgsRejectsInvalidSpecs(t *testing.T) {
	t.Parallel()
	caps := capableCapabilities()
	valid := ipv4Spec()

	mutated := func(mutate func(*Spec)) Spec {
		spec := valid
		mutate(&spec)
		return spec
	}

	cases := map[string]Spec{
		"zero address":          mutated(func(s *Spec) { s.Addr = netip.Addr{} }),
		"unmapped mapped addr":  mutated(func(s *Spec) { s.Addr = netip.MustParseAddr("::ffff:1.1.1.1") }),
		"family mismatch":       mutated(func(s *Spec) { s.Family = model.FamilyIPv6 }),
		"unsupported protocol":  mutated(func(s *Spec) { s.Protocol = "sctp" }),
		"max hops zero":         mutated(func(s *Spec) { s.MaxHops = 0 }),
		"max hops too large":    mutated(func(s *Spec) { s.MaxHops = 65 }),
		"queries zero":          mutated(func(s *Spec) { s.Queries = 0 }),
		"queries too large":     mutated(func(s *Spec) { s.Queries = 6 }),
		"probe timeout too low": mutated(func(s *Spec) { s.ProbeTimeoutMS = 50 }),
		"probe timeout high":    mutated(func(s *Spec) { s.ProbeTimeoutMS = 60_001 }),
	}
	for name, spec := range cases {
		spec := spec
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := caps.BuildArgs(spec); err == nil {
				t.Fatalf("BuildArgs(%+v) = nil error, want rejection", spec)
			}
		})
	}

	if _, err := (Capabilities{}).BuildArgs(valid); err == nil {
		t.Fatal("BuildArgs with unavailable capabilities = nil error, want rejection")
	}
}

func TestBuildArgsInterfaceRejections(t *testing.T) {
	t.Parallel()

	noDeviceCaps := Capabilities{Version: "v1.7.3", Flags: Flags{
		JSON: true, IPv4: true, IPv6: true,
		MaxHopsShort: true, QueriesShort: true, Timeout: true,
	}}
	withInterface := func(name string) Spec {
		spec := ipv4Spec()
		spec.Interface = name
		return spec
	}

	t.Run("device selection unsupported", func(t *testing.T) {
		t.Parallel()
		if _, err := noDeviceCaps.BuildArgs(withInterface("eth0")); err == nil {
			t.Fatal("BuildArgs = nil error without -D/--dev capability")
		}
	})

	for name, iface := range map[string]string{
		"path traversal":       "../../etc/passwd",
		"shell metachar":       "eth0; touch /tmp/pwned",
		"command substitution": "eth0$(id)",
		"whitespace":           "eth 0",
		"too long":             strings.Repeat("e", 16),
		"invalid leading":      "-D",
	} {
		iface := iface
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := capableCapabilities().BuildArgs(withInterface(iface)); err == nil {
				t.Fatalf("BuildArgs(interface=%q) = nil error, want rejection", iface)
			}
		})
	}
}

func TestBuildArgsAutomaticRoutingHasNoDeviceFlag(t *testing.T) {
	t.Parallel()
	caps := capableCapabilities()
	argv, err := caps.BuildArgs(ipv4Spec())
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	for _, arg := range argv {
		if arg == "-D" || arg == "--dev" {
			t.Fatalf("automatic routing argv contains a device flag: %v", argv)
		}
	}
}

func TestBuildArgsProtocolPortRejections(t *testing.T) {
	t.Parallel()

	fullFlags := Flags{
		JSON: true, IPv4: true, IPv6: true,
		MaxHopsShort: true, QueriesShort: true, Timeout: true,
		TCPShort: true, UDPShort: true, PortShort: true,
	}
	fullCaps := Capabilities{Version: "v1.7.3", Flags: fullFlags}

	tcpNoPort := tcpSpec()
	tcpNoPort.Port = nil
	udpNoPort := udpSpec()
	udpNoPort.Port = nil
	tcpZero := tcpSpec()
	tcpZero.Port = intPtr(0)
	tcpTooHigh := tcpSpec()
	tcpTooHigh.Port = intPtr(65536)
	icmpWithPort := ipv4Spec()
	icmpWithPort.Port = intPtr(443)

	cases := map[string]Spec{
		"tcp missing port":   tcpNoPort,
		"udp missing port":   udpNoPort,
		"tcp port zero":      tcpZero,
		"tcp port above max": tcpTooHigh,
		"port on icmp":       icmpWithPort,
	}
	for name, spec := range cases {
		spec := spec
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := fullCaps.BuildArgs(spec); err == nil {
				t.Fatalf("BuildArgs(%+v) = nil error, want rejection", spec)
			}
		})
	}

	t.Run("tcp unsupported by binary", func(t *testing.T) {
		t.Parallel()
		caps := Capabilities{Version: "v1.7.3", Flags: Flags{
			JSON: true, IPv4: true, IPv6: true,
			MaxHopsShort: true, QueriesShort: true, Timeout: true,
		}}
		if _, err := caps.BuildArgs(tcpSpec()); err == nil {
			t.Fatal("BuildArgs(tcp) = nil error for an ICMP-only binary")
		}
	})

	t.Run("tcp without port capability", func(t *testing.T) {
		t.Parallel()
		caps := Capabilities{Version: "v1.7.3", Flags: Flags{
			JSON: true, IPv4: true, IPv6: true,
			MaxHopsShort: true, QueriesShort: true, Timeout: true,
			TCPShort: true, UDPShort: true,
		}}
		if _, err := caps.BuildArgs(tcpSpec()); err == nil {
			t.Fatal("BuildArgs(tcp) = nil error without a destination-port flag")
		}
	})
}

func TestBuildArgsPortBoundaries(t *testing.T) {
	t.Parallel()
	caps := capableCapabilities()
	for _, port := range []int{model.MinPort, model.DefaultTCPPort, model.MaxPort} {
		spec := tcpSpec()
		spec.Port = intPtr(port)
		argv, err := caps.BuildArgs(spec)
		if err != nil {
			t.Fatalf("BuildArgs(port=%d): %v", port, err)
		}
		if got := argv[len(argv)-2]; got != strconv.Itoa(port) {
			t.Fatalf("port argument = %q, want %d (argv %v)", got, port, argv)
		}
		if argv[len(argv)-1] != spec.Addr.String() {
			t.Fatalf("target is not last: %v", argv)
		}
	}
}

func TestBuildArgsICMPNeverCarriesPort(t *testing.T) {
	t.Parallel()
	caps := capableCapabilities()
	for _, family := range []model.IPFamily{model.FamilyIPv4, model.FamilyIPv6} {
		addr := mustAddr("1.1.1.1")
		if family == model.FamilyIPv6 {
			addr = mustAddr("2606:4700:4700::1111")
		}
		spec := Spec{
			Addr: addr, Family: family, Protocol: model.ProtocolICMP,
			MaxHops: 30, Queries: 3, ProbeTimeoutMS: 1000,
		}
		argv, err := caps.BuildArgs(spec)
		if err != nil {
			t.Fatalf("BuildArgs(%s): %v", family, err)
		}
		for _, arg := range argv {
			if arg == "-p" || arg == "--port" {
				t.Fatalf("icmp argv contains a port flag: %v", argv)
			}
		}
		if spec.Port != nil {
			t.Fatal("test setup error: ICMP spec carries a port")
		}
	}
}

func TestMinimalEnvIsFixedAndMinimal(t *testing.T) {
	t.Setenv("TRACECAT_AGENT_TOKEN", "super-secret-token-value")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "also-secret")
	env := minimalEnv()
	wantKeys := map[string]bool{"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "NO_COLOR": true}
	if len(env) != len(wantKeys) {
		t.Fatalf("env has %d entries, want %d: %v", len(env), len(wantKeys), env)
	}
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("malformed env entry %q", entry)
		}
		if !wantKeys[key] {
			t.Fatalf("unexpected inherited environment variable %q", key)
		}
		if strings.Contains(entry, "secret") || strings.Contains(entry, "SECRET") {
			t.Fatalf("environment entry leaks a secret: %q", entry)
		}
	}
}

func assertSafeArgv(t *testing.T, argv []string) {
	t.Helper()
	metacharacters := ";|&$`\"'<>(){}[]\\\n\r\t "
	for _, arg := range argv {
		if strings.ContainsAny(arg, metacharacters) {
			t.Fatalf("argument %q contains shell metacharacters", arg)
		}
	}
}
