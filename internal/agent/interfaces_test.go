package agent

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func testNetInterface(t *testing.T, name string, up, loopback bool, addrs ...string) netInterface {
	t.Helper()
	parsed := make([]netip.Addr, 0, len(addrs))
	for _, raw := range addrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		parsed = append(parsed, addr.Unmap())
	}
	return netInterface{Name: name, Up: up, Loopback: loopback, Addrs: parsed}
}

func interfaceSourceOf(items ...netInterface) interfaceSource {
	return func() ([]netInterface, error) { return items, nil }
}

func TestEnumerateInterfacesFilters(t *testing.T) {
	t.Parallel()
	source := interfaceSourceOf(
		testNetInterface(t, "eth0", true, false, "192.168.1.10"),
		testNetInterface(t, "ens5", true, false, "2001:db8::5"),
		testNetInterface(t, "lo", true, true, "127.0.0.1"),
		testNetInterface(t, "eth1", false, false, "10.0.0.1"),
		testNetInterface(t, "docker0", true, false, "172.17.0.1"),
		testNetInterface(t, "veth1234", true, false, "10.1.0.2"),
		testNetInterface(t, "br-abcd", true, false, "172.18.0.1"),
		testNetInterface(t, "virbr0", true, false, "192.168.122.1"),
		testNetInterface(t, "cni0", true, false, "10.244.0.1"),
		testNetInterface(t, "flannel.1", true, false, "10.244.0.0"),
		testNetInterface(t, "calico123", true, false, "10.2.0.1"),
		testNetInterface(t, "podman0", true, false, "10.88.0.1"),
		testNetInterface(t, "lxcbr0", true, false, "10.0.3.1"),
		testNetInterface(t, "lxdbr0", true, false, "10.0.4.1"),
		testNetInterface(t, "kube-ipvs0", true, false, "10.96.0.1"),
		testNetInterface(t, "eth2", true, false, "fe80::1"),
		testNetInterface(t, "eth3", true, false, "169.254.1.1"),
	)

	got, err := enumerateInterfaces(InterfacesConfig{}, source)
	if err != nil {
		t.Fatalf("enumerateInterfaces: %v", err)
	}
	want := []string{"ens5", "eth0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interfaces = %v, want %v", got, want)
	}
}

func TestEnumerateInterfacesStableSorted(t *testing.T) {
	t.Parallel()
	source := interfaceSourceOf(
		testNetInterface(t, "zeta0", true, false, "10.0.0.3"),
		testNetInterface(t, "alpha0", true, false, "10.0.0.1"),
		testNetInterface(t, "middle0", true, false, "10.0.0.2"),
	)
	first, err := enumerateInterfaces(InterfacesConfig{}, source)
	if err != nil {
		t.Fatalf("enumerateInterfaces: %v", err)
	}
	second, err := enumerateInterfaces(InterfacesConfig{}, source)
	if err != nil {
		t.Fatalf("enumerateInterfaces: %v", err)
	}
	want := []string{"alpha0", "middle0", "zeta0"}
	if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
		t.Fatalf("interfaces = %v / %v, want stable %v", first, second, want)
	}
}

func TestEnumerateInterfacesExcludeExtensionAndIncludeOverride(t *testing.T) {
	t.Parallel()
	source := interfaceSourceOf(
		testNetInterface(t, "eth0", true, false, "192.168.1.10"),
		testNetInterface(t, "ens5", true, false, "192.168.1.11"),
		testNetInterface(t, "docker0", true, false, "172.17.0.1"),
	)

	excluded, err := enumerateInterfaces(InterfacesConfig{Exclude: []string{"ens*"}}, source)
	if err != nil {
		t.Fatalf("enumerateInterfaces excluded: %v", err)
	}
	if !reflect.DeepEqual(excluded, []string{"eth0"}) {
		t.Fatalf("excluded interfaces = %v, want [eth0]", excluded)
	}

	included, err := enumerateInterfaces(InterfacesConfig{Include: []string{"docker0"}}, source)
	if err != nil {
		t.Fatalf("enumerateInterfaces include: %v", err)
	}
	if !reflect.DeepEqual(included, []string{"docker0", "ens5", "eth0"}) {
		t.Fatalf("included interfaces = %v, want docker0 override", included)
	}
}

func TestEnumerateInterfacesIncludeValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		source  interfaceSource
		include []string
	}{
		"missing": {
			source:  interfaceSourceOf(testNetInterface(t, "eth0", true, false, "192.168.1.10")),
			include: []string{"eth9"},
		},
		"down": {
			source:  interfaceSourceOf(testNetInterface(t, "eth1", false, false, "192.168.1.11")),
			include: []string{"eth1"},
		},
		"loopback": {
			source:  interfaceSourceOf(testNetInterface(t, "lo", true, true, "127.0.0.1")),
			include: []string{"lo"},
		},
		"no usable address": {
			source:  interfaceSourceOf(testNetInterface(t, "eth2", true, false, "fe80::1")),
			include: []string{"eth2"},
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := enumerateInterfaces(InterfacesConfig{Include: tc.include}, tc.source); err == nil {
				t.Fatalf("enumerateInterfaces = nil error for %s include", name)
			}
		})
	}

	t.Run("source error", func(t *testing.T) {
		t.Parallel()
		source := func() ([]netInterface, error) { return nil, errors.New("boom") }
		if _, err := enumerateInterfaces(InterfacesConfig{}, source); err == nil {
			t.Fatal("enumerateInterfaces = nil error, want source error")
		}
	})
}

func TestValidateInterfacesConfig(t *testing.T) {
	t.Parallel()
	if err := validateInterfacesConfig(InterfacesConfig{
		Exclude: []string{"ens*", "br-*"},
		Include: []string{"eth0", "ens5"},
	}); err != nil {
		t.Fatalf("valid interfaces config rejected: %v", err)
	}

	invalid := map[string]InterfacesConfig{
		"empty exclude pattern":     {Exclude: []string{""}},
		"space in exclude pattern":  {Exclude: []string{"docker *"}},
		"invalid exclude char":      {Exclude: []string{"docker!"}},
		"too long exclude pattern":  {Exclude: []string{strings.Repeat("a", 65)}},
		"duplicate exclude pattern": {Exclude: []string{"docker*", "docker*"}},
		"empty include name":        {Include: []string{""}},
		"space in include name":     {Include: []string{"eth 0"}},
		"invalid include chars":     {Include: []string{"eth0;id"}},
		"too long include name":     {Include: []string{strings.Repeat("e", 16)}},
		"duplicate include name":    {Include: []string{"eth0", "eth0"}},
	}
	for name, cfg := range invalid {
		cfg := cfg
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateInterfacesConfig(cfg); err == nil {
				t.Fatalf("validateInterfacesConfig(%+v) = nil error, want rejection", cfg)
			}
		})
	}
}
