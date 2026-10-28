package nexttrace

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const protocolICMP = model.ProtocolICMP

func mustAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr.Unmap()
}

func familyOf(addr netip.Addr) model.IPFamily { return model.FamilyOf(addr) }

var (
	fakeBuildOnce sync.Once
	fakeBuiltPath string
	fakeBuildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeBuiltPath != "" {
		_ = os.RemoveAll(filepath.Dir(fakeBuiltPath))
	}
	os.Exit(code)
}

// buildFake compiles the fake NextTrace program once per test binary and
// returns a path to a private copy for the current test.
func buildFake(t *testing.T) string {
	t.Helper()
	fakeBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "tracecat-fake-nexttrace-*")
		if err != nil {
			fakeBuildErr = err
			return
		}
		out := filepath.Join(dir, "fake-nexttrace")
		cmd := exec.Command("go", "build", "-o", out, "./testdata/fake")
		cmd.Dir = "."
		if output, err := cmd.CombinedOutput(); err != nil {
			fakeBuildErr = fmt.Errorf("go build testdata/fake: %v: %s", err, output)
			return
		}
		fakeBuiltPath = out
	})
	if fakeBuildErr != nil {
		t.Fatalf("building fake nexttrace: %v", fakeBuildErr)
	}

	dir := t.TempDir()
	dst := filepath.Join(dir, "fake-nexttrace")
	copyExecutable(t, fakeBuiltPath, dst)
	return dst
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading fake binary: %v", err)
	}
	if err := os.WriteFile(dst, data, 0o700); err != nil {
		t.Fatalf("writing fake binary: %v", err)
	}
}

type fakeControl struct {
	Version          string `json:"version"`
	VersionExit      int    `json:"version_exit"`
	Help             string `json:"help"`
	HelpExit         int    `json:"help_exit"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	Exit             int    `json:"exit"`
	DelayMS          int    `json:"delay_ms"`
	LargeOutputBytes int64  `json:"large_output_bytes"`
	SpawnChild       bool   `json:"spawn_child"`
	RecordPath       string `json:"record_path"`
}

// newFake returns a fake NextTrace executable whose sibling control file
// contains ctrl.
func newFake(t *testing.T, ctrl fakeControl) string {
	t.Helper()
	path := buildFake(t)
	data, err := json.Marshal(ctrl)
	if err != nil {
		t.Fatalf("marshalling fake control: %v", err)
	}
	if err := os.WriteFile(path+".json", data, 0o600); err != nil {
		t.Fatalf("writing fake control: %v", err)
	}
	return path
}

type fakeRecord struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
	PID  int               `json:"pid"`
}

func waitForRecord(t *testing.T, path string, timeout time.Duration) fakeRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			var record fakeRecord
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatalf("decoding fake record %s: %v", path, err)
			}
			return record
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for fake record %s", path)
	return fakeRecord{}
}

func readRecord(t *testing.T, path string) fakeRecord {
	t.Helper()
	return waitForRecord(t, path, 2*time.Second)
}

func waitForFile(t *testing.T, path string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return string(data)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for file %s", path)
	return ""
}

// capableFlags enables every flag used by the runner tests.
func capableFlags() Flags {
	return Flags{
		JSON:         true,
		IPv4:         true,
		IPv6:         true,
		IPv4Long:     true,
		IPv6Long:     true,
		MaxHopsShort: true,
		MaxHopsLong:  true,
		QueriesShort: true,
		QueriesLong:  true,
		Timeout:      true,
		Traceroute:   true,
		TCPShort:     true,
		TCPLong:      true,
		UDPShort:     true,
		UDPLong:      true,
		PortShort:    true,
		PortLong:     true,
		DeviceShort:  true,
		DeviceLong:   true,
	}
}

func capableCapabilities() Capabilities {
	return Capabilities{Version: "v1.7.1", Flags: capableFlags()}
}

func ipv4Spec() Spec {
	addr := mustAddr("1.1.1.1")
	return Spec{
		Addr:           addr,
		Family:         familyOf(addr),
		Protocol:       protocolICMP,
		MaxHops:        30,
		Queries:        3,
		ProbeTimeoutMS: 1000,
	}
}

func intPtr(value int) *int { return &value }

func tcpSpec() Spec {
	spec := ipv4Spec()
	spec.Protocol = model.ProtocolTCP
	spec.Port = intPtr(443)
	return spec
}

func udpSpec() Spec {
	spec := ipv4Spec()
	spec.Protocol = model.ProtocolUDP
	spec.Port = intPtr(model.DefaultUDPPort)
	return spec
}

// flagsWithoutTCP models an older NextTrace build that only supports ICMP.
func flagsWithoutTCP() Flags {
	return Flags{
		JSON: true, IPv4: true, IPv6: true,
		MaxHopsShort: true, QueriesShort: true, Timeout: true,
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
