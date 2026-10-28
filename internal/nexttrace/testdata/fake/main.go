// Command fake-nexttrace is a deterministic stand-in for the real NextTrace
// binary used by TraceCat's tests. It never performs network I/O.
//
// Behaviour is controlled by a JSON file resolved from the
// FAKE_NEXTRACE_CONTROL environment variable or, when that is unset, from a
// sibling file named "<executable>.json". This keeps the fake usable even
// though the Agent runs it with a minimal, fixed environment.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultVersion = "NextTrace v1.7.1 2024-05-01T00:00:00Z\n"

const defaultHelp = `Usage:
  nexttrace [flags] <target>

Flags:
  -4, --ipv4              only use IPv4
  -6, --ipv6              only use IPv6
  -T, --tcp               use TCP SYN probes
  -U, --udp               use UDP probes
  -p, --port int          destination port (default 80)
  -j, --json              output JSON
  -m, --max-hops int      maximum hops (default 30)
  -q, --queries int       number of probes per hop (default 3)
      --timeout int       probe timeout in milliseconds (default 1000)
      --traceroute        use traceroute-style probing
`

type control struct {
	Version     string `json:"version"`
	VersionExit int    `json:"version_exit"`
	Help        string `json:"help"`
	HelpExit    int    `json:"help_exit"`

	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	Exit             int    `json:"exit"`
	DelayMS          int    `json:"delay_ms"`
	LargeOutputBytes int64  `json:"large_output_bytes"`
	SpawnChild       bool   `json:"spawn_child"`
	RecordPath       string `json:"record_path"`
}

func main() {
	executable, err := os.Executable()
	if err != nil {
		executable = os.Args[0]
	}
	executable, _ = filepath.Abs(executable)

	// Child mode is used by the process-group kill test.
	if len(os.Args) > 1 && os.Args[1] == "--child" {
		runChild(executable)
		return
	}

	ctrl := loadControl(executable)

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			fmt.Print(defaultIfEmpty(ctrl.Version, defaultVersion))
			os.Exit(ctrl.VersionExit)
		case "--help":
			fmt.Print(defaultIfEmpty(ctrl.Help, defaultHelp))
			os.Exit(ctrl.HelpExit)
		}
	}

	recordPath := ctrl.RecordPath
	if recordPath == "" {
		recordPath = executable + ".args"
	}
	record := map[string]any{
		"args": os.Args[1:],
		"env":  environment(),
		"pid":  os.Getpid(),
	}
	if data, err := json.Marshal(record); err == nil {
		_ = os.WriteFile(recordPath, data, 0o600)
	}

	if ctrl.SpawnChild {
		spawnChild(executable)
	}

	if ctrl.DelayMS > 0 {
		time.Sleep(time.Duration(ctrl.DelayMS) * time.Millisecond)
	}

	if ctrl.LargeOutputBytes > 0 {
		writeLargeOutput(ctrl.LargeOutputBytes)
	} else if ctrl.Stdout != "" {
		fmt.Print(ctrl.Stdout)
	}
	if ctrl.Stderr != "" {
		fmt.Fprint(os.Stderr, ctrl.Stderr)
	}
	os.Exit(ctrl.Exit)
}

func loadControl(executable string) control {
	path := os.Getenv("FAKE_NEXTRACE_CONTROL")
	if path == "" {
		path = executable + ".json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return control{}
	}
	var ctrl control
	if err := json.Unmarshal(data, &ctrl); err != nil {
		return control{}
	}
	return ctrl
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func environment() map[string]string {
	env := make(map[string]string)
	for _, entry := range os.Environ() {
		if key, value, ok := strings.Cut(entry, "="); ok {
			env[key] = value
		}
	}
	return env
}

func spawnChild(executable string) {
	// Use the current executable with a dedicated argument so the child does
	// not touch the parent's control files.
	child, err := os.StartProcess(executable, []string{executable, "--child", strconv.Itoa(os.Getpid())}, &os.ProcAttr{})
	if err != nil {
		return
	}
	pidPath := executable + ".child.pid"
	_ = os.WriteFile(pidPath, []byte(strconv.Itoa(child.Pid)), 0o600)
	go func() {
		_, _ = child.Wait()
	}()
}

func runChild(executable string) {
	pidPath := executable + ".child.pid"
	_ = os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o600)
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

func writeLargeOutput(size int64) {
	chunk := []byte(strings.Repeat("x", 64<<10))
	for written := int64(0); written < size; {
		remaining := size - written
		if remaining > int64(len(chunk)) {
			remaining = int64(len(chunk))
		}
		n, err := os.Stdout.Write(chunk[:remaining])
		if err != nil {
			return
		}
		written += int64(n)
	}
}
