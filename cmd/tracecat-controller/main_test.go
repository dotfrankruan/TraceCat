package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotfrankruan/tracecat/internal/controller"
)

func runForTest(args []string, stdin string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunVersion(t *testing.T) {
	code, stdout, stderr := runForTest([]string{"-version"}, "")
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "tracecat-controller") {
		t.Fatalf("unexpected version output: %q", stdout)
	}
}

func TestRunHashPassword(t *testing.T) {
	code, stdout, stderr := runForTest([]string{"-hash-password"}, "a long enough password\n")
	if code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr)
	}
	hash := strings.TrimSpace(stdout)
	if err := controller.ValidatePasswordHash(hash); err != nil {
		t.Fatalf("printed hash is invalid: %v (%q)", err, hash)
	}
	ok, err := controller.VerifyPassword("a long enough password", hash)
	if err != nil || !ok {
		t.Fatalf("printed hash does not verify: %v", err)
	}

	code, _, stderr = runForTest([]string{"-hash-password"}, "short\n")
	if code != 1 || !strings.Contains(stderr, "12") {
		t.Fatalf("short password: code=%d stderr=%q", code, stderr)
	}
}

func TestRunUnknownFlag(t *testing.T) {
	if code, _, _ := runForTest([]string{"-nope"}, ""); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if code, _, _ := runForTest([]string{"stray"}, ""); code != 2 {
		t.Fatalf("exit code with stray argument = %d, want 2", code)
	}
}

func TestRunMissingConfig(t *testing.T) {
	code, _, stderr := runForTest([]string{"-config", filepath.Join(t.TempDir(), "missing.json")}, "")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "configuration error") {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
}

func TestRunInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"listen":"0.0.0.0:8080","auth":{"mode":"dev"},"agents":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runForTest([]string{"-config", path}, "")
	if code != 1 || !strings.Contains(stderr, "configuration error") {
		t.Fatalf("exit code = %d stderr=%q", code, stderr)
	}
}
