package nexttrace

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/dotfrankruan/tracecat/internal/model"
)

const (
	// DefaultMaxStdoutBytes is the default hard cap on captured NextTrace
	// stdout. Exceeding it terminates the process group and is reported as
	// output_too_large.
	DefaultMaxStdoutBytes int64 = 4 << 20
	// DefaultMaxStderrBytes is the hard cap on captured stderr. Stderr is never
	// returned to callers; it is only bounded to avoid unbounded memory use.
	DefaultMaxStderrBytes int64 = 64 << 10

	// maxStdoutCeiling prevents an absurd configuration from being used as a
	// memory amplification vector.
	maxStdoutCeiling int64 = 64 << 20
)

// RunLimits bounds captured output for one execution.
type RunLimits struct {
	MaxStdoutBytes int64
	MaxStderrBytes int64
}

// RunResult is the outcome of one NextTrace execution. Stderr is deliberately
// not exposed: it may contain targets, interface names or other internal
// details that must never reach the wire.
type RunResult struct {
	Stdout         []byte
	ExitCode       int
	TimedOut       bool
	Cancelled      bool
	OutputTooLarge bool
}

// Runner executes a fixed NextTrace binary with capability-verified flags.
type Runner struct {
	binary string
	caps   Capabilities
}

// NewRunner builds a Runner for a fixed absolute binary path and detected
// capabilities. The path is never exposed by this package.
func NewRunner(binary string, caps Capabilities) *Runner {
	return &Runner{binary: binary, caps: caps}
}

// Run executes spec under a single overall deadline derived from timeout. On
// deadline or context cancellation the entire process group is killed, so no
// orphaned NextTrace children survive.
//
// Error codes are limited to nexttrace_unavailable, nexttrace_failed,
// timeout, cancelled, output_too_large and internal. Messages are safe and
// contain neither stderr content nor filesystem paths.
func (r *Runner) Run(ctx context.Context, spec Spec, timeout time.Duration, limits RunLimits) (RunResult, *model.APIError) {
	var res RunResult
	if r == nil || r.binary == "" {
		return res, model.NewError(model.ErrNextTraceMissing, "nexttrace is not configured")
	}
	if !r.caps.Available() {
		return res, model.NewError(model.ErrNextTraceMissing, "nexttrace is not available")
	}
	args, err := r.caps.BuildArgs(spec)
	if err != nil {
		return res, model.NewError(model.ErrInternal, "invalid nexttrace invocation")
	}
	if timeout <= 0 {
		return res, model.NewError(model.ErrInternal, "invalid execution timeout")
	}
	if limits.MaxStdoutBytes <= 0 {
		limits.MaxStdoutBytes = DefaultMaxStdoutBytes
	}
	if limits.MaxStdoutBytes > maxStdoutCeiling {
		limits.MaxStdoutBytes = maxStdoutCeiling
	}
	if limits.MaxStderrBytes <= 0 {
		limits.MaxStderrBytes = DefaultMaxStderrBytes
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, r.binary, args...)
	cmd.Env = minimalEnv()
	cmd.WaitDelay = 2 * time.Second
	configureProcessGroup(cmd)

	stdout := newBoundedBuffer(limits.MaxStdoutBytes)
	stderr := newBoundedBuffer(limits.MaxStderrBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	var killOnce sync.Once
	kill := func() {
		killOnce.Do(func() {
			if p := cmd.Process; p != nil {
				_ = killProcessGroup(p)
			}
		})
	}
	stdout.SetOverflowHook(kill)
	cmd.Cancel = func() error {
		kill()
		return nil
	}

	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			res.Cancelled = true
			return res, model.NewError(model.ErrCancelled, "traceroute cancelled")
		}
		if runCtx.Err() != nil {
			res.TimedOut = true
			return res, model.NewError(model.ErrTimeout, "traceroute timed out")
		}
		return res, model.NewError(model.ErrNextTraceFailed, "failed to start nexttrace")
	}

	waitErr := cmd.Wait()
	res.ExitCode = exitCode(waitErr)

	// Classification order matters: cancellation and deadline take precedence
	// over a secondary exit error caused by killing the process group.
	if ctx.Err() != nil {
		res.Cancelled = true
		return res, model.NewError(model.ErrCancelled, "traceroute cancelled")
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
		return res, model.NewError(model.ErrTimeout, "traceroute timed out")
	}
	if stdout.Overflowed() {
		res.OutputTooLarge = true
		return res, model.NewError(model.ErrOutputTooLarge, "nexttrace output exceeded the configured limit")
	}
	if waitErr != nil {
		return res, model.NewError(model.ErrNextTraceFailed, "nexttrace did not complete successfully")
	}

	res.Stdout = stdout.Bytes()
	return res, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// boundedBuffer captures at most limit bytes and invokes an optional hook the
// first time the limit is exceeded. Writes beyond the limit are accepted and
// discarded so the copying goroutine keeps draining the pipe until the process
// group is killed.
type boundedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int64
	overflow bool
	hook     func()
	hookOnce sync.Once
}

func newBoundedBuffer(limit int64) *boundedBuffer {
	return &boundedBuffer{limit: limit}
}

// SetOverflowHook installs the callback invoked on the first overflow. It must
// be called before the buffer receives writes.
func (b *boundedBuffer) SetOverflowHook(hook func()) {
	b.hook = hook
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	fireHook := false
	b.mu.Lock()
	remaining := b.limit - int64(b.buf.Len())
	switch {
	case remaining <= 0:
		if !b.overflow {
			b.overflow = true
			fireHook = true
		}
	case int64(len(p)) > remaining:
		_, _ = b.buf.Write(p[:remaining])
		if !b.overflow {
			b.overflow = true
			fireHook = true
		}
	default:
		_, _ = b.buf.Write(p)
	}
	b.mu.Unlock()

	if fireHook && b.hook != nil {
		b.hookOnce.Do(b.hook)
	}
	return len(p), nil
}

// Overflowed reports whether the limit was exceeded.
func (b *boundedBuffer) Overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

// Bytes returns a copy of the captured bytes.
func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}
