// Command tracecat-agent runs the TraceCat Agent: the only TraceCat component
// that executes the external NextTrace binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dotfrankruan/tracecat/internal/agent"
	"github.com/dotfrankruan/tracecat/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", agent.DefaultConfigPath, "path to the agent JSON configuration file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("tracecat-agent %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
		return 0
	}

	bootstrap := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := agent.Load(*configPath)
	if err != nil {
		bootstrap.Error("failed to load agent config", "error", err)
		return 1
	}
	logger := newLogger(cfg.LogLevel)
	if logger == nil {
		logger = bootstrap
	}

	service, err := agent.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize agent", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx); err != nil {
		logger.Error("agent stopped with error", "error", err)
		return 1
	}
	logger.Info("agent stopped cleanly")
	return 0
}

func newLogger(level string) *slog.Logger {
	var parsed slog.Level
	switch level {
	case "debug":
		parsed = slog.LevelDebug
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		parsed = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parsed}))
}
