// Command tracecat-controller serves the TraceCat dashboard and orchestrates
// distributed traceroute jobs across administratively configured Agents.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dotfrankruan/tracecat/internal/controller"
	"github.com/dotfrankruan/tracecat/internal/ipguard"
	"github.com/dotfrankruan/tracecat/internal/version"
)

const (
	healthPollInterval = 30 * time.Second
	shutdownTimeout    = 10 * time.Second
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("tracecat-controller", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/tracecat/controller.json", "path to the JSON configuration file")
	showVersion := flags.Bool("version", false, "print the version and exit")
	hashPassword := flags.Bool("hash-password", false, "read a password from stdin and print a PBKDF2 hash")
	flags.Usage = func() {
		fmt.Fprintf(stderr, "usage: tracecat-controller [options]\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "tracecat-controller %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
		return 0
	}
	if *hashPassword {
		hash, err := controller.HashPasswordForCLI(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "hash-password: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, hash)
		return 0
	}

	cfg, err := controller.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	logger := newLogger(stderr, cfg.LogLevel)

	policy, err := ipguard.NewPolicy(nil)
	if err != nil {
		logger.Error("could not initialize the destination policy", "error", err)
		return 1
	}
	store, err := controller.OpenStore(cfg.Database.Path, cfg.Database.MaxHistoryJobs)
	if err != nil {
		logger.Error("could not open the job history database", "error", err)
		return 1
	}

	resolver := controller.NewResolverService(
		controller.NewNetResolver(cfg.DNS.Resolver), policy,
		time.Duration(cfg.DNS.TimeoutMS)*time.Millisecond, cfg.DNS.MaxAddresses)
	agentClient := controller.NewAgentClient()
	registry := controller.NewRegistry(cfg, agentClient, logger)
	hub := controller.NewHub()
	manager := controller.NewManager(cfg, store, registry, agentClient, hub, logger)
	api, err := controller.NewAPI(cfg, store, resolver, registry, manager, logger)
	if err != nil {
		logger.Error("could not initialize the HTTP API", "error", err)
		_ = store.Close()
		return 1
	}

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No WriteTimeout: authenticated SSE responses are long-lived.
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The health poller is started here and stopped by the same context on
	// graceful shutdown.
	controller.RunHealthPoller(ctx, registry, healthPollInterval)

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("could not bind the listener", "error", err)
		stop()
		registry.Wait()
		_ = store.Close()
		return 1
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	logger.Info("tracecat-controller listening",
		"listen", cfg.Listen,
		"public_origin", cfg.PublicOrigin,
		"auth_mode", cfg.Auth.Mode,
		"agents", len(cfg.Agents),
	)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server failed", "error", err)
			stop()
			shutdown(server, manager, registry, store, logger)
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutdown signal received")
		stop()
	}

	shutdown(server, manager, registry, store, logger)
	logger.Info("tracecat-controller stopped")
	return 0
}

// shutdown performs a bounded graceful shutdown: stop accepting connections
// (and close SSE streams), cancel jobs, wait for the health poller, close the
// database.
func shutdown(server *http.Server, manager *controller.Manager, registry *controller.Registry, store *controller.Store, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	serverDone := make(chan struct{})
	go func() {
		if err := server.Shutdown(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("HTTP server shutdown did not complete cleanly", "error", err)
		}
		close(serverDone)
	}()

	// Cancelling jobs closes their SSE subscribers, which lets Shutdown finish.
	manager.Shutdown(ctx)
	<-serverDone
	registry.Wait()
	if err := store.Close(); err != nil {
		logger.Warn("could not close the database", "error", err)
	}
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slogLevel}))
}
