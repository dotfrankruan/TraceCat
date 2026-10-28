// Package version exposes build metadata. Values are injected at build time
// with -ldflags "-X github.com/dotfrankruan/tracecat/internal/version.Version=...".
package version

// Version is the semantic version of TraceCat.
var Version = "dev"

// Commit is the git commit SHA the binary was built from.
var Commit = "unknown"

// BuildDate is the RFC3339 build timestamp.
var BuildDate = "unknown"
