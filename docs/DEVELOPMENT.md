# Development

## Toolchain

| Tool | Needed for | Notes |
| --- | --- | --- |
| Go 1.23+ | Controller, Agent, tests | `go.mod` pins 1.23 |
| Node 22+ & pnpm 10 | Dashboard build only | **Never** needed at runtime; the Controller embeds static assets |
| NextTrace | Agent runtime + end-to-end checks | `nexttrace --version`; tests use a fake binary |
| Tailscale (optional) | Production Agent binding | Local dev configs use loopback with an explicit override |

## Build

```bash
make ui            # optional: rebuild dashboard into internal/webui/public
make build-backend # Controller + Agent binaries in ./bin
make build         # both
```

The dashboard assets are committed under `internal/webui/public`, so a plain
`go build ./cmd/tracecat-controller` works without Node installed. Rebuilding
the UI requires pnpm and writes that directory, which should then be committed
with the source change.

## Test

```bash
make vet
make test          # go test ./...
make test-race     # go test -race ./...
```

Tests are hermetic: no public traceroute targets, no external GeoIP calls, no
real Tailscale membership. NextTrace is replaced by a fake executable that
records its argv. The tests do not require root or `CAP_NET_RAW`.

## Run the stack locally

Terminal 1 — an Agent (dev config binds loopback; the Tailscale requirement is
explicitly disabled for local development):

```bash
export TRACECAT_AGENT_TOKEN=local-dev-token-please-change
./bin/tracecat-agent -config configs/agent.dev.json
```

Terminal 2 — the Controller (dev auth mode requires a loopback listener):

```bash
./bin/tracecat-controller -config configs/controller.dev.json
# http://127.0.0.1:8080
```

`auth.mode=dev` is a deliberate local-development bypass: it is refused on
non-loopback listeners and rejects requests carrying proxy headers. Never use
it on a shared host or behind a tunnel.

## Repository conventions

- `internal/model` is the single source of truth for the wire contract; any
  change requires bumping the schema version and updating `docs/API.md` plus
  `web/src/types.ts`.
- Destination policy changes belong in `internal/ipguard` and must include
  table-driven tests for both address families and IPv4-mapped forms.
- Never introduce shell execution, dynamic executable paths, or
  user-controlled argument arrays. New NextTrace options must be typed,
  bounded, capability-detected, and allowlisted in the command builder.
- Do not log secrets. Do not add dependencies for convenience; prefer stdlib.
- Run `gofmt` and `go vet` before opening a PR.
