# TraceCat

**Secure, distributed traceroute from the web.** TraceCat is a lightweight
Controller + Agent system that runs the excellent
[NextTrace](https://github.com/nxtrace/NTrace-core) CLI on multiple vantage
points and turns the structured results into a fast, dark-mode dashboard with
side-by-side path comparison.

TraceCat is deliberately *not* a remote-execution platform. Agents execute one
fixed NextTrace binary with a strictly constructed argument vector; there is no
shell, no user-controlled executable or flags, and no generic command API.

```
 browser ──HTTPS/Cloudflare Access──> Controller ──HTTP over Tailscale──> Agents ──> nexttrace
                                      (Go + SQLite)      (Go, unprivileged)
```

## Highlights

- **Typed, shell-free execution.** Targets are parsed as numeric IP literals;
  argv is built from a typed struct and asserted against an allowlist.
- **Defense in depth on targets.** Controller and every Agent independently
  enforce a default-deny IP policy (global unicast only) with an explicit
  admin CIDR allowlist for lab ranges. IPv4-mapped IPv6 bypasses are closed.
- **Authenticated at the application boundary.** Cloudflare Access JWTs are
  verified against the team JWKS (signature/issuer/audience/expiry); local
  password sessions use PBKDF2 + HttpOnly/SameSite cookies + CSRF. An explicit
  loopback-only dev mode exists for development.
- **DNS resolved once, centrally.** A/AAAA + IDN, deduplicated, policy-filtered;
  multiple addresses are always presented as an explicit choice, and only the
  selected numeric IP is sent to Agents.
- **Honest results.** Per-node Pending/Running/Completed/Failed/Timed out/
  Cancelled, bounded history, raw JSON export, and a UI that never claims an
  intermediate timeout means a broken route.
- **Small and maintainable.** Go stdlib-first (only `x/net/idna` and pure-Go
  SQLite as dependencies), one React/Tailwind dashboard embedded into the
  Controller binary, no Node at runtime.

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/tracecat-controller`, `internal/controller` | Web/API server, DNS, auth, job scheduler, SQLite history, SSE |
| `cmd/tracecat-agent`, `internal/agent` | Tailscale-only, token-authenticated trace runner |
| `internal/nexttrace` | Capability detection, typed command builder, version-aware JSON parser |
| `internal/ipguard` | Shared destination policy (default-deny + admin allowlist) |
| `internal/model` | Versioned wire contract |
| `internal/webui`, `web` | Embedded dashboard and its React/TS/Tailwind sources |
| `deploy`, `configs`, `docs` | systemd units, Docker, Tailscale/Cloudflare guidance, API and security docs |

## Quick start (local development)

Requirements: Go 1.23+ and NextTrace installed. Node/pnpm are needed **only**
when rebuilding the dashboard; prebuilt assets are embedded so `go build` works
without Node.

```bash
# 1. Build (skip `make ui` if you only want the committed dashboard assets)
make ui
make build-backend

# 2. Run an Agent against a dev config (loopback for local testing)
TRACECAT_AGENT_TOKEN=dev-token-at-least-16-chars ./bin/tracecat-agent -config configs/agent.dev.json

# 3. Run the Controller in explicit loopback-only dev mode
./bin/tracecat-controller -config configs/controller.dev.json

# 4. Open http://127.0.0.1:8080
```

`make ui` requires Node 22+/pnpm; the deployed artifact is a single Go binary
with static assets, so Node is never installed or run on servers. Node.js is
build-time only.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for systemd, Tailscale and
Cloudflare deployment, [docs/API.md](docs/API.md) for the wire contract, and
[`SECURITY.md`](SECURITY.md) for the threat model.

## Production topology

1. Controller on a small host or container, listener on `127.0.0.1:8080`.
2. `cloudflared` tunnel exposing the Controller hostname, protected by a
   Cloudflare Access application (MFA). TraceCat verifies the Access JWT itself.
3. Agents on each vantage point, bound to their Tailscale IP, reached only by
   the Controller according to tailnet ACLs, each with its own bearer token.
4. NextTrace installed on each Agent host; the Agent runs unprivileged with only
   `CAP_NET_RAW`.

## Verified environment

- Go 1.27.x toolchain; NextTrace v1.7.1 (macOS) and v1.7.3 (Debian 13) verified
  for flag detection and JSON parsing; the parser tolerates known schema
  variations.
- Deployed and exercised on Debian 13 with systemd 257 and Tailscale 1.104.
- Tests do not require public traceroute targets, real GeoIP services, or
  internet access.

See [docs/TESTING.md](docs/TESTING.md) for exactly what is verified.

## Limitations (MVP)

- One-shot ICMP traceroute only; TCP/UDP and MTR are intentionally not exposed.
- Single-tenant: every authenticated user may use all configured nodes.
- No resumable jobs after a Controller restart; bounded history only.
- Agent transport is HTTP inside the Tailscale/WireGuard tailnet.
- Geolocation/ASN data comes from NextTrace's third-party providers and may be
  missing or inaccurate; missing values are never invented.
- Intermediate probe timeouts are not evidence of a broken path.

## License and attribution

TraceCat is licensed under the [Apache License 2.0](LICENSE).
NextTrace is an independent GPL-3.0 project, invoked as an external binary and
not vendored or modified; see [NOTICE](NOTICE) for attribution and operator
obligations.
