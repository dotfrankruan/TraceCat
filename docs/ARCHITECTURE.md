# TraceCat Architecture

TraceCat is a small distributed traceroute system: one **Controller** (web
dashboard + API + scheduler + history) and one **Agent** per vantage point.
Agents run the locally installed NextTrace binary; the Controller never runs
traceroute itself.

```
                    Cloudflare Access (user auth)          tailnet (WireGuard)
 browser ──HTTPS──> cloudflared ──HTTP/loopback──> Controller ──HTTP──> Agent ──exec──> nexttrace
   (same-origin)        │                              │                  │
                        └── verifies Access JWT        │                  └── fixed binary,
                            at the application         └── SQLite            fixed argv,
                            boundary                       (history)         no shell
```

## 1. Components

### Controller (`cmd/tracecat-controller`, `internal/controller`)

- Serves the embedded React dashboard (`internal/webui`) and `/api/v1`.
- Authenticates browsers: Cloudflare Access JWT verification (RS256, JWKS,
  issuer/audience/expiry) or local PBKDF2 password sessions; explicit,
  loopback-only `dev` bypass.
- Resolves user-supplied domains centrally (A + AAAA, IDN, bounded timeouts),
  returns all usable addresses, and requires the user to select one.
- Applies the destination IP policy (`internal/ipguard`) before dispatch.
- Validates node selections against an administratively configured registry;
  there is no user-supplied Agent URL and no node registration API.
- Dispatches traces through a bounded worker pool, tracks per-node state,
  persists a bounded history in SQLite, and streams job state changes via SSE.
- Serves structured JSON exports of completed jobs.

### Agent (`cmd/tracecat-agent`, `internal/agent`)

- Listens only on an explicitly configured Tailscale address; startup fails if
  the address is not assigned or is a wildcard.
- Requires a per-Agent bearer token (constant-time verification) on every
  request; tailnet connectivity is not sufficient authorization.
- Revalidates every request field independently: schema version, ids, family,
  protocol, numeric limits, and the target IP policy (never trusts the
  Controller).
- Builds a fixed argument vector from typed values and executes a fixed
  NextTrace binary through `exec.CommandContext` — no shell, no
  user-controlled executable or arguments.
- Enforces process timeouts, kills the whole process group on cancellation,
  caps stdout/stderr, bounds concurrency and request rates, and never returns
  environment variables, paths, stderr or stack traces.

### NextTrace integration (`internal/nexttrace`)

- Detects the installed binary's version and flag capabilities at startup
  (`--version`, `--help`); unsupported/missing flags are a configuration error,
  never a reason to guess.
- One-shot ICMP traceroute only in the MVP (`-4`/`-6`, `--json`, `-m`, `-q`,
  optional `--timeout`, optional explicit `--traceroute` when detected).
- Parses NextTrace JSON into isolated DTOs (`nexttrace.json.v1`) and then into
  stable internal models; a NextTrace schema change does not leak into the
  dashboard contract.
- Keeps a bounded copy of the raw structured JSON for debugging/export.

### Dashboard (`web/`)

- React + TypeScript + Vite + Tailwind, built at release time and embedded in
  the Controller binary. No Node.js at runtime.
- Talks only to the Controller, same-origin, with CSRF header and session
  cookie. Renders all third-party metadata as text (no `dangerouslySetInnerHTML`).
- Presents per-node hop tables, an AS-path visualization, deterministic ASN
  colors, progress, history, exports and a side-by-side comparison view.

## 2. Request lifecycle

1. Browser loads the SPA from the Controller and calls `GET /api/v1/session`.
   Cloudflare Access has already authenticated the user; the Controller
   verifies the Access JWT itself before trusting the request.
2. User submits a target. Controller validates it as an IP literal or a domain
   (IDN aware), resolves A/AAAA centrally with a bounded timeout, filters
   disallowed addresses, deduplicates and returns all choices.
3. User explicitly selects one numeric IP (when several exist), selects one or
   more Agents, and starts a job. The Controller revalidates the IP and node
   ids, writes the job as `pending`, and queues work on its bounded pool.
4. For each node the Controller sends one `POST /v1/trace` with a numeric IP
   and typed limits, under a per-node timeout and the job's cancellation
   context.
5. The Agent validates and revalidates, checks the destination policy,
   constructs argv, runs NextTrace with a process-group kill guard, parses the
   JSON, sanitizes metadata, and returns a normalized result (plus bounded raw
   JSON).
6. The Controller stores the node result, recomputes the aggregate job state,
   and publishes the full job snapshot over SSE. One node failing never fails
   the others; the aggregate becomes `completed`, `partial`, `failed` or
   `cancelled`.
7. History is trimmed to the configured maximum. Exports include normalized
   results and the bounded raw NextTrace JSON.

## 3. Data model

- `model.AgentTraceRequest` / `model.AgentTraceResponse` — Controller ↔ Agent.
- `model.Job` / `model.NodeResult` / `model.Hop` / `model.Probe` — browser
  contract and persisted result shape.
- SQLite tables: `jobs`, `job_nodes`, `sessions` (local auth only). Job payloads
  are stored as validated JSON documents; SQL is fully parameterized.
- NextTrace DTOs live only in `internal/nexttrace` and are never persisted or
  exposed directly.

See `docs/API.md` for the normative wire contract.

## 4. Failure handling

| Failure | Behaviour |
| --- | --- |
| DNS failure / no addresses / all filtered | `502 dns_failure` / `404 no_addresses`; no job created |
| One Agent unreachable | node `failed` (`agent_unreachable`); other nodes proceed |
| Agent times out | node `timed_out`; Controller cancels the HTTP request |
| User cancels | contexts cancelled; Agents kill process groups; nodes `cancelled` |
| Malformed/oversized NextTrace JSON | node `failed` with `parse_error`/`output_too_large`; raw output not exposed |
| Agent returns malformed contract data | node `failed`; response size bounded |
| Controller restarts | persisted terminal history remains; queued/running jobs are not resumed (documented limitation) |
| Node config invalid | Controller refuses to start with a clear error |

## 5. Deliberate non-features

No arbitrary command execution, no user-supplied Agent URLs or tokens, no
remote self-update, no plugin loading, no file upload/download beyond JSON job
exports, no TCP/UDP/MTR in the MVP, no multi-tenant authorization, no external
message broker. These are security decisions, not missing plumbing.

## 6. Deployment topology

- Controller: Docker or systemd; loopback listener behind Cloudflare Tunnel +
  Access (recommended) or a tailnet-only listener.
- Agents: systemd on each vantage point, unprivileged service user, NextTrace
  installed by the administrator, `CAP_NET_RAW` granted narrowly (ambient
  capability or file capability on the binary).
- Communication: HTTP over Tailscale (WireGuard-encrypted). Cleartext HTTP is
  only accepted for private/Tailscale Agent addresses; public hosts require
  HTTPS.
- SQLite database in `/var/lib/tracecat` with `0700` state directory.
