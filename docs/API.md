# TraceCat API Contract (v1)

This document is normative for both the Go implementation and the web client.
Any change to field names, status codes or semantics requires bumping the
schema version (`tracecat.agent.v1` / `tracecat.controller.v1`).

TraceCat has exactly three network edges:

```
Browser  --(same-origin HTTPS)-->  Controller  --(HTTP over Tailscale)-->  Agent  -->  nexttrace
```

- The browser never talks to an Agent.
- The Agent never resolves DNS for a trace and never accepts a hostname.
- The Agent's only outbound execution is the locally configured NextTrace
  binary with a fixed, typed argument vector. Protocols are a fixed enum
  (`icmp`/`tcp`/`udp`) mapped to capability-detected flags; TCP/UDP destination
  ports are bounded integers, never strings, ranges or service names.

Shared limits (also in `internal/model/model.go`):

| Limit              | Value                     |
| ------------------ | ------------------------- |
| `protocol`         | `icmp`, `tcp` or `udp` (fixed enum; `allowed_protocols` config) |
| `port`             | 1 .. 65535, required for `tcp`/`udp`, forbidden for `icmp` |
| `max_hops`         | 1 .. 64                   |
| `queries`          | 1 .. 5                    |
| `timeout_ms`       | 5 000 .. 120 000          |
| Max nodes per job  | 16 (Controller config, default 8) |
| Max resolved IPs   | 16 (Controller config)    |
| Job id             | `^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$` |
| Node id            | `^[a-z0-9][a-z0-9_-]{0,31}$` |

All timestamps on the wire are RFC 3339 with nanosecond precision in UTC, e.g.
`2025-01-02T03:04:05.123456789Z`. All JSON responses use
`Content-Type: application/json` and `Cache-Control: no-store` (except static
frontend assets). `429` responses include a `Retry-After` hint. Error responses
always use the envelope:

```json
{ "error": { "code": "target_rejected", "message": "destination 10.0.0.1 rejected: private_address" } }
```

Error `code` values are stable; `message` is human-readable, sanitized, and
free of secrets, stack traces, environment variables and filesystem paths.

---

## 1. Agent API (Controller -> Agent)

Base path `/v1`. The Agent listens only on its configured Tailscale IP and
requires a per-Agent bearer token on every request.

### Authentication

```
Authorization: Bearer <per-agent-token>
```

The token is stored on the Agent as an environment variable named by the
configuration (`auth.token_env`) and on the Controller per node
(`agents[].token_env`). Comparison is constant-time over SHA-256 digests.
Missing/incorrect token -> `401` with `WWW-Authenticate: Bearer`. The token is
never logged, echoed, stored in the database or included in results.

### `GET /v1/health`

Authenticated. Reports Agent identity, installed NextTrace version, detected
capabilities and enforced limits.

```json
{
  "schema_version": "tracecat.agent.v1",
  "status": "ok",
  "node_id": "tokyo-1",
  "version": "0.1.0",
  "nexttrace": {
    "available": true,
    "version": "v1.7.3",
    "capabilities": ["json", "ipv4", "ipv6", "max_hops", "queries", "timeout"]
  },
  "limits": {
    "max_hops": 64,
    "max_queries": 5,
    "max_timeout_ms": 120000,
    "max_concurrent_traces": 4,
    "protocols": ["icmp", "tcp", "udp"]
  },
  "time": "2025-01-02T03:04:05.123456789Z"
}
```

- `status`: `ok` when the binary is usable, `degraded` when it is not.
- `nexttrace.capabilities` is detected from the installed binary's `--help`
  output; it is never assumed. `nexttrace.error` (safe message only) is set
  when unavailable.
- This endpoint never returns the executable path, environment or config.

### `POST /v1/trace`

Authenticated. Runs one one-shot ICMP, TCP or UDP traceroute against one
numeric IP. MTR/session streaming is not part of the contract.

Request (strict JSON; unknown fields are rejected; body limited to 64 KiB):

```json
{
  "schema_version": "tracecat.agent.v1",
  "job_id": "8f0c2a1b4d5e6f708192a3b4c5d6e7f8",
  "node_id": "tokyo-1",
  "target_ip": "203.0.113.10",
  "family": "ipv4",
  "protocol": "icmp",
  "max_hops": 30,
  "queries": 3,
  "timeout_ms": 60000
}
```

Semantics:

1. `target_ip` MUST be a canonical numeric IP literal (no brackets, no zone,
   no hostname, no port). It is re-parsed and re-validated by the Agent
   applying the same `ipguard` policy as the Controller. A hostname is always
   rejected, even though the Controller resolved the domain earlier.
2. `family` MUST match the normalized address family.
3. `node_id` MUST equal the configured `node_id`.
4. `protocol` MUST be one of `"icmp"`, `"tcp"` or `"udp"`, and MUST be enabled
   in both the Agent configuration (`nexttrace.allowed_protocols`) and the
   installed binary's capability detection.
5. `port` MUST be omitted for `icmp`, and MUST be a JSON integer in
   `1 .. 65535` for `tcp`/`udp`. It is never a string, range, list or service
   name. Example TCP request body (same fields otherwise):

   ```json
   {
     "schema_version": "tracecat.agent.v1",
     "job_id": "8f0c2a1b4d5e6f708192a3b4c5d6e7f8",
     "node_id": "tokyo-1",
     "target_ip": "203.0.113.10",
     "family": "ipv4",
     "protocol": "tcp",
     "port": 443,
     "max_hops": 30,
     "queries": 3,
     "timeout_ms": 60000
   }
   ```

6. `timeout_ms` bounds the entire NextTrace execution, not a single probe.
   A per-probe timeout is a fixed Agent setting, not a request field.
7. The Agent's own configured maximums are authoritative: an Agent may reject
   a request that exceeds its local limits or disables the requested protocol.

Success response (`200`; the HTTP request succeeded even if the trace failed):

```json
{
  "schema_version": "tracecat.agent.v1",
  "job_id": "8f0c2a1b4d5e6f708192a3b4c5d6e7f8",
  "node_id": "tokyo-1",
  "status": "completed",
  "target_ip": "203.0.113.10",
  "family": "ipv4",
  "protocol": "icmp",
  "started_at": "2025-01-02T03:04:05.100000000Z",
  "ended_at": "2025-01-02T03:04:19.900000000Z",
  "duration_ms": 14800,
  "nexttrace_version": "v1.7.3",
  "parser_schema": "nexttrace.json.v1",
  "summary": {
    "hop_count": 12,
    "reached_destination": true,
    "destination_rtt_ms": 41.217,
    "replies": 30,
    "probes": 36
  },
  "hops": [
    {
      "ttl": 1,
      "probes": [
        {
          "success": true,
          "address": "10.200.0.1",
          "rtt_ms": 2.682,
          "error_code": "",
          "asn": null,
          "as_name": "",
          "country": "",
          "region": "",
          "city": "",
          "owner": "",
          "isp": "",
          "prefix": "",
          "lat": null,
          "lng": null,
          "mpls": null
        }
      ]
    }
  ],
  "error": null,
  "raw_result": { "Hops": [] }
}
```

- `status` is one of `completed`, `failed`, `timed_out`, `cancelled`.
  `pending`/`running` never appear in an Agent response (they are Controller
  states).
- `hops` groups probes by TTL, sorted ascending. Failed probes have
  `success=false`, no `address`, `rtt_ms` omitted and `error_code` one of
  `no_reply`, `unreachable` or `unknown`. `no_reply` is **not** evidence that
  the route is broken; routers along a path often drop probes. The UI must
  present it as "no reply".
- GeoIP/ASN/PTR fields are omitted when NextTrace did not provide them. Never
  synthesize defaults.
- `port` is echoed for `tcp`/`udp` responses and omitted for `icmp`.
- `raw_result` is the unmodified structured NextTrace JSON (bounded, default
  max 1 MiB) retained for debugging. It is omitted if too large;
  `raw_result_truncated=true` then indicates that. It is never rendered as
  HTML.
- HTTP-level failures use the error envelope with these codes:
  `invalid_request`, `unauthorized`, `forbidden`, `target_rejected`,
  `rate_limited`, `busy`, `payload_too_large`, `unsupported_schema_version`,
  `internal`. Body/parse/timeout failures *inside* a well-formed trace request
  are reported with `200` + a terminal `status` and `error`:
  `nexttrace_unavailable`, `nexttrace_failed`, `parse_error`, `timeout`,
  `cancelled`, `output_too_large`, `internal`.

### Agent resource controls

- Max concurrent trace processes (config, default 4): excess requests get
  `503` `busy`.
- Request rate limit per remote IP and globally (token bucket): `429`
  `rate_limited` with `Retry-After`.
- HTTP body <= 64 KiB, response bounded by design, stdout <= 4 MiB (config),
  stderr <= 64 KiB and never returned.
- Server timeouts: `ReadHeaderTimeout=5s`, `ReadTimeout=15s`, no unbounded
  writes, `MaxHeaderBytes=16 KiB`.
- Cancellation: when the Controller disconnects or the execution deadline
  expires, the Agent kills the entire NextTrace process group (not just the
  parent) and reports `cancelled`/`timed_out`.

---

## 2. Controller API (Browser -> Controller)

Base path `/api/v1`. Same-origin only. All endpoints except `/healthz` require
authentication. Browser-side authentication is one of:

- `cloudflare` (production): verified Cloudflare Access JWT (see §2.1);
- `local`: password login, server-side session cookie;
- `dev`: explicit loopback-only authentication bypass (never for production).

State-changing requests additionally require the CSRF header returned by the
session endpoint (see §2.2).

### 2.1 Authentication modes

`cloudflare` mode verifies the Access JWT from (in order) the
`Cf-Access-Jwt-Assertion` header or the `CF_Authorization` cookie:
RS256 signature against the team's JWKS, `iss`, `aud`, `exp`/`nbf` (60 s
leeway), and optional email/domain allowlists. Unverified identity headers
(`Cf-Access-Authenticated-User-Email` etc.) are never trusted.

`local` mode: `POST /api/v1/auth/login` with a password verified against an
administrator-generated PBKDF2-HMAC-SHA256 hash. On success the server sets an
HttpOnly, SameSite=Strict session cookie (Secure when the public origin is
HTTPS) and returns a CSRF token. Sessions expire server-side and can be revoked
by logout. Login attempts are rate limited.

`dev` mode is refused unless the listener is a loopback address; requests
carrying proxy headers are additionally rejected in this mode.

### 2.2 CSRF

Any `POST`/`PUT`/`PATCH`/`DELETE` must send:

```
X-TraceCat-CSRF: <csrf_token from GET /api/v1/session>
```

The token is compared in constant time against the server-side value. Requests
with an `Origin` that does not match the configured public origin are rejected
with `403 csrf_failed`. `Sec-Fetch-Site`, when present, must be `same-origin` or
`none`. In `cloudflare` mode the CSRF token is an HMAC of the verified subject
and a server secret, so multi-instance deployments can validate it statelessly.

### 2.3 `GET /api/v1/session`

Returns `200` when authenticated, `401` (error envelope) when not.

```json
{
  "authenticated": true,
  "mode": "cloudflare",
  "user": { "email": "ops@example.com", "subject": "...", "auth_method": "cloudflare" },
  "csrf_token": "…",
  "limits": {
    "max_hops": 30,
    "max_queries": 3,
    "max_execution_ms": 60000,
    "min_execution_ms": 5000,
    "max_nodes_per_job": 8,
    "max_addresses": 16,
    "max_history_jobs": 200,
    "protocols": ["icmp", "tcp", "udp"]
  },
  "version": "0.1.0",
  "warnings": []
}
```

The frontend must render limits from this response, not hardcode them.

### 2.4 `POST /api/v1/auth/login` and `POST /api/v1/auth/logout`

Local mode only (`404` in cloudflare/dev mode).

Login request: `{"password":"…"}` with `Content-Type: application/json` (body
<= 4 KiB; other content types get `415`). Success: `200` with the
session object above and a `Set-Cookie` for `tracecat_session`. Failure: `401
unauthorized`; repeated failures: `429 rate_limited`.

Logout: `204 No Content`; clears the cookie and revokes the session server-side.

### 2.5 `GET /api/v1/nodes`

Administratively configured Agents only; no user-supplied Agent URLs exist.

```json
{
  "nodes": [
    {
      "id": "tokyo-1",
      "name": "Tokyo",
      "location": "Tokyo, JP",
      "provider": "DMIT",
      "enabled": true,
      "health": "ok",
      "last_seen": "2025-01-02T03:04:05Z",
      "nexttrace_version": "v1.7.3"
    }
  ]
}
```

`health` is `ok`, `degraded`, `unreachable`, `unknown` or `disabled`. It is
derived from recent authenticated health checks; it is not user-controllable.

### 2.6 `POST /api/v1/resolve`

Resolves a user target centrally. Body: `{"target":"example.com"}` (<= 1 KiB).

- IP literal input: parsed with `netip`, normalized (mapped IPv4 -> IPv4), the
  target policy applied, and returned without any DNS lookup. Bracketed IPv6
  input is accepted and normalized.
- Domain input: validated (LDH/IDN via `x/net/idna`, at least two labels, no
  URL/shell characters), then A and AAAA records are resolved concurrently with
  the configured resolver under one bounded timeout (default 4 s). CNAMEs are
  followed by the resolver. Addresses are deduplicated, policy-filtered,
  sorted (IPv4 then IPv6) and capped (default 16).
- For client-side proxies, the actual DNS lookup happens on the Controller,
  not on Agents, and not in the browser.

Response:

```json
{
  "input": "example.com",
  "kind": "domain",
  "addresses": [
    { "ip": "203.0.113.10", "family": "ipv4" },
    { "ip": "203.0.113.11", "family": "ipv4" },
    { "ip": "2001:db8::10", "family": "ipv6" }
  ],
  "requires_selection": true,
  "truncated": false,
  "warnings": [
    "Agents trace the centrally resolved IP. For CDN and GeoDNS services, paths may differ from resolving the hostname locally on each Agent."
  ]
}
```

- If exactly one address is returned, `requires_selection=false` and the UI may
  preselect it, but must still display the exact numeric destination.
- If more than one address is returned, the UI MUST require an explicit choice;
  it must not silently pick the first one.
- Errors: `400 invalid_request`, `422 target_rejected`, `502 dns_failure`,
  `404 no_addresses` (domain exists but no usable A/AAAA records after policy),
  `429 rate_limited`.

### 2.7 `POST /api/v1/jobs`

Body (strict JSON, <= 8 KiB):

```json
{
  "target_ip": "203.0.113.10",
  "original_target": "example.com",
  "node_ids": ["tokyo-1", "frankfurt-1"],
  "protocol": "icmp",
  "max_hops": 30,
  "queries": 3,
  "timeout_ms": 60000
}
```

For `tcp`/`udp`, add `"port": 443` (or any bounded integer); the UI pre-fills
NextTrace's conventional defaults (80/TCP, 33494/UDP) but the user may change
the port. For `icmp`, `port` must be absent. The Controller enforces its own
`limits.allowed_protocols` in addition to each Agent's configuration.

The Controller revalidates the IP with `ipguard` (never trusts `/resolve`),
validates every node id against the administrative node table, enforces
authenticated/enabled nodes and server-side limits, generates the job id
(32 hex chars) and dispatches to all selected Agents through a bounded worker
pool. Returns `202`:

```json
{ "job": { /* Job document, status "pending" or "running" */ } }
```

One failing Agent never fails the job; each node has its own terminal status.
`original_target` is display-only metadata, bounded/sanitized and never sent to
Agents.

Errors: `400 invalid_request`, `403 forbidden` (unknown/disabled node),
`422 target_rejected`, `429 rate_limited` (per-user job rate), `503 busy`
(global job concurrency), `413 payload_too_large`.

### 2.8 `GET /api/v1/jobs/{id}`

Returns `200` `{"job": Job}` or `404 not_found`.

Job document:

```json
{
  "schema_version": "tracecat.controller.v1",
  "id": "8f0c2a1b4d5e6f708192a3b4c5d6e7f8",
  "status": "running",
  "target_ip": "203.0.113.10",
  "original_target": "example.com",
  "family": "ipv4",
  "protocol": "tcp",
  "port": 443,
  "max_hops": 30,
  "queries": 3,
  "timeout_ms": 60000,
  "created_at": "…",
  "started_at": "…",
  "ended_at": "",
  "created_by": "ops@example.com",
  "nodes": [
    {
      "node_id": "tokyo-1",
      "node_name": "Tokyo",
      "location": "Tokyo, JP",
      "provider": "DMIT",
      "status": "completed",
      "started_at": "…",
      "ended_at": "…",
      "duration_ms": 14800,
      "nexttrace_version": "v1.7.3",
      "parser_schema": "nexttrace.json.v1",
      "summary": { "hop_count": 12, "reached_destination": true, "destination_rtt_ms": 41.217, "replies": 30, "probes": 36 },
      "hops": [ /* as Agent trace response */ ],
      "error": null
    }
  ],
  "summary": {
    "total": 2, "pending": 0, "running": 0,
    "completed": 1, "failed": 1, "timed_out": 0, "cancelled": 0,
    "reached": 1
  }
}
```

`job.status`: `pending` -> `running` -> one of `completed` (all nodes
completed), `partial` (mixed outcomes with at least one completed), `failed`
(none completed), `cancelled`. Node statuses are `pending`, `running`,
`completed`, `failed`, `timed_out`, `cancelled`.

Per-node `error.code` is a stable normalized code: `agent_unreachable` (network
failure reaching the Agent), `agent_error` (Agent returned an HTTP error or an
invalid/oversized contract response), `nexttrace_unavailable`,
`nexttrace_failed`, `parse_error`, `output_too_large`, `timeout`, `cancelled`
or `internal`. Error messages never contain stderr, environment values,
executable paths or stack traces.

Aggregate and per-node retries are never performed silently.

### 2.9 `GET /api/v1/jobs`

Recent history, newest first, bounded by `max_history_jobs` and `?limit=`
(default 20, max 100). Hops are omitted:

```json
{
  "jobs": [
    {
      "id": "…", "status": "completed", "target_ip": "203.0.113.10",
      "original_target": "example.com", "family": "ipv4",
      "created_at": "…", "ended_at": "…",
      "summary": { "total": 2, "pending": 0, "running": 0, "completed": 2, "failed": 0, "timed_out": 0, "cancelled": 0, "reached": 2 }
    }
  ]
}
```

### 2.10 `POST /api/v1/jobs/{id}/cancel`

Requests cancellation of a job in `pending`/`running`. Idempotent. Cancels
in-flight Controller->Agent requests (the Agent then kills its process group).
Node statuses become `cancelled`. Returns `200 {"job": Job}`. Unknown job:
`404`; terminal job: `409 conflict`.

### 2.11 `GET /api/v1/jobs/{id}/events` (Server-Sent Events)

Live job-state notifications, authenticated via the session cookie (and CSRF is
not required for GET). Content type `text/event-stream`.

- On connect: one `event: job` event with the complete Job snapshot.
- On every job or node state change: one `event: job` event with the complete
  Job snapshot. This is state-change notification only: it is **not**
  hop-by-hop probe streaming and the UI must not claim otherwise.
- Keepalive comment line `: ping` every 15 s.
- Connection closes when the job reaches a terminal state or the client
  disconnects.
- Clients may fall back to polling `GET /api/v1/jobs/{id}`.

### 2.12 `GET /api/v1/jobs/{id}/export`

Returns a `Content-Disposition: attachment` JSON document:

```json
{
  "schema_version": "tracecat.controller.v1",
  "exported_at": "…",
  "job": { /* full Job */ },
  "raw_results": { "tokyo-1": { "Hops": [] } }
}
```

Raw NextTrace results are included only here, and only for authenticated
users. They are bounded and never interpreted as HTML.

### 2.13 `GET /healthz`

Unauthenticated liveness only:

```json
{ "status": "ok", "schema_version": "tracecat.controller.v1" }
```

No version, node, configuration or error details are exposed.

---

## 3. Security headers and transport

- Controller: `Content-Security-Policy` (self-hosted assets only, no inline
  scripts), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
- No permissive CORS. The frontend is served same-origin; cross-origin
  requests are not enabled in production.
- Agent: `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`.
- Client IP for rate limiting comes from the TCP peer unless it is a
  configured trusted proxy (e.g. loopback cloudflared); forwarding headers are
  otherwise ignored.

## 4. Data retention

The Controller stores jobs, per-node normalized results, bounded raw results
and local sessions in SQLite. History is trimmed to the newest
`max_history_jobs` jobs on insert. The original user input is stored only by
the Controller. Agents are stateless apart from rate-limit counters.
