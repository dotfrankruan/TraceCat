# Controller configuration

`tracecat-controller` reads exactly one JSON document, selected with `-config`
(default `/etc/tracecat/controller.json`). The loader is strict:

- unknown fields are rejected;
- any trailing data after the top-level object is rejected;
- the file is size-limited to 1 MiB;
- every value is validated before the HTTP listener is bound.

Two examples ship with the repository:

- [`configs/controller.example.json`](../configs/controller.example.json) —
  production-shaped `cloudflare` configuration;
- [`configs/controller.dev.json`](../configs/controller.dev.json) — loopback-only
  `dev` configuration for local fake Agents.

Run `tracecat-controller -version` to print build metadata and
`tracecat-controller -hash-password` to generate a local-mode password hash
(password is read from stdin, must be at least 12 characters; the hash is
printed to stdout).

## Secrets

**No secret is ever written in the JSON document.** Secrets are referenced by
environment-variable *name* and resolved at startup:

| Field | Meaning |
| --- | --- |
| `auth.local.password_hash_env` | name of the environment variable holding the PBKDF2 password hash |
| `agents[].token_env` | name of the environment variable holding that Agent's bearer token |
| `auth.cloudflare.csrf_secret_env` | optional; name of an environment variable holding a random secret used to derive stateless CSRF tokens (set it when running multiple Controller replicas) |

If a referenced environment variable is missing or empty, startup fails. Tokens
and hashes are never logged, returned by the API, or stored in SQLite.

Generate a local password hash:

```sh
read -rsp 'Password: ' PW; echo
printf '%s' "$PW" | tracecat-controller -hash-password
# pbkdf2-sha256$210000$<salt>$<hash>
```

The hash uses PBKDF2-HMAC-SHA256 with 210,000 iterations, a 16-byte random salt
and a 32-byte derived key, encoded as
`pbkdf2-sha256$<iterations>$<salt base64url>$<key base64url>`. Verification is
constant time.

## Top-level fields

### `listen` (string, default `127.0.0.1:8080`)

`host:port` to bind. The host must be a literal IP address and must not be a
wildcard (`0.0.0.0`, `::`, empty host). The Controller is normally placed behind
Cloudflare / a local reverse proxy, so the default loopback bind is intentional;
put it behind Tailscale or your reverse proxy if browsers connect directly.

### `public_origin` (string)

Externally visible browser origin, normalized to `scheme://host[:port]`. Used
for:

- `Origin` / same-origin CSRF checks;
- the `Secure` attribute of the local-mode session cookie.

Rules: absolute `http` or `https` URL, no credentials, no path (only `/`), no
query and no fragment. `http` is only accepted for loopback addresses; every
other deployment must use `https`. In `dev` mode the value may be omitted and
defaults to `http://<listen-host>:<listen-port>`.

### `auth` (object, required)

`auth.mode` is one of `cloudflare`, `local`, `dev`. Exactly the section matching
the chosen mode may be populated; populated fields for another mode are
rejected to prevent dangerous misconfiguration.

#### `auth.mode = "cloudflare"`

Production mode. Every API request must carry a verified Cloudflare Access JWT,
either in the `Cf-Access-Jwt-Assertion` header or in the `CF_Authorization`
cookie (header wins).

| Field | Required | Meaning |
| --- | --- | --- |
| `auth.cloudflare.team_domain` | yes | Cloudflare Access team domain, `https://<team>.cloudflareaccess.com`, no path |
| `auth.cloudflare.audience` | yes | non-empty list of expected Access application audience tags |
| `auth.cloudflare.allowed_emails` | no | exact, case-insensitive email allowlist |
| `auth.cloudflare.allowed_email_domains` | no | exact email-domain allowlist (the part after `@`); a configured allowlist is fail-closed |
| `auth.cloudflare.jwks_cache_ttl_seconds` | no | JWKS cache TTL, 30..86400, default 300 |
| `auth.cloudflare.csrf_secret_env` | no | env var holding a >=16-byte HMAC secret for stateless CSRF tokens; a random per-process secret is used when omitted (set it for multi-instance deployments) |

JWT verification: compact JWS, `RS256` only, `kid` must resolve in the team's
JWKS (`<team_domain>/cdn-cgi/access/certs`), `iss` must equal the team domain,
`aud` must contain a configured audience, `exp`/`nbf`/`iat` are checked with
60 seconds of leeway, and the optional email/domain allowlists are applied.
JWKS documents are size-limited, fetched with timeouts, cached, and refreshed
when an unknown `kid` appears at most once per 10-second window so key rotation
works without a restart. Identity headers such as
`Cf-Access-Authenticated-User-Email` are **never** trusted.

#### `auth.mode = "local"`

Password login with server-side sessions.

| Field | Required | Meaning |
| --- | --- | --- |
| `auth.local.password_hash_env` | yes | env var holding the PBKDF2 hash (see above) |
| `auth.local.session_ttl_seconds` | no | session lifetime, 60..2592000 seconds, default 43200 (12 h) |

`POST /api/v1/auth/login` is rate limited to 10 attempts per minute per client
IP. Successful login creates a random 256-bit session token stored as its
SHA-256 hash in SQLite with a per-session CSRF token. The cookie is
`HttpOnly; SameSite=Strict; Path=/`, and `Secure` whenever `public_origin` is
`https`. `POST /api/v1/auth/logout` revokes the row and clears the cookie;
expired sessions are purged opportunistically on login.

#### `auth.mode = "dev"`

Explicit loopback-only authentication bypass. It is refused unless `listen` is a
loopback address, and any API request carrying `X-Forwarded-For`, `X-Real-IP` or
`X-Forwarded-Host` is rejected with `403`. The session endpoint still returns a
CSRF token and state-changing requests still require it. Never expose a dev-mode
listener to an untrusted network; the session response includes a warning.

### `database`

| Field | Required | Meaning |
| --- | --- | --- |
| `database.path` | yes | SQLite file path (parent directories are created); `:memory:` is accepted for throwaway runs |
| `database.max_history_jobs` | no | number of jobs retained, 1..10000, default 200 |

SQLite runs with WAL, `busy_timeout=5000`, foreign keys on and a single pooled
connection. A missing database is created; a corrupt or inaccessible database
fails startup with a clear error rather than being replaced. The schema stores
the full bounded `model.Job` in `jobs`, per-node results and bounded raw
NextTrace output in `job_nodes`, and local sessions in `sessions`. History is
trimmed to the newest `max_history_jobs` rows on every write.

`limits.max_history_jobs` is accepted as an alias for convenience; if both are
set they must agree.

### `dns`

Central resolution happens on the Controller, never on Agents or in browsers.

| Field | Required | Meaning |
| --- | --- | --- |
| `dns.timeout_ms` | no | total budget for the concurrent A+AAAA lookup, 100..10000, default 4000 |
| `dns.max_addresses` | no | maximum returned addresses, 1..32, default 16 |
| `dns.resolver` | no | optional custom resolver as `host:port`; the host must be an IP literal or hostname and UDP is used. Omit to use the system resolver |

Literal IP targets never trigger DNS. Domain targets are IDNA-normalized with
`x/net/idna` (`xn--` punycode), A and AAAA lookups run concurrently under one
bounded context, CNAMEs are followed by the resolver, addresses are unmapped,
deduplicated, policy-filtered with `internal/ipguard`, sorted IPv4-first then
IPv6, and truncated to `max_addresses` (`truncated=true`). Resolution returns
404 `no_addresses` when a successful lookup yields nothing usable after policy
filtering, and 502 `dns_failure` for resolver errors/timeouts. Every domain
result includes the CDN/GeoDNS warning from `docs/API.md`.

### `limits`

Server-side allowlist of user-selectable limits and Controller resource
controls. The frontend renders these values from `GET /api/v1/session` instead
of hardcoding them.

| Field | Default | Range | Meaning |
| --- | --- | --- | --- |
| `limits.max_hops` | 30 | 1..64 | maximum `max_hops` a user may request |
| `limits.max_queries` | 3 | 1..5 | maximum `queries` a user may request |
| `limits.min_execution_ms` | 5000 | 5000..120000 | minimum `timeout_ms` |
| `limits.max_execution_ms` | 60000 | >= `min_execution_ms`, <= 120000 | maximum `timeout_ms` |
| `limits.max_nodes_per_job` | 8 | 1..16 | maximum Agents per job |
| `limits.max_jobs_per_minute` | 30 | 1..10000 | per-user/client job creation rate |
| `limits.max_concurrent_jobs` | 4 | 1..256 | global worker pool size (excess jobs get `503 busy`) |
| `limits.max_concurrent_traces` | 4 | 1..256 | simultaneous Controller->Agent trace requests |
| `limits.max_resolves_per_minute` | 120 | 1..10000 | per-client `/resolve` rate |
| `limits.max_raw_result_bytes` | 1048576 | 0..16777216 | per-node raw NextTrace result retained for export; larger output is dropped |
| `limits.max_history_jobs` | 200 | 1..10000 | alias of `database.max_history_jobs` (must agree if both set) |

### `agents` (array, required, 1..16 entries)

Administratively configured Agents. There is no API to add or change Agents at
runtime, and the browser never receives Agent URLs or tokens.

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | node id matching `^[a-z0-9][a-z0-9_-]{0,31}$`, unique |
| `name` | yes | display name (<=64 sanitized characters) |
| `location` | no | display location (<=128 sanitized characters) |
| `provider` | no | display provider (<=128 sanitized characters) |
| `url` | yes | Agent base URL, see transport rules below |
| `token_env` | yes | env var holding the Agent bearer token |
| `enabled` | no | defaults to `true`; disabled Agents never receive jobs and report `health: "disabled"` |
| `request_timeout_ms` | no | per-request cap for Controller->Agent calls; default `limits.max_execution_ms + 15000`; range `limits.max_execution_ms + 5000` .. 600000 |

Agent URL transport rules:

- scheme must be `http` or `https`;
- no credentials, query, fragment or path (a single `/` is allowed);
- hostname hosts require `https` (their cleartext policy cannot be classified
  without resolving, so cleartext is never allowed);
- literal IP hosts may use `http` only when `ipguard.IsNonPublic` classifies the
  address as loopback/private/link-local/Tailscale/otherwise non-public;
  cleartext `http` to a public IP is rejected because it would expose the
  bearer token;
- ports are validated (1..65535).

In the MVP Agents serve plain HTTP on their Tailscale address (or another
private address), so the example configuration uses `http://100.64.x.x:PORT`.
Cleartext on the private tailnet is accepted because that address is
non-public; it never leaves the tailnet. Production deployments may terminate
TLS with Tailscale Serve, an SNI proxy or a sidecar and configure `https://`
Agent URLs instead — public IPs and hostnames always require `https`.

Per-node dispatch timeout is the user's `timeout_ms` plus a 10-second margin,
capped by `request_timeout_ms`. Redirects are never followed, response bodies
are capped at 16 MiB, and Agent errors are mapped per node
(`agent_unreachable`, `agent_error`, `timed_out`, `cancelled`) without failing
other nodes in the same job.

### `trusted_proxies` (array of CIDR strings)

Addresses allowed to supply client-IP forwarding headers (for example a
loopback `cloudflared`). The TCP peer is used unless it belongs to one of these
CIDRs, in which case the nearest non-trusted `X-Forwarded-For` hop (or
`X-Real-IP`) is used. Default routes (`0.0.0.0/0`, `::/0`) are rejected. Leave
empty if no proxy sits in front of the Controller; forwarding headers from
untrusted peers are always ignored.

### `log_level` (string)

One of `debug`, `info`, `warn`, `error` (default `info`). Logs are structured
JSON on stderr and never contain tokens, password hashes, session cookies or
Authorization headers. Request logs omit query strings and headers.

## Operational notes

- Graceful shutdown on `SIGINT`/`SIGTERM` stops accepting connections, closes
  SSE streams, cancels in-flight jobs, waits up to 10 seconds, then closes the
  database.
- The Agent health poller starts with the process (immediate check, then every
  30 seconds). `GET /api/v1/nodes` reports the cached state:
  `ok`, `degraded`, `unreachable`, `unknown` or `disabled`.
- SSE (`GET /api/v1/jobs/{id}/events`) sends a bare job snapshot as
  `event: job` on connect and on every state change, `: ping` every 15 seconds,
  and closes when the job reaches a terminal state or the client disconnects.
- Raw NextTrace results are only exposed by
  `GET /api/v1/jobs/{id}/export`, are bounded by `limits.max_raw_result_bytes`
  and are never interpreted as HTML.
