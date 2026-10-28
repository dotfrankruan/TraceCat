# Testing

TraceCat's tests are hermetic: they never hit public traceroute targets, real
GeoIP providers or the internet, and they do not require root, Tailscale
membership or `CAP_NET_RAW`. NextTrace is replaced by a fake executable that
records its argv and emits fixture JSON.

## Commands

```bash
make test        # go test ./...
make test-race   # go test -race ./...
make vet         # go vet ./...
make check       # vet + tests + dashboard typecheck/build (when pnpm present)
```

Dashboard-only checks:

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web run typecheck
pnpm --dir web build
```

## Test layers

| Layer | Location | What it proves |
| --- | --- | --- |
| Destination policy | `internal/ipguard` | default-deny classes, IPv4-mapped bypass, admin allowlist, invalid input/zone/brackets, Tailscale range classification |
| NextTrace command/parser | `internal/nexttrace` | capability detection against both comma-style and real pflag-style help output (`-j  --json`), exact argv, no-shell execution, process-group timeout/cancel, stdout/stderr caps, schema variants, metadata sanitization, raw retention |
| Agent HTTP | `internal/agent` | bearer auth, strict JSON, body limits, target revalidation, rate limit, concurrency, status/error mapping, health, config validation |
| Controller | `internal/controller` | DNS (A/AAAA, IDN, failures, limits), Access JWT verification, local sessions/CSRF, job dispatch/partial failure/cancel, SSE, SQLite history/trim, security headers, rate limits |
| Dashboard | `web` | strict TypeScript, production build embedded by `internal/webui` |

## Security test matrix

<!-- Filled from the verified run; keep this table in sync with the suite. -->

| Attack / failure | Test evidence |
| --- | --- |
| Shell metacharacters in target | `internal/ipguard`: `1.1.1.1; touch /tmp/pwned`, `$(id)`, backticks, newline injection rejected; Agent tests assert 422 `target_rejected` before spawn |
| Argument injection | `internal/nexttrace`: `--help`, `-4`, `-o /etc/passwd`, extra positional rejected by IP parsing; argv assertions on the fake binary |
| No shell launched | fake NextTrace records argv and environment; arguments are exactly the allowlisted vector |
| Invalid IPv4/IPv6 | parser rejects `999.999.999.999`, `1.1.1`, `[2606::1]`, zone IDs, Unicode digits |
| IPv4-mapped IPv6 | `::ffff:127.0.0.1`, `::ffff:10.0.0.1` rejected; mapped global unmapped and allowed |
| Private/reserved destinations | loopback, RFC1918, CGNAT, link-local, multicast, documentation, benchmark, NAT64/Teredo/6to4 rejected by both layers |
| Multiple DNS results | resolver returns v4+v6; `requires_selection=true`; no auto-pick |
| DNS failure / empty results | `dns_failure` / `no_addresses`; no job created |
| Unauthorized Agent access | missing/wrong bearer token => 401; no trace executed |
| Malformed NextTrace JSON | `parse_error`, no partial hop data |
| Oversized stdout/stderr | `output_too_large`, process group killed, stderr never returned |
| Process timeout/cancellation | `timed_out` / `cancelled`; fake child process group reaped |
| Too many concurrent requests | 503 `busy` (semaphore) and 429 `rate_limited` (token bucket) |
| Invalid Agent/Controller config | wildcard/missing Tailscale bind, invalid node URLs, bad secrets, default-route allowlist rejected at startup |
| Malicious HTML in ASN/PTR/GeoIP | sanitized (`<script>`, control chars, bidi); frontend renders text only, no `dangerouslySetInnerHTML` |
| Controller errors / partial Agent failures | one node fails => `partial`; other results intact; body/type/schema violations rejected |
| Cloudflare Access JWT | bad signature/issuer/audience/expired tokens rejected; spoofed identity headers ignored |
| CSRF / Origin | missing/mismatched CSRF token and cross-origin state changes rejected |

## End-to-end verification (documented separately)

The MVP is additionally exercised end to end on a Linux host with real systemd
and Tailscale, using the real NextTrace binary for one-shot ICMP traces and a
loopback Agent for deterministic tests. See the verification section in the
final report / `docs/DEPLOYMENT.md` verification checklist.
