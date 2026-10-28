# Testing

TraceCat's tests are hermetic: they never hit public traceroute targets, real
GeoIP providers or the internet, and they do not require root, membership in a
private overlay/VPC, or `CAP_NET_RAW`. NextTrace is replaced by a fake executable that
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
| Protocols/ports | `internal/nexttrace`, `internal/agent`, `internal/controller` | TCP/UDP capability detection, exact `-T/-U/-p` argv, port validation matrix, per-layer allowlists |
| Interfaces | `internal/agent`, `internal/controller` | enumeration/filtering/include, health advertisement, per-node `-D` dispatch, rejection matrix |
| Installer/release | `deploy/install_test.sh`, `verify/installer-remote-verify.sh` | URL/listen/origin parsing, checksum refusal, upgrade-keeps-config, token handling, dev/local auth installs |
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

## Verified run (this checkout)

Environment: macOS arm64, Go 1.27.3, Node 24/pnpm 12, NextTrace v1.7.1; plus a
Debian 13 host (systemd 257, Tailscale 1.104, NextTrace v1.7.3) for real
service deployment (`docs/VERIFICATION.md`).

| Command | Result |
| --- | --- |
| `gofmt -l $(find . -name '*.go')` | clean |
| `go vet ./...` | clean |
| `go test -race -count=1 ./...` | all packages `ok` (agent ≈8.6 s, controller ≈11.4 s, nexttrace ≈3.2 s, ipguard ≈1.3 s, cmd ≈2.0 s) |
| `pnpm --dir web typecheck` | exit 0 (strict TS) |
| `pnpm --dir web build` | exit 0; embedded assets regenerated |
| GitHub Actions CI (main) | Go vet/race/build and dashboard typecheck/build both green |

A real local stack (Controller dev mode on loopback, Agent bound to loopback,
real NextTrace v1.7.1) was exercised end to end:

- `/resolve` for a literal returned the normalized address with
  `requires_selection=false`; an injection attempt returned `invalid_request`;
  a private address returned `422 target_rejected`; a missing CSRF header
  returned `403`.
- A distributed job to `1.1.1.1` completed in ≈4 s with parsed hops, ASN
  `13335`, RTTs, `reached_destination=true`; SSE delivered the bare `Job`
  snapshot; export contained `raw_results`; history listed the job; cancelling
  a finished job returned `409`.
- A two-node job with one unreachable Agent produced `partial` with
  `agent_unreachable` on the failed node and an intact result for the healthy
  node.
- Cancelling a running trace killed the NextTrace process (verified with
  `pgrep`), returned `200` + `cancelled` for the node, and left no orphans.
- Dashboard flow (Chrome DevTools Protocol, real backend): resolve literal →
  select agents → start → live status → hop table/AS path → compare view →
  mobile layout, with no CSP violations, no console errors, and no spurious
  transport warnings on normal SSE completion.

An independent verifier reproduced the full matrix on a real Debian 13 host
with systemd and Tailscale, using the shipped units/config formats and
independently checking trace responses:
**329 PASS / 0 FAIL / 2 environment-N/A SKIPs** (Agent 126, Controller dev 125,
local auth 57, headless-browser 17/17), plus desktop/mobile screenshots and a
zero-violation CSP/console report. See `docs/VERIFICATION.md` for every check,
the three defects it found (all fixed and re-verified) and residual risks.
