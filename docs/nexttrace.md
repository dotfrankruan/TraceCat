# NextTrace integration

TraceCat does not implement traceroute itself. The Agent executes an
administrator-installed [NextTrace](https://github.com/nxtrace/NTrace-core)
binary as a separate, unprivileged child process and normalizes its JSON output
into the TraceCat wire contract (`docs/API.md` §1).

This document describes the supported NextTrace versions and flags, how they
are detected, how the Agent invokes the binary safely, what Linux privilege the
binary needs, and the GPL-3.0 licensing relationship.

---

## 1. Trust boundary and rules

Only the Agent talks to NextTrace. The Controller and browser never influence
the executable path, arguments or environment.

- **Fixed executable path.** `nexttrace.binary` is an absolute path from the
  Agent configuration. It is validated at startup (existing regular file,
  executable, not world-writable) and is never derived from a request.
- **Typed argument vector only.** Arguments are built from validated,
  already-normalized values (`netip.Addr`, enum family/protocol, bounded
  integers). There is no string concatenation of user input into a command
  line, no shell (`sh`, `bash`, `eval`, `exec`) and no environment expansion.
- **Target is always last.** The final argument is the canonical
  `netip.Addr.String()` of the destination. Requests carrying hostnames,
  brackets, zones, whitespace, shell metacharacters or IPv4-mapped IPv6 forms
  are rejected before any execution.
- **Minimal fixed environment.** The child receives exactly
  `PATH`, `HOME`, `LANG=C`, `LC_ALL=C` and `NO_COLOR=1`. Agent tokens,
  configuration and unrelated environment variables are never inherited.
- **Process-group supervision.** Every execution has an overall deadline
  derived from the request's `timeout_ms` (capped by the Agent configuration).
  On timeout, shutdown or client disconnect the whole process group is
  `SIGKILL`ed (Unix process groups; a parent-only kill fallback exists on
  platforms without POSIX process groups), so no orphaned NextTrace processes
  survive.
- **Bounded output.** stdout is capped by `nexttrace.max_stdout_bytes`
  (default 4 MiB); exceeding it kills the process group and reports
  `output_too_large`. stderr is capped separately at 64 KiB and is **never**
  returned to callers or included in API responses.

---

## 2. Supported NextTrace versions and flags

TraceCat's Agent is developed and verified against the **v1.7.x line**,
specifically **v1.7.1** and **v1.7.3**. Other builds are usable only if they
expose the required command-line surface below; the Agent never assumes a flag
exists.

The Agent detects flags from the installed binary's own `--version` and
`--help` output at startup:

| Capability reported by `/v1/health` | Flag detection requirement | Required |
| ----------------------------------- | -------------------------- | -------- |
| `json`                              | `--json`                   | yes      |
| `ipv4`                              | `-4` (or `--ipv4`)         | yes      |
| `ipv6`                              | `-6` (or `--ipv6`)         | yes      |
| `max_hops`                          | `-m` or `--max-hops`       | yes      |
| `queries`                           | `-q` or `--queries`        | yes      |
| `timeout`                           | `--timeout`                | optional |
| `traceroute`                        | `--traceroute`             | optional |

If a required flag is missing, the Agent still starts but reports
`status: "degraded"` on `/v1/health`; every `POST /v1/trace` then returns HTTP
200 with `status: "failed"` and `error.code: "nexttrace_unavailable"`. The
executable path is never included in health responses or errors.

The argument constructor uses the short spellings (`-m`, `-q`) when detected,
falling back to the long spellings (`--max-hops`, `--queries`) otherwise. The
`--traceroute` flag is inserted immediately after the family flag only when it
was detected. `--timeout` is included only when detected.

### Exact argument vectors (ICMP)

IPv4, verified NextTrace v1.7.1, `max_hops=30`, `queries=3`,
`probe_timeout_ms=1000`:

```text
-4 --json -q 3 -m 30 --timeout 1000 1.1.1.1
```

IPv6:

```text
-6 --json -q 3 -m 30 --timeout 1000 2606:4700:4700::1111
```

When the binary exposes `--traceroute`, it is added directly after the family
flag:

```text
-4 --traceroute --json -q 3 -m 30 --timeout 1000 1.1.1.1
```

The target is always the last argument. The Agent re-checks the constructed
vector against a strict allowlist before `exec` (family flag, optional
`--traceroute`, `--json`, queries flag + value, max-hops flag + value, optional
`--timeout` + value, canonical target), and rejects any mismatch as an internal
error instead of executing.

---

## 3. Capability detection

At startup the Agent runs:

1. `<binary> --version` with a **5 s** bound, parsing a normalized version
   (`v1.7.1`, `v1.7.3`, …) from the output.
2. `<binary> --help` with a **5 s** bound, scanning for standalone flag tokens.

Detection never exposes the executable path, raw command output or
environment. Failures collapse to safe messages such as
`nexttrace capability detection timed out` or
`installed nexttrace does not support the flags TraceCat requires`.

`GET /v1/health` (authenticated with the Agent bearer token) reports the
cached result:

```json
{
  "status": "degraded",
  "nexttrace": {
    "available": false,
    "version": "v1.7.2",
    "capabilities": ["ipv4", "ipv6", "max_hops", "queries"],
    "error": {
      "code": "nexttrace_unavailable",
      "message": "installed nexttrace does not support the flags TraceCat requires"
    }
  },
  "limits": {
    "max_hops": 64,
    "max_queries": 5,
    "max_timeout_ms": 60000,
    "max_concurrent_traces": 4
  }
}
```

The Controller uses this authenticated endpoint for health polling; the Agent
never serves health data without a valid bearer token.

---

## 4. Configuration reference (`nexttrace` section)

```json
{
  "nexttrace": {
    "binary": "/usr/local/bin/nexttrace",
    "max_concurrent_traces": 4,
    "probe_timeout_ms": 1000,
    "max_execution_ms": 60000,
    "max_stdout_bytes": 4194304,
    "max_raw_bytes": 1048576,
    "geo_provider": ""
  }
}
```

| Field                    | Default     | Meaning |
| ------------------------ | ----------- | ------- |
| `binary`                 | required    | Absolute path to the NextTrace executable; must be a regular, executable, non-world-writable file. |
| `max_concurrent_traces`  | `4`         | Maximum simultaneous NextTrace processes; excess requests receive `503 busy`. |
| `probe_timeout_ms`       | `1000`      | Per-probe timeout passed via `--timeout` when supported (agent setting, never a request field). |
| `max_execution_ms`       | `60000`     | Local cap on the overall execution deadline; also the maximum request `timeout_ms` accepted. |
| `max_stdout_bytes`       | `4194304`   | Hard stdout cap; exceeding it kills the process group and reports `output_too_large`. |
| `max_raw_bytes`          | `1048576`   | Maximum raw NextTrace JSON retained in the response; larger results set `raw_result_truncated=true` and omit `raw_result`. |
| `geo_provider`           | `""`        | Reserved allowlisted provider hint (`ipinfo`, `ip-api`, `ipdb`, `maxmind`, `cloudflare`, `none`); it does not alter the argv in the MVP. |

NextTrace execution is additionally limited by `security.allowed_cidrs`,
`security.allow_private_targets` (default `false`) and the global `ipguard`
destination policy. The Agent revalidates the target even though the Controller
already did.

---

## 5. Output dialect and normalization

The Agent's parser (`internal/nexttrace/parser.go`) accepts the current
NextTrace v1.7.x JSON shape and the older flat variant, and ignores unknown or
newly added fields:

- grouped (current): `{"Hops": [[{...}, {...}], ...]}` where the outer array
  is per-TTL and the inner array is per-query;
- flat: `{"Hops": [{...}, ...]}`.

Normalization rules:

- Probes are grouped by `TTL`, sorted ascending, matching `model.Hop`.
- `Rtt` is interpreted as **nanoseconds** and converted to milliseconds with
  three decimals; `0` means unknown and is omitted. Failed probes never carry
  an RTT.
- `Address.IP` becomes a canonical `netip` string (unmapped, zone-free);
  unparseable values are omitted rather than echoed.
- `Success: false` maps to `error_code`: `no_reply` when `Error` is `null` or
  `{}`, `unreachable` when the error text indicates unreachability, otherwise
  `unknown`. `no_reply` is not evidence that a route is broken.
- `Geo` may be `null`. Names prefer the `*_en` variants when non-empty.
  `asnumber` accepts strings such as `"13335"` or `"AS13335"`.
- `lat`/`lng` are included only when both are valid and either the Geo entry
  has an IP/country identity or the coordinates are non-zero (NextTrace uses
  `0` for unknown, but `0,0` is a legitimate coordinate).
- Every string is sanitized with `model.SanitizeText` (invalid UTF-8, control
  characters and ANSI escapes removed) and capped: PTR 253, names 128, ISP
  128, prefix 64, MPLS at most 8 entries of 64 characters.
- `TraceSummary` is derived from observed hops only; missing data stays
  missing.
- Unparseable or structurally unexpected JSON yields `parse_error`; the parser
  never returns partially fabricated hops. The raw JSON is retained unmodified
  only when it fits `max_raw_bytes`; otherwise `raw_result_truncated=true`.

Trace-internal outcomes are always HTTP 200 with a terminal node status
(`completed`, `failed`, `timed_out`, `cancelled`) and a stable error code
(`nexttrace_unavailable`, `nexttrace_failed`, `parse_error`, `timeout`,
`cancelled`, `output_too_large`, `internal`).

---

## 6. Linux capabilities

NextTrace needs raw ICMP sockets, which requires `CAP_NET_RAW`; a normal
unprivileged process lacks it. Grant the capability to the **binary**, not to
the Agent:

```bash
# Debian/Ubuntu/Fedora/Arch package layout
sudo setcap cap_net_raw+ep /usr/local/bin/nexttrace
getcap /usr/local/bin/nexttrace
# /usr/local/bin/nexttrace cap_net_raw=ep
```

Notes:

- The Agent itself runs unprivileged. Do **not** run the Agent as root; running
  the Agent as a non-root user is required for the hardening rules to be
  meaningful.
- Package upgrades may replace the binary and drop the capability. Re-apply
  `setcap` after upgrading NextTrace (and verify with `getcap`).
- Some kernels/filesystems mount images with `nosuid` or similar restrictions;
  if `setcap` fails or the capability is ignored, use the ambient-capability
  variant below.
- If you prefer not to mark the file, grant the capability to the Agent service
  via systemd ambient capabilities and inherit it to the child:

  ```ini
  [Service]
  User=tracecat
  AmbientCapabilities=CAP_NET_RAW
  CapabilityBoundingSet=CAP_NET_RAW
  # Keep the rest of the unit's hardening; AmbientCapabilities is inherited by
  # the NextTrace child executed by the Agent.
  ```

  The `setcap` approach is preferred because it limits the capability to the
  external binary instead of the whole Agent process tree.
- The Agent checks that the executable is an absolute path, a regular file,
  executable and not world-writable before use.

---

## 7. Licensing: NextTrace is an external GPL-3.0 program

NextTrace (the `nexttrace` binary, from the NTrace-core project) is licensed
under the **GNU General Public License v3.0**. TraceCat does not embed, link,
vendor or modify NextTrace:

- The Agent invokes the separately installed executable as a child process
  using the public command-line interface and parses its JSON output. This is
  an arm's-length external-binary relationship, not a derivative work or a
  linked combined work.
- TraceCat's own source remains under its own license; distributing TraceCat
  does not by itself require licensing TraceCat under the GPL, provided
  NextTrace is not bundled.
- If you redistribute NextTrace together with TraceCat (for example in an
  image or package), you must comply with the GPL-3.0 for that binary:
  include the license text, provide the corresponding source (or a valid
  written offer), and preserve notices. See the NextTrace project for the
  authoritative terms and source.
- Users install NextTrace separately; the Agent never downloads or updates it.

---

## 8. Testing this integration

The deterministic fake in `internal/nexttrace/testdata/fake/main.go` stands in
for the real binary in tests. It records argv and environment, and can emit
configurable JSON, stderr, exit codes, delays, oversized output and even spawn
a child process to verify process-group cleanup. No test performs real network
traceroute or requires NextTrace to be installed.

Run the focused suites:

```bash
go test ./internal/nexttrace/...
go test ./internal/agent/...
go test -race ./internal/nexttrace/... ./internal/agent/... ./cmd/tracecat-agent/...
```
