# Changelog

All notable changes to TraceCat are documented here. The project follows
[Semantic Versioning](https://semver.org/) and the wire contract carries its own
schema versions (`tracecat.agent.v1`, `tracecat.controller.v1`).

## [Unreleased]

### Added

- **Automatic Agent enrollment.** Agents can register themselves with the
  Controller over an authenticated enrollment endpoint
  (`POST /api/v1/agents/enroll`, high-entropy shared enrollment token), receive
  their own per-Agent trace token, and appear in the dashboard automatically;
  no machine list in the Controller command line or config. Registered Agents
  persist across restarts and static configuration still takes precedence.
  The installer enables enrollment by default for new Controllers
  (`--no-enrollment` opts out); Agents install with
  `agent --controller <url>` and the enrollment token supplied via the
  environment. Multi-Agent is the documented default path; the one-command
  quickstart is explicitly a single-host demo.
- One-command quickstart (`deploy/quickstart.sh`): installs a loopback-only
  Controller + Agent, generates local-auth credentials, and prints the URL and
  password. README/QUICKSTART/DEPLOYMENT now lead with this path; the existing
  installer remains for multi-host/private-network deployments.

## [0.1.1] — 2026-10-28

### Added

- **Optional TCP and UDP traceroute** in addition to ICMP. The protocol is a fixed
  enum (`icmp`/`tcp`/`udp`) mapped to capability-detected NextTrace flags, and
  TCP/UDP probes require an explicit destination port bounded to `1..65535`
  (numeric only). Both Controller and Agent enforce their own
  `allowed_protocols` allowlist; the dashboard exposes a protocol selector and
  validated port input, and protocol/port are stored, displayed and exported
  with each job. MTR sessions remain unsupported.
- **Per-Agent network interface selection.** Agents enumerate eligible
  interfaces (Up, non-loopback, usable address; container/bridge/virtual names
  excluded by default, with admin `interfaces.exclude`/`interfaces.include`),
  advertise them in `/v1/health`, and accept a per-node `node_interfaces`
  selection that maps to a fixed NextTrace `-D` argument. The dashboard exposes
  an Automatic/interface selector for each selected Agent. Auto means OS
  routing.
- **Generic private bind policy.** The Agent no longer assumes Tailscale: any
  explicitly configured, assigned non-public address is accepted (overlay, VPC,
  RFC1918, CGNAT, ULA, loopback); public binds require an explicit
  `security.allow_public_bind` opt-in. Tailscale is documented as one option,
  with no tag/API dependency.
- **Deployment automation.** GitHub Actions release workflow builds
  linux/amd64 + linux/arm64 Controller/Agent tarballs with checksums and
  publishes them to the release; `deploy/install.sh` installs or upgrades a
  host end to end (verified download, systemd units, service user, generated
  configs/secrets, token handling). A local `scripts/build-release.sh`
  reproduces the packaging for offline/CI testing.
- **Quick Start guide** (`QUICKSTART.md`) covering the local stack, protocol/port
  selection, interface selection and troubleshooting.

## [0.1.0] — 2026-10-28

Initial deployable MVP: a Go Controller + Tailscale-only Go Agents running the
external NextTrace CLI, with an embedded React dashboard.

### Added

- **Controller**: central A/AAAA + IDN resolution with bounded timeout,
  deduplication and destination-policy filtering; explicit multi-address
  selection; bounded worker pool and per-node timeouts; per-node
  Pending/Running/Completed/Failed/Timed out/Cancelled states with partial-job
  aggregation; cancellation; SSE state-change snapshots; bounded SQLite history
  and JSON export (including bounded raw NextTrace output).
- **Authentication**: Cloudflare Access JWT verification (RS256, cached JWKS,
  issuer/audience/expiry, optional email allowlists) and local PBKDF2 password
  sessions with HttpOnly/SameSite cookies and CSRF; default-deny middleware;
  explicit loopback-only `dev` mode; strict schemas, body limits, rate limits,
  security headers/CSP and same-origin-only browser API.
- **Agent**: unprivileged service bound only to its configured Tailscale
  address; per-Agent bearer token (constant-time); independent revalidation of
  every request and the destination policy; typed NextTrace argument builder
  with capability detection; process-group supervision and bounded
  stdout/stderr; strict version-aware JSON parser with metadata sanitization.
- **Target policy**: default-deny global-unicast-only destination policy shared
  by Controller and Agent, IPv4-mapped-IPv6 unmap-before-classify, and an
  explicit administrator CIDR allowlist on both sides.
- **Dashboard**: dark, responsive React/TypeScript/Tailwind UI with DNS address
  selection, agent multi-select, live job state, dense hop tables, deterministic
  ASN colors, AS-path visualization, side-by-side comparison with honest deltas,
  bounded history and JSON export. Built assets are committed and embedded;
  Node.js is build-time only.
- **Deployment**: example configs, systemd units with sandboxing, Docker/
  compose for the Controller, Tailscale ACL and Cloudflare Tunnel examples,
  deployment and security documentation, CI and Dependabot.
- **Verification**: hermetic fake-NextTrace test harness, adversarial security
  suite, and an independent real-host deployment verification report
  (`docs/VERIFICATION.md`): 329 PASS / 0 FAIL / 2 environment-N/A SKIPs across
  Agent, Controller, local-auth and headless-browser suites.

### Fixed during hardening

- NextTrace v1.7.x capability detection with real pflag-style help output
  (`-j  --json`).
- NextTrace v1.7.x non-root privilege advisory printed before JSON is now
  tolerated without weakening JSON validation or retaining the banner.
- `MemoryDenyWriteExecute` removed from the Agent systemd unit (NextTrace v1.7.3
  SIGSEGVs under a W^X policy); kept on the Controller, which never execs it.
- Reverse DNS: NextTrace's top-level `Hostname` field is parsed (previously
  `Address.Domain` only).
- Job concurrency slot is released before the terminal state is published,
  removing a transient `503` race after a job finishes.
- Interrupted jobs are reconciled to `failed` on Controller restart instead of
  remaining "running" in history.
- Dashboard no longer reports the expected SSE close after a terminal snapshot
  as a transport error.
- Controller `security.allowed_cidrs` added so private-lab destinations can be
  explicitly approved at both layers.
- Controller rate-limit responses now include `Retry-After`, and local login
  enforces `Content-Type: application/json` (`415`) like the Agent API.

### Changed

- Agent configuration schema: removed `security.require_tailscale_bind` and
  `security.allow_non_tailscale_bind`; added `security.allow_public_bind` and
  top-level `interfaces.{exclude,include}`. Histories with old configs must be
  updated (strict JSON rejects unknown keys).

### Verification

Independently verified on Debian 13 + systemd + a private overlay with real
NextTrace v1.7.3. **v0.1.1 delta: 408 PASS / 0 FAIL / 3 informational SKIPs**
(Agent 174, Controller 155, installer/release 61, headless browser 18/18),
including real TCP/UDP traces, exact child argv, interface selection, bind
policy and one-command installer checks. Three installer P1 defects were found
during the delta and fixed before release (`docs/VERIFICATION.md` §13).

### Known limitations

See the "Limitations" section of `README.md`: one-shot ICMP/TCP/UDP only, single-tenant
authorization, no job resumption after a Controller restart, cleartext HTTP
inside the tailnet, third-party GeoIP accuracy, and in-memory per-instance rate
limits.
