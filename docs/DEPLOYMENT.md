# Deployment

TraceCat has two deployables:

- **Controller** — one instance. Serves the dashboard/API, resolves DNS,
  schedules jobs, stores history in SQLite.
- **Agent** — one per vantage point. Binds an explicit private address, runs the
  locally installed NextTrace binary, requires a per-Agent bearer token.

Releases are built by CI for **linux/amd64** and **linux/arm64** as
self-contained tarballs (dashboard embedded, no Node.js or runtime
dependencies). The easiest path is the installer; manual systemd and Docker
instructions follow for custom setups.

## TL;DR

```bash
# Single host, one command (Controller + Agent on loopback, local auth):
curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/quickstart.sh | sudo bash

# Distributed (default): enrollment is on; the installer prints the Agent command.
sudo bash /tmp/tracecat-install.sh controller --auth cloudflare \
  --listen 10.0.0.10:8080 --public-origin https://trace.example.com \
  --cf-team-domain https://your-team.cloudflareaccess.com --cf-audience AUD_TAG

# then on each Agent host (auto-detects a private IP:8443):
TRACECAT_ENROLLMENT_TOKEN='<token printed by the Controller>' \
  sudo -E bash /tmp/tracecat-install.sh agent --controller http://10.0.0.10:8080
```

The full reference is below.

> **Networking:** TraceCat does not require Tailscale and does not use tags.
> Any private overlay, VPC or tunnel is fine as long as the Controller can reach
> each Agent's `listen` address and nothing else can. See
> [PRIVATE-NETWORKING.md](PRIVATE-NETWORKING.md).

---

## 1. Installer (recommended)

The installer supports **first install and upgrades**. It reads the matching
release asset from GitHub, verifies its SHA-256 against `checksums.txt`,
installs the binary, a hardened systemd unit and a validated config, creates a
dedicated `tracecat` system user, generates secrets locally, and enables the
service. Existing configs are preserved unless `--force` is passed (the old file
is backed up).

```bash
curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/install.sh \
  -o /tmp/tracecat-install.sh
sudo bash /tmp/tracecat-install.sh --help
```

### 1.1 Agent first (it prints the token the Controller needs)

On each vantage point (Linux, systemd, NextTrace already installed):

```bash
sudo bash /tmp/tracecat-install.sh agent \
  --listen 10.0.0.5:8443
```

- `--listen` must be an assigned **non-public** address (RFC1918, CGNAT, ULA,
  loopback for local use, or an overlay address). Wildcards are refused and
  public binds require `--allow-public-bind` explicitly.
- NextTrace is discovered in `PATH`; override with
  `--nexttrace /usr/local/bin/nexttrace`. The Agent runs it with `CAP_NET_RAW`
  via the unit's ambient capability.
- The installer generates a random bearer token into
  `/etc/tracecat/agent.env` (`0600`) and prints the token once, together with
  the URL to configure on the Controller. Keep it secret.
- Optional: `--protocols icmp,tcp` to restrict probes, `--no-start` to stage
  without starting.

Verify on the Agent host:

```bash
systemctl status tracecat-agent
ss -ltnp | grep 8443                       # only the configured private IP
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/health  # 401
```

### 1.2 Controller

On the Controller host, export each Agent token as the environment variable you
name in the `--agent` spec (the installer writes them into
`/etc/tracecat/controller.env`, mode `0600`; it never embeds them in JSON):

```bash
export TRACECAT_TOKEN_AGENT1='<token printed by the Agent installer>'

sudo -E bash /tmp/tracecat-install.sh controller \
  --auth cloudflare \
  --public-origin https://trace.example.com \
  --cf-team-domain https://your-team.cloudflareaccess.com \
  --cf-audience '<Access application AUD tag>' \
  --agent agent1,http://10.0.0.5:8443,TRACECAT_TOKEN_AGENT1,Tokyo,Tokyo JP,Example
```

`--agent` is repeatable:
`id,url,token_env[,name[,location[,provider]]]`. The URL must be `https://`
unless the host is a literal private/Tailscale/VPC IP (cleartext to public
addresses is rejected).

Auth modes:

- **cloudflare** (recommended for internet exposure): the Controller verifies
  the Cloudflare Access JWT itself (RS256/JWKS, issuer/audience/expiry). Set
  `--cf-email` / `--cf-domain` to further restrict identities. TLS and the
  Access application are configured in Cloudflare (see §4).
- **local**: single-factor password login; use with a private-only listener or
  in front of an SSO proxy. `--password-stdin` reads the password non-
  interactively (minimum 12 characters); the installer stores only a PBKDF2
  hash.
- **dev**: anonymous, loopback-only. `--listen` must be `127.0.0.1:...`; never
  expose it.

The Controller listens on `127.0.0.1:8080` by default (safe behind
`cloudflared`) and serves the embedded dashboard. If you expose it on a private
overlay instead, pass `--listen <private-ip>:8080` and set `--public-origin` to
the URL browsers use.

If any Agent token variable is missing, the installer writes commented
placeholders into `/etc/tracecat/controller.env` and **does not start** the
service — fill them in and run `systemctl enable --now tracecat-controller`.

### 1.3 Upgrades and rollback

```bash
# Upgrade to the latest release (keeps configs and database)
sudo bash /tmp/tracecat-install.sh controller --version 0.1.1
sudo bash /tmp/tracecat-install.sh agent --version 0.1.1

# Rebuild config from flags (backs up the old files)
sudo bash /tmp/tracecat-install.sh controller ... --force
```

Always install the same release on Controller and Agents. Roll back by running
the installer with the previous `--version`; the SQLite history remains
compatible (migrations are additive). For fully offline installs, download the
release tarball + checksums and use `--tarball FILE --checksums FILE`.

Check installed versions:

```bash
tracecat-controller -version
tracecat-agent -version
```

---

## 2. Manual systemd install

Use this when you want to manage files yourself. Get the binaries either from a
[release](https://github.com/dotfrankruan/TraceCat/releases) tarball or build
with `make build` (Go 1.23+; Node.js is only needed for `make ui`).

### 2.1 Agent

```bash
sudo useradd --system --home-dir /var/lib/tracecat --create-home \
     --shell /usr/sbin/nologin tracecat
sudo install -d -m 0755 /etc/tracecat
sudo install -m 0755 tracecat-agent /usr/local/bin/tracecat-agent
sudo install -m 0640 -o root -g tracecat configs/agent.example.json /etc/tracecat/agent.json
sudo install -m 0600 -o root -g root deploy/systemd/tracecat-agent.env.example /etc/tracecat/agent.env
sudoedit /etc/tracecat/agent.json   # node_id, listen=<private-ip>:PORT, nexttrace.binary
sudoedit /etc/tracecat/agent.env    # TRACECAT_AGENT_TOKEN=<48 random bytes>

sudo install -m 0644 deploy/systemd/tracecat-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracecat-agent
```

The Agent **fails startup** if `listen` is a wildcard, is not assigned to a
local interface, or is globally routable while `security.allow_public_bind` is
false. It never falls back to all interfaces. See
[PRIVATE-NETWORKING.md](PRIVATE-NETWORKING.md) for reachability/ACL options.

#### Linux capabilities for NextTrace

NextTrace needs `CAP_NET_RAW` for ICMP and TCP/UDP SYN probes. The shipped unit
grants it narrowly to the unprivileged process:

```ini
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
```

The alternative is a file capability on the binary
(`sudo setcap cap_net_raw+ep /usr/local/bin/nexttrace`) and removing the two
capability lines. Never run the Agent as root.

The unit intentionally omits `MemoryDenyWriteExecute`: NextTrace v1.7.3
SIGSEGVs under a W^X policy. Keep the remaining sandbox directives.

```bash
sudo -u tracecat /usr/local/bin/nexttrace --version
sudo -u tracecat /usr/local/bin/nexttrace --json -q 1 -m 2 1.1.1.1 | head -c 200
```

### 2.2 Controller

```bash
sudo install -m 0755 tracecat-controller /usr/local/bin/tracecat-controller
sudo useradd --system --home-dir /var/lib/tracecat --create-home \
     --shell /usr/sbin/nologin tracecat
sudo install -d -m 0755 /etc/tracecat
sudo install -d -m 0700 -o tracecat -g tracecat /var/lib/tracecat
sudo install -m 0640 -o root -g tracecat configs/controller.example.json /etc/tracecat/controller.json
sudo install -m 0600 -o root -g tracecat deploy/systemd/tracecat-controller.env.example /etc/tracecat/controller.env
sudoedit /etc/tracecat/controller.json
sudoedit /etc/tracecat/controller.env
sudo install -m 0644 deploy/systemd/tracecat-controller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracecat-controller
```

Config reference: [controller-config.md](controller-config.md). Generate a
local-auth hash with `tracecat-controller -hash-password` (reads stdin). Agent
tokens are referenced by env-var **name** in `agents[].token_env` and must be
set in the environment file.

### 2.3 Docker (Controller only)

```bash
sudo install -d -m 0700 -o 65532 -g 65532 /var/lib/tracecat
sudo install -d -m 0755 /etc/tracecat
sudo install -m 0640 -o root -g 65532 configs/controller.example.json /etc/tracecat/controller.json
sudo docker compose -f deploy/docker/docker-compose.yml up -d --build
```

The image is distroless, non-root, read-only and drops all capabilities; it
uses host networking so the Controller can bind loopback behind a tunnel. The
Agent is intentionally not containerized in the example: it needs a host network
address and the host-installed NextTrace binary.

---

## 3. Network exposure

- **Controller browser exposure:** put it behind Cloudflare Tunnel + Access
  (§4) or expose it only on a private overlay/VPN. Never bind it to a public
  interface without TLS and authentication in front.
- **Controller→Agent:** private overlay or VPC only. Restrict the Agent port to
  the Controller host, and keep the per-Agent bearer token.
- **Agent→Internet:** required for traceroute/GeoIP. Restrict egress if your
  policy allows; TraceCat does not proxy traffic.

See [PRIVATE-NETWORKING.md](PRIVATE-NETWORKING.md) for firewall examples and
verification commands.

---

## 4. Cloudflare Access (optional but recommended)

TraceCat verifies the Access JWT at the origin, so a tunnel misconfiguration
does not create an open proxy. Configuration is on your Cloudflare account:

1. Create a tunnel and route the Controller hostname to
   `http://127.0.0.1:8080` (see `deploy/cloudflared/config.yml.example`).
2. Create a Cloudflare Access application for that hostname with an MFA-capable
   allow policy.
3. Use `auth.mode=cloudflare` with `team_domain` and `audience` from that
   application; optionally restrict `allowed_emails` /
   `allowed_email_domains`. No Cloudflare API token is needed or accepted.
4. Set `public_origin` to the public HTTPS URL so cookies are `Secure` and
   CSRF/Origin checks match.
5. Keep the Controller port itself private (loopback/tailnet) — the tunnel is
   the only ingress.

---

## 5. Verification checklist

```bash
# Controller process and unauthenticated liveness
systemctl is-active tracecat-controller
curl -fsS http://127.0.0.1:8080/healthz

# Agent binds only its private address and enforces auth
ss -ltnp | grep <agent-port>
curl -s -o /dev/null -w '%{http_code}\n' http://<agent-private-ip>:<port>/v1/health       # 401
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer wrong' \
  http://<agent-private-ip>:<port>/v1/health                                              # 401

# Authenticated Agent health (from the Controller host, token from agent.env)
curl -fsS -H "Authorization: Bearer $TOKEN" http://<agent-private-ip>:<port>/v1/health | jq
```

Then open the dashboard: resolve a target, pick each Agent, run an ICMP trace,
and optionally TCP/UDP traces (bounded port). One Agent failing must not fail
the others.

---

## 6. Operations

- **Logs:** `journalctl -u tracecat-controller` / `-u tracecat-agent`. Tokens,
  request bodies and headers are never logged. Crash-restart loops are rate-
  limited by systemd's default start limit; inspect `journalctl` and use
  `systemctl reset-failed` before a manual restart.
- **Version:** release binaries embed version/commit/build date; ad-hoc
  `go build` binaries report `dev`.
- **Database:** `/var/lib/tracecat/controller.db` (WAL). History is trimmed to
  `database.max_history_jobs`. For a consistent copy, stop the service and copy
  the DB plus `-wal`/`-shm`, or use SQLite's online backup.
- **Token rotation:** generate a new token, update the Agent env file, restart
  the Agent, update the matching env var in `/etc/tracecat/controller.env`,
  restart the Controller. Rotate one Agent at a time.
- **NextTrace upgrades:** upgrade the binary, restart the Agent; capability
  detection runs at startup. If required flags disappear, the Agent starts
  degraded and rejects traces instead of guessing. Re-run
  [verify/agent-remote-verify.sh](../verify/agent-remote-verify.sh) after major
  NextTrace upgrades.
- **Interrupted jobs:** on Controller startup, jobs left `pending`/`running` by
  a previous process are marked `failed` (traces are never resumed silently).

---

## 7. Troubleshooting

| Symptom | Fix |
| --- | --- |
| Installer: `checksum mismatch` | Corrupted download or wrong `--version`; retry. Never bypass verification for production. |
| Installer: controller installs but does not start | It writes commented `# TRACECAT_TOKEN_*=...` lines when Agent token env vars are missing. Fill them in `/etc/tracecat/controller.env` and start the unit. |
| Agent: `listen address ... is not assigned` | The configured private address is missing. Bring up the overlay/VPC interface, then restart the Agent (or add a unit dependency). |
| Agent: `wildcard binds are refused` | Use an explicit address such as `10.0.0.5:8443`; never `0.0.0.0`. |
| Agent: `globally routable ... allow_public_bind` | Bind a private address, or explicitly accept the risk with `security.allow_public_bind: true` plus TLS/firewall. |
| Agent: `nexttrace binary ... does not exist` / `nexttrace_unavailable` | Fix `nexttrace.binary` (absolute path) and permissions; check `/v1/health`. |
| Agent: `permission denied` sending probes | Grant `CAP_NET_RAW` (ambient capability or `setcap`); test as the `tracecat` user. |
| Controller: `bind: address already in use` | Change `listen` (and `public_origin` if it embeds the port). |
| `target_rejected` | Destination outside the global-unicast policy; add a narrow `security.allowed_cidrs` on **both** Controller and Agent. |
| `403 csrf_failed` in dev/cloudflare mode after a Controller restart | CSRF HMAC keys are per-process unless `csrf_secret_env` is set; reload the page. Local-auth sessions survive restarts. |
| TCP/UDP unavailable | Check `limits.allowed_protocols` (Controller), `nexttrace.allowed_protocols` (Agent) and detected `tcp`/`udp` capabilities in `/v1/health`. A port is mandatory for TCP/UDP. |
| Interface dropdown empty | The Agent did not report any eligible interfaces: NextTrace may lack `-D/--dev`, or all interfaces are loopback/down/container/bridge. Check `/v1/health` and the `interfaces` config section. |
| Hops show **no reply** | Intermediate routers often drop probes; this is not evidence of a broken route. |

Agent health/logs should never contain tokens or executable paths; if they do,
treat it as a security defect and report it.

---

## 8. Uninstall

```bash
sudo systemctl disable --now tracecat-controller tracecat-agent
sudo rm -f /etc/systemd/system/tracecat-*.service
sudo rm -rf /etc/tracecat /var/lib/tracecat
sudo rm -f /usr/local/bin/tracecat-controller /usr/local/bin/tracecat-agent
sudo userdel tracecat   # optional
```

Remove any tunnel/overlay ACL entries and the Cloudflare Access application that
referenced the deployment.
