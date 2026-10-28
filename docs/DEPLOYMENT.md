# Deployment

TraceCat has two deployables:

- **Controller** — one instance; serves the dashboard/API, resolves DNS, stores
  history in SQLite, talks to Agents.
- **Agent** — one per vantage point; binds to its Tailscale address, runs the
  locally installed NextTrace, requires a per-Agent token.

The Agent is *not* an open service: it never listens on a public interface and
never accepts a hostname or arbitrary arguments.

## 0. Prerequisites

| Host | Requirements |
| --- | --- |
| Controller | Go-built binary (or Docker), write access to a state dir, Cloudflare Tunnel (recommended) or tailnet-only exposure |
| Agent | Linux + systemd (recommended), Tailscale (logged in, address assigned), NextTrace installed, a dedicated unprivileged user, ability to grant `CAP_NET_RAW` (ICMP and TCP/UDP SYN probes) |
| Network | Controller can reach Agent `listen` IP:port over Tailscale; Agents reach the Internet for traceroute/GeoIP |

Tests and this documentation were verified with NextTrace v1.7.3 on Debian 13,
systemd 257 and Tailscale 1.104.

## 1. Controller

### 1.1 systemd (recommended)

```bash
# Binaries (build with `make build-backend` locally, or download a release)
sudo install -m 0755 bin/tracecat-controller /usr/local/bin/tracecat-controller

# Service account and directories
sudo useradd --system --home-dir /var/lib/tracecat --create-home \
     --shell /usr/sbin/nologin tracecat
sudo install -d -m 0755 /etc/tracecat
sudo install -d -m 0700 -o tracecat -g tracecat /var/lib/tracecat

# Configuration: start from the example and edit it
sudo install -m 0640 -o root -g tracecat configs/controller.example.json /etc/tracecat/controller.json
sudo install -m 0600 -o root -g tracecat deploy/systemd/tracecat-controller.env.example /etc/tracecat/controller.env
sudoedit /etc/tracecat/controller.json
sudoedit /etc/tracecat/controller.env

# systemd unit
sudo install -m 0644 deploy/systemd/tracecat-controller.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracecat-controller
sudo systemctl status tracecat-controller
journalctl -u tracecat-controller -f
```

The example unit keeps the Controller on `127.0.0.1:8080` (the safe default)
behind `cloudflared`. If you instead expose it on the tailnet, set `listen` to a
Tailscale address and use the tailnet ACL example
(`deploy/tailscale/acl.hujson.example`).

Generate a local-auth password hash (only for `auth.mode=local`) with:

```bash
tracecat-controller -hash-password   # reads the password from stdin, prints pbkdf2-sha256$...
```

Put the hash in `/etc/tracecat/controller.env` as
`TRACECAT_CONTROLLER_PASSWORD_HASH=...` (never in the JSON config, never in git).

### 1.2 Cloudflare Tunnel + Access

The Controller verifies Cloudflare Access JWTs itself, so a tunnel
misconfiguration cannot turn it into an open proxy. Your Cloudflare deployment
is separate; at minimum:

1. Create a tunnel and expose the Controller hostname to
   `http://127.0.0.1:8080` (see `deploy/cloudflared/config.yml.example`).
2. Create a Cloudflare Access application for that hostname with an allow policy
   (MFA recommended).
3. Configure `auth.mode=cloudflare` in `controller.json` with:
   - `team_domain`: `https://<your-team>.cloudflareaccess.com`
   - `audience`: the Access application's Audience (AUD) tag
   - optionally `allowed_emails` / `allowed_email_domains`
   - if you set `csrf_secret_env`, put the named secret (>=16 random bytes) in
     `/etc/tracecat/controller.env`; otherwise a random per-process secret is
     generated (fine for a single Controller instance)
4. Set `public_origin` to the public HTTPS URL so cookies are `Secure` and
   Origin/CSRF checks match.

No Cloudflare API token is needed or accepted; verification uses only the
public JWKS endpoint of the team domain.

### 1.3 Docker

```bash
sudo install -d -m 0700 -o 65532 -g 65532 /var/lib/tracecat
sudo install -d -m 0755 /etc/tracecat
sudo install -m 0640 -o root -g 65532 configs/controller.example.json /etc/tracecat/controller.json
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

The image is distroless, non-root, read-only, with all capabilities dropped.
Use `network_mode: host` so the Controller can bind loopback behind
cloudflared. The Agent image is intentionally not provided: it needs the host
Tailscale address and the host NextTrace binary.

## 2. Agent (systemd, recommended)

```bash
# 1. Install NextTrace from a trusted source (official release, distro package,
#    or audited build) and verify the version:
nexttrace --version

# 2. Unprivileged service account
sudo useradd --system --home-dir /var/lib/tracecat --shell /usr/sbin/nologin tracecat

# 3. Binary and config
sudo install -m 0755 bin/tracecat-agent /usr/local/bin/tracecat-agent
sudo install -d -m 0755 /etc/tracecat
sudo install -m 0640 -o root -g tracecat configs/agent.example.json /etc/tracecat/agent.json
sudoedit /etc/tracecat/agent.json      # node_id, listen=<tailscale-ip>:8443, nexttrace.binary

# 4. Per-Agent secret (generate one, use the same value on the Controller)
token=$(openssl rand -base64 48)
sudo install -m 0600 -o root -g root /dev/null /etc/tracecat/agent.env
printf 'TRACECAT_AGENT_TOKEN=%s\n' "$token" | sudo tee /etc/tracecat/agent.env >/dev/null
# Add the same value to the Controller's environment as the env var named by
# agents[].token_env in controller.json.

# 5. systemd
sudo install -m 0644 deploy/systemd/tracecat-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracecat-agent
sudo systemctl status tracecat-agent
journalctl -u tracecat-agent -f
```

The Agent **fails startup** if `listen` is a wildcard (`0.0.0.0`, `::`), is not
assigned to a local interface, or is not in a Tailscale range while
`security.require_tailscale_bind` is true. It never silently binds to all
interfaces or falls back to another address.

### 2.1 Linux capabilities for NextTrace

The Agent process itself needs no privileges. NextTrace needs `CAP_NET_RAW` to
send ICMP probes. Two supported approaches:

**A. Ambient capability on the service (default unit).** The unit sets:

```ini
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
```

The unprivileged NextTrace child inherits only `CAP_NET_RAW`. No root, no
setuid binary.

**B. File capability on the NextTrace binary.**

```bash
sudo setcap cap_net_raw+ep /usr/local/bin/nexttrace
# then remove AmbientCapabilities/CapabilityBoundingSet from the unit
```

Either way, keep the systemd sandbox directives. Do **not** run the Agent as
root "because it is easier".

> **Note:** the shipped Agent unit intentionally does **not** set
> `MemoryDenyWriteExecute=true`. NextTrace v1.7.3 SIGSEGVs under a W^X memory
> policy (verified on Debian 13/systemd 257), so only the Controller unit keeps
> that directive. Do not re-add it to the Agent.

Verify NextTrace works under the service account before starting the Agent:

```bash
sudo -u tracecat /usr/local/bin/nexttrace --version   # must print a version
sudo -u tracecat /usr/local/bin/nexttrace --json -q 1 -m 2 1.1.1.1 | head -c 200
# If the second command fails with a permission error, fix CAP_NET_RAW (A or B).
```

### 2.2 Multiple Agents

Repeat on each vantage point with a different `node_id`, `listen` address/port
and bearer token. Add each to `controller.json` under `agents`:

```json
{
  "id": "tokyo-1",
  "name": "Tokyo",
  "location": "Tokyo, JP",
  "provider": "DMIT",
  "url": "http://100.64.0.11:8443",
  "token_env": "TRACECAT_TOKEN_TOKYO_1",
  "enabled": true
}
```

Node URLs are administrative configuration only; there is no node registration
API and users can never submit a URL. Use HTTPS for any non-private host.

## 3. Tailscale

1. Install and log in Tailscale on the Controller and each Agent.
2. Tag nodes (`tag:tracecat-controller`, `tag:tracecat-agent`) and apply
   `deploy/tailscale/acl.hujson.example` (adjust ports/names).
3. Agents listen only on their tailnet address; only the Controller tag may
   reach the Agent port.
4. Tailnet connectivity is **not** authentication: TraceCat still requires the
   per-Agent bearer token.

Verify from the Controller host:

```bash
curl -fsS -H "Authorization: Bearer $TRACECAT_TOKEN_TOKYO_1" \
  http://100.64.0.11:8443/v1/health | jq
```

## 4. Verification checklist

```bash
# Controller process and liveness
systemctl is-active tracecat-controller
curl -fsS http://127.0.0.1:8080/healthz

# Agent auth is enforced (401 without/with a wrong token)
curl -s -o /dev/null -w '%{http_code}\n' http://<agent-tailscale-ip>:8443/v1/health
curl -s -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer wrong' \
  http://<agent-tailscale-ip>:8443/v1/health

# Controller sees the node(s)
# (authenticate through your configured mode first; dev mode only on loopback)

# End-to-end: open the dashboard, resolve a domain (e.g. example.com), pick an
# IP, select nodes, start a trace and confirm per-node results.
```

## 5. Operations

- **Logs:** `journalctl -u tracecat-controller` / `-u tracecat-agent`. Tokens and
  request bodies are never logged. Repeated crash-restart loops are rate-limited
  by systemd's default start limit (`StartLimitBurst=5` per 10 s); investigate
  with `journalctl` and `systemctl reset-failed` before restarting manually.
- **Version:** release binaries built with `make build` embed the git
  version/commit/build date; ad-hoc `go build` binaries report `dev`.
- **Database:** `/var/lib/tracecat/controller.db` (WAL enabled). History is
  trimmed to `database.max_history_jobs`; back up by stopping the service and
  copying the DB + `-wal`/`-shm`, or use SQLite's online backup.
- **Token rotation:** update `/etc/tracecat/agent.env`, `systemctl restart
  tracecat-agent`, then update the Controller environment variable and restart
  `tracecat-controller`. Different Agents have independent tokens.
- **NextTrace upgrades:** upgrade the binary, then restart the Agent (capability
  detection runs at startup) and check `/v1/health` reports the new version and
  capabilities. If a required flag disappears, the Agent refuses to start
  rather than guessing.
- **Troubleshooting:**
  - *Agent exits with "listen address is not assigned"*: Tailscale is not up yet
    or the configured IP changed. The unit `Requires=tailscaled.service`; check
    `tailscale ip`.
  - *`nexttrace_unavailable`*: binary path/permissions or missing required flags
    (`--json`, `-4`, `-6`, `-m`, `-q`). Run it manually as the `tracecat` user.
  - *Permission denied sending probes*: grant `CAP_NET_RAW` via approach A or B
    above; check with `sudo -u tracecat nexttrace --json -q 1 -m 1 1.1.1.1`.
  - *401 from Agent*: token mismatch or missing env var; tokens are compared
    exactly (no trimming of intentional characters).
  - *`target_rejected`*: destination is outside the default global-unicast
    policy; add a narrow admin CIDR allowlist deliberately on BOTH layers
    (`security.allowed_cidrs` in `controller.json` and in `agent.json`); never
    `0.0.0.0/0`.
  - *Agents trace a different path than local resolution*: expected for
    CDN/GeoDNS; the dashboard warns about this and shows the exact IP traced.

## 6. Uninstall

```bash
sudo systemctl disable --now tracecat-controller tracecat-agent
sudo rm -f /etc/systemd/system/tracecat-*.service
sudo rm -rf /etc/tracecat /var/lib/tracecat
sudo rm -f /usr/local/bin/tracecat-controller /usr/local/bin/tracecat-agent
sudo userdel tracecat
```
