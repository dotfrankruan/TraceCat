#!/usr/bin/env bash
# Install/refresh the TraceCat Agent on the dedicated Debian test host.
#
# Part of the independent verification harness (see docs/VERIFICATION.md).
# It contains NO secrets: the per-Agent bearer token is generated on the target
# host (if absent) and stays in /etc/tracecat/agent.env (0600 root:root).
# Verifiers read it over SSH.
#
# Usage:
#   verify/setup-testhost-agent.sh
#   AGENT_BIN=/tmp/x SKIP_BUILD=1 verify/setup-testhost-agent.sh
#
# Environment:
#   TESTHOST      ssh target            (default root@124.222.154.86)
#   TAILSCALE_IP  bind address          (default 100.81.98.125)
#   NODE_ID       agent node_id         (default debian-test-1)
#   AGENT_BIN     prebuilt linux binary (default /tmp/tracecat-agent-linux-amd64)
#   SKIP_BUILD    set to 1 to reuse AGENT_BIN
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTHOST="${TESTHOST:-root@124.222.154.86}"
TAILSCALE_IP="${TAILSCALE_IP:-100.81.98.125}"
NODE_ID="${NODE_ID:-debian-test-1}"
AGENT_BIN="${AGENT_BIN:-/tmp/tracecat-agent-linux-amd64}"

ssh_run() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$TESTHOST" "$@"; }

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  echo "==> cross-compiling tracecat-agent (linux/amd64, CGO disabled)"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -o "$AGENT_BIN" ./cmd/tracecat-agent )
fi
test -f "$AGENT_BIN"

# --- config (no secrets; rendered locally, shipped as a file) -------------
CONFIG_TMP="$(mktemp)"
trap 'rm -f "$CONFIG_TMP"' EXIT
cat >"$CONFIG_TMP" <<JSON
{
  "node_id": "${NODE_ID}",
  "name": "Debian test host (independent verification)",
  "listen": "${TAILSCALE_IP}:8443",
  "auth": {
    "token_env": "TRACECAT_AGENT_TOKEN"
  },
  "nexttrace": {
    "binary": "/usr/local/bin/nexttrace",
    "max_concurrent_traces": 4,
    "probe_timeout_ms": 1000,
    "max_execution_ms": 60000,
    "max_stdout_bytes": 4194304,
    "max_raw_bytes": 1048576,
    "geo_provider": "",
    "allowed_protocols": ["icmp", "tcp", "udp"]
  },
  "security": {
    "allow_private_targets": false,
    "allowed_cidrs": [],
    "allow_public_bind": false
  },
  "interfaces": {
    "exclude": [],
    "include": []
  },
  "rate_limit": {
    "requests_per_minute": 60,
    "burst": 10,
    "max_concurrent_http": 16
  },
  "log_level": "info"
}
JSON

echo "==> copying binary, config and systemd unit to $TESTHOST"
scp -q -o BatchMode=yes "$AGENT_BIN" "$TESTHOST:/tmp/tracecat-agent.new"
scp -q -o BatchMode=yes "$CONFIG_TMP" "$TESTHOST:/tmp/tracecat-agent.json.new"
scp -q -o BatchMode=yes "$REPO_ROOT/deploy/systemd/tracecat-agent.service" \
  "$TESTHOST:/tmp/tracecat-agent.service.new"

echo "==> installing binary, user, config, secret and unit"
ssh_run "bash -s" <<'REMOTE'
set -euo pipefail

# --- binary ---------------------------------------------------------------
install -m 0755 /tmp/tracecat-agent.new /usr/local/bin/tracecat-agent
rm -f /tmp/tracecat-agent.new

# --- unprivileged service account ----------------------------------------
if ! id tracecat >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/tracecat --shell /usr/sbin/nologin tracecat
fi
install -d -m 0755 /etc/tracecat
install -d -m 0700 -o tracecat -g tracecat /var/lib/tracecat

# --- config (no secrets) --------------------------------------------------
install -m 0640 -o root -g tracecat /tmp/tracecat-agent.json.new /etc/tracecat/agent.json
rm -f /tmp/tracecat-agent.json.new

# --- per-Agent secret (generated once, never leaves the host) -------------
if [[ ! -s /etc/tracecat/agent.env ]]; then
  ( umask 077
    printf 'TRACECAT_AGENT_TOKEN=%s\n' "$(openssl rand -base64 48 | tr -d '\n')" \
      > /etc/tracecat/agent.env )
fi
chown root:root /etc/tracecat/agent.env
chmod 0600 /etc/tracecat/agent.env

# --- systemd unit: the repo unit is used unmodified -----------------------
install -m 0644 /tmp/tracecat-agent.service.new /etc/systemd/system/tracecat-agent.service
rm -f /tmp/tracecat-agent.service.new
systemctl daemon-reload
systemctl enable tracecat-agent >/dev/null 2>&1 || true
systemctl restart tracecat-agent

sleep 1
systemctl is-active tracecat-agent
REMOTE

echo "==> installed and started."
