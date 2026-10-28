#!/usr/bin/env bash
# Deploy the full TraceCat stack (Controller + two Agents) on the dedicated
# Debian verification host.
#
# Layout:
#   agent A : node debian-test-1, listen <TS_IP>:8443  (deployed by
#             verify/setup-testhost-agent.sh; left untouched here)
#   agent B : node debian-test-2, listen <TS_IP>:8444  (second vantage point,
#             distinct token, same NextTrace binary)
#   controller (dev)       : 127.0.0.1:8080, public_origin http://127.0.0.1:18080,
#                            dev auth (loopback only) — used by the SSH-tunnelled
#                            browser proof
#   controller (local auth): 127.0.0.1:8081, PBKDF2 password + SQLite sessions,
#                            used to verify local auth/CSRF/logout independent of
#                            the dev-mode dashboard flow
#
# Contains NO secrets: tokens are generated on the host, the local-auth password
# is random and kept in /root/tc-verify/local-password.txt (0600) for the
# verifier only. Test-only systemd units and configs live on the host, never in
# the repo.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTHOST="${TESTHOST:-root@124.222.154.86}"
TS_IP="${TS_IP:-100.81.98.125}"
NODE_A="${NODE_A:-debian-test-1}"
NODE_B="${NODE_B:-debian-test-2}"
PUBLIC_ORIGIN="${PUBLIC_ORIGIN:-http://127.0.0.1:18090}"
SKIP_BUILD="${SKIP_BUILD:-0}"

ssh_run() { ssh -o BatchMode=yes -o ConnectTimeout=15 "$TESTHOST" "$@"; }

AGENT_BIN="${AGENT_BIN:-/tmp/tracecat-agent-linux-amd64}"
CONTROLLER_BIN="${CONTROLLER_BIN:-/tmp/tracecat-controller-linux-amd64}"

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "==> cross-compiling agent + controller (linux/amd64, CGO disabled)"
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -o "$AGENT_BIN" ./cmd/tracecat-agent )
  ( cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -o "$CONTROLLER_BIN" ./cmd/tracecat-controller )
fi
test -x "$AGENT_BIN" && test -x "$CONTROLLER_BIN"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

# --- agent B config -------------------------------------------------------
cat >"$TMPD/agent-b.json" <<JSON
{
  "node_id": "${NODE_B}",
  "name": "Debian test host B (second vantage point)",
  "listen": "${TS_IP}:8444",
  "auth": { "token_env": "TRACECAT_AGENT_TOKEN" },
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
  "rate_limit": { "requests_per_minute": 120, "burst": 20, "max_concurrent_http": 16 },
  "log_level": "info"
}
JSON

# --- controller (dev) config ---------------------------------------------
cat >"$TMPD/controller.json" <<JSON
{
  "listen": "127.0.0.1:8080",
  "public_origin": "${PUBLIC_ORIGIN}",
  "auth": { "mode": "dev" },
  "database": {
    "path": "/var/lib/tracecat/controller.db",
    "max_history_jobs": 200
  },
  "dns": { "timeout_ms": 4000, "max_addresses": 16 },
  "limits": {
    "max_hops": 30,
    "max_queries": 3,
    "min_execution_ms": 5000,
    "max_execution_ms": 60000,
    "max_nodes_per_job": 8,
    "max_jobs_per_minute": 60,
    "max_concurrent_jobs": 4,
    "max_concurrent_traces": 4,
    "max_resolves_per_minute": 300,
    "max_raw_result_bytes": 1048576,
    "allowed_protocols": ["icmp", "tcp", "udp"]
  },
  "agents": [
    {
      "id": "${NODE_A}",
      "name": "Debian test host A",
      "location": "Shanghai, CN",
      "provider": "Tencent Cloud",
      "url": "http://${TS_IP}:8443",
      "token_env": "TRACECAT_AGENT_TOKEN_1",
      "enabled": true,
      "request_timeout_ms": 75000
    },
    {
      "id": "${NODE_B}",
      "name": "Debian test host B",
      "location": "Shanghai, CN",
      "provider": "Tencent Cloud",
      "url": "http://${TS_IP}:8444",
      "token_env": "TRACECAT_AGENT_TOKEN_2",
      "enabled": true,
      "request_timeout_ms": 75000
    }
  ],
  "trusted_proxies": [],
  "log_level": "info"
}
JSON

# --- controller (local auth) config --------------------------------------
cat >"$TMPD/controller-local.json" <<JSON
{
  "listen": "127.0.0.1:8081",
  "public_origin": "http://127.0.0.1:8081",
  "auth": {
    "mode": "local",
    "local": {
      "password_hash_env": "TRACECAT_CONTROLLER_PASSWORD_HASH",
      "session_ttl_seconds": 3600
    }
  },
  "database": {
    "path": "/var/lib/tracecat/controller-local.db",
    "max_history_jobs": 200
  },
  "dns": { "timeout_ms": 4000, "max_addresses": 16 },
  "limits": {
    "max_hops": 30,
    "max_queries": 3,
    "min_execution_ms": 5000,
    "max_execution_ms": 60000,
    "max_nodes_per_job": 8,
    "max_jobs_per_minute": 60,
    "max_concurrent_jobs": 4,
    "max_concurrent_traces": 4,
    "max_resolves_per_minute": 300,
    "max_raw_result_bytes": 1048576,
    "allowed_protocols": ["icmp", "tcp", "udp"]
  },
  "agents": [
    {
      "id": "${NODE_A}",
      "name": "Debian test host A",
      "location": "Shanghai, CN",
      "provider": "Tencent Cloud",
      "url": "http://${TS_IP}:8443",
      "token_env": "TRACECAT_AGENT_TOKEN_1",
      "enabled": true,
      "request_timeout_ms": 75000
    },
    {
      "id": "${NODE_B}",
      "name": "Debian test host B",
      "location": "Shanghai, CN",
      "provider": "Tencent Cloud",
      "url": "http://${TS_IP}:8444",
      "token_env": "TRACECAT_AGENT_TOKEN_2",
      "enabled": true,
      "request_timeout_ms": 75000
    }
  ],
  "trusted_proxies": ["127.0.0.1/32", "::1/128"],
  "log_level": "info"
}
JSON

# The local-auth instance is also used to exercise Controller rate limits with
# small, fast limits (the dev instance keeps production-like defaults).
python3 - "$TMPD/controller-local.json" <<'PYCFG'
import json, sys
path = sys.argv[1]
cfg = json.load(open(path))
cfg["limits"]["max_jobs_per_minute"] = 3
cfg["limits"]["max_resolves_per_minute"] = 5
json.dump(cfg, open(path, "w"), indent=2)
PYCFG

echo "==> copying binaries, configs and units to $TESTHOST"
scp -q -o BatchMode=yes "$AGENT_BIN" "$TESTHOST:/tmp/tracecat-agent.new"
scp -q -o BatchMode=yes "$CONTROLLER_BIN" "$TESTHOST:/tmp/tracecat-controller.new"
scp -q -o BatchMode=yes "$TMPD/agent-b.json" "$TESTHOST:/tmp/agent-b.json.new"
scp -q -o BatchMode=yes "$TMPD/controller.json" "$TESTHOST:/tmp/controller.json.new"
scp -q -o BatchMode=yes "$TMPD/controller-local.json" "$TESTHOST:/tmp/controller-local.json.new"
scp -q -o BatchMode=yes "$REPO_ROOT/deploy/systemd/tracecat-agent.service" "$TESTHOST:/tmp/agent.service.new"
scp -q -o BatchMode=yes "$REPO_ROOT/deploy/systemd/tracecat-controller.service" "$TESTHOST:/tmp/controller.service.new"

echo "==> installing services"
ssh_run "bash -s" <<'REMOTE'
set -euo pipefail

install -m 0755 /tmp/tracecat-agent.new /usr/local/bin/tracecat-agent
install -m 0755 /tmp/tracecat-controller.new /usr/local/bin/tracecat-controller
rm -f /tmp/tracecat-agent.new /tmp/tracecat-controller.new
# agent A is deployed by setup-testhost-agent.sh; restart it so it runs the
# binary just built from the verified commit.
systemctl restart tracecat-agent

install -d -m 0755 /etc/tracecat
install -d -m 0700 -o tracecat -g tracecat /var/lib/tracecat
install -d -m 0700 /root/tc-verify

# ---------- agent B (second tailnet vantage point, own token) -------------
if [[ ! -s /etc/tracecat/agent-b.env ]]; then
  ( umask 077
    printf 'TRACECAT_AGENT_TOKEN=%s\n' "$(openssl rand -base64 48 | tr -d '\n')" \
      > /etc/tracecat/agent-b.env )
fi
chown root:root /etc/tracecat/agent-b.env
chmod 0600 /etc/tracecat/agent-b.env
install -m 0640 -o root -g tracecat /tmp/agent-b.json.new /etc/tracecat/agent-b.json
rm -f /tmp/agent-b.json.new
sed -e 's#^Description=.*#Description=TraceCat Agent B (verification, second tailnet vantage point)#' \
    -e 's#^ExecStart=.*#ExecStart=/usr/local/bin/tracecat-agent -config /etc/tracecat/agent-b.json#' \
    -e 's#^EnvironmentFile=.*#EnvironmentFile=/etc/tracecat/agent-b.env#' \
    /tmp/agent.service.new > /etc/systemd/system/tracecat-agent-b.service
rm -f /tmp/agent.service.new
systemctl daemon-reload
systemctl enable tracecat-agent-b >/dev/null 2>&1 || true
systemctl restart tracecat-agent-b

# ---------- controller, dev auth mode ------------------------------------
{
  printf 'TRACECAT_AGENT_TOKEN_1=%s\n' "$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent.env)"
  printf 'TRACECAT_AGENT_TOKEN_2=%s\n' "$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent-b.env)"
} > /etc/tracecat/controller.env
chown root:root /etc/tracecat/controller.env
chmod 0600 /etc/tracecat/controller.env
install -m 0640 -o root -g tracecat /tmp/controller.json.new /etc/tracecat/controller.json
rm -f /tmp/controller.json.new
install -m 0644 /tmp/controller.service.new /etc/systemd/system/tracecat-controller.service
rm -f /tmp/controller.service.new
systemctl daemon-reload
systemctl enable tracecat-controller >/dev/null 2>&1 || true
systemctl restart tracecat-controller

# ---------- controller, local auth mode (independent test instance) ------
if [[ ! -s /root/tc-verify/local-password.txt ]]; then
  ( umask 077; openssl rand -base64 24 | tr -d '\n' > /root/tc-verify/local-password.txt )
fi
chmod 0600 /root/tc-verify/local-password.txt
password="$(cat /root/tc-verify/local-password.txt)"
hash="$(printf '%s' "$password" | /usr/local/bin/tracecat-controller -hash-password)"
{
  printf 'TRACECAT_CONTROLLER_PASSWORD_HASH=%s\n' "$hash"
  printf 'TRACECAT_AGENT_TOKEN_1=%s\n' "$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent.env)"
  printf 'TRACECAT_AGENT_TOKEN_2=%s\n' "$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent-b.env)"
} > /etc/tracecat/controller-local.env
chown root:root /etc/tracecat/controller-local.env
chmod 0600 /etc/tracecat/controller-local.env
install -m 0640 -o root -g tracecat /tmp/controller-local.json.new /etc/tracecat/controller-local.json
rm -f /tmp/controller-local.json.new
sed -e 's#^Description=.*#Description=TraceCat Controller (local-auth verification instance)#' \
    -e 's#^ExecStart=.*#ExecStart=/usr/local/bin/tracecat-controller -config /etc/tracecat/controller-local.json#' \
    -e 's#^EnvironmentFile=.*#EnvironmentFile=/etc/tracecat/controller-local.env#' \
    /etc/systemd/system/tracecat-controller.service > /etc/systemd/system/tracecat-controller-local.service
systemctl daemon-reload
systemctl enable tracecat-controller-local >/dev/null 2>&1 || true
systemctl restart tracecat-controller-local

sleep 1.5
for unit in tracecat-agent tracecat-agent-b tracecat-controller tracecat-controller-local; do
  printf '%-28s %s\n' "$unit" "$(systemctl is-active "$unit")"
done
echo "--- listeners ---"
ss -H -ltnp | grep -E ':(8443|8444|8080|8081)\b' || true
echo "--- healthz ---"
curl -sS -m 5 -o - -w ' [%{http_code}]\n' http://127.0.0.1:8080/healthz || true
curl -sS -m 5 -o - -w ' [%{http_code}]\n' http://127.0.0.1:8081/healthz || true
REMOTE

echo "==> full stack deployed. Local-auth password: /root/tc-verify/local-password.txt (host only)."
