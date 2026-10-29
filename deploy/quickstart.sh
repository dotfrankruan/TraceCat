#!/usr/bin/env bash
# TraceCat one-command quickstart: Controller + Agent on this host.
#
# Installs both components as systemd services on loopback, with a local-auth
# password generated for you. Intended for a quick, safe single-host trial.
# For multi-host / internet-facing deployments use deploy/install.sh directly.
#
# Usage:
#   sudo bash deploy/quickstart.sh [options]
#
# Options:
#   --controller-port <p>  default 8080
#   --agent-port <p>       default 9481
#   --nexttrace <path>     NextTrace binary (default: found in PATH)
#   --version <vX.Y.Z>     release version (default: latest)
#   --force                replace existing /etc/tracecat configs (backs up)
#   -h, --help
set -euo pipefail

REPO="dotfrankruan/TraceCat"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTROLLER_PORT=8080
AGENT_PORT=9481
NEXTTRACE_PATH=""
VERSION=""
FORCE=0

log()  { printf '[quickstart] %s\n' "$*"; }
die()  { printf '[quickstart] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
TraceCat one-command quickstart: Controller + Agent on this host.

Usage: sudo bash deploy/quickstart.sh [options]

  --controller-port <p>  dashboard port (default 8080)
  --agent-port <p>       Agent port (default 9481)
  --nexttrace <path>     NextTrace binary (default: found in PATH)
  --version <vX.Y.Z>     release version (default: latest)
  --force                replace existing /etc/tracecat configs (backs up)
  -h, --help
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller-port) CONTROLLER_PORT="${2:?}"; shift 2 ;;
    --agent-port)      AGENT_PORT="${2:?}"; shift 2 ;;
    --nexttrace)       NEXTTRACE_PATH="${2:?}"; shift 2 ;;
    --version)         VERSION="${2:?}"; shift 2 ;;
    --force)           FORCE=1; shift ;;
    -h|--help)         usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"
[[ -n "$CONTROLLER_PORT" && "$AGENT_PORT" =~ ^[0-9]+$ && "$CONTROLLER_PORT" =~ ^[0-9]+$ ]] || die "ports must be numeric"

# The installer can be run from a source checkout, an extracted release, or
# downloaded standalone.
if [[ -x "$ROOT/install.sh" ]]; then
  INSTALLER="$ROOT/install.sh"
elif [[ -x "$ROOT/deploy/install.sh" ]]; then
  INSTALLER="$ROOT/deploy/install.sh"
else
  command -v curl >/dev/null 2>&1 || die "curl is required"
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP:-}"' EXIT
  curl -fsSL --retry 3 --proto '=https' \
    "https://raw.githubusercontent.com/$REPO/main/deploy/install.sh" \
    -o "$TMP/install.sh" || die "could not download the installer"
  INSTALLER="$TMP/install.sh"
fi

if [[ -z "$NEXTTRACE_PATH" ]]; then
  NEXTTRACE_PATH="$(command -v nexttrace || true)"
fi
[[ -n "$NEXTTRACE_PATH" && -x "$NEXTTRACE_PATH" ]] \
  || die "NextTrace not found; install it or pass --nexttrace /path/to/nexttrace"

for port in "$CONTROLLER_PORT" "$AGENT_PORT"; do
  if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":${port} "; then
    die "port $port is already in use; choose another with --controller-port/--agent-port"
  fi
done

if [[ "$FORCE" -eq 0 ]]; then
  for f in /etc/tracecat/agent.json /etc/tracecat/controller.json; do
    [[ -f "$f" ]] && die "$f already exists; rerun with --force to replace it (old files are backed up)"
  done
fi

version_args=()
[[ -n "$VERSION" ]] && version_args=(--version "$VERSION")

force_args=()
[[ "$FORCE" -eq 1 ]] && force_args=(--force)

# 1) Agent (loopback). The installer generates the token and writes it to
#    /etc/tracecat/agent.env (0600).
log "installing Agent on 127.0.0.1:${AGENT_PORT}"
bash "$INSTALLER" agent \
  --listen "127.0.0.1:${AGENT_PORT}" \
  --nexttrace "$NEXTTRACE_PATH" \
  --node-id local \
  --no-start ${version_args[@]+"${version_args[@]}"} ${force_args[@]+"${force_args[@]}"}
systemctl enable --now tracecat-agent >/dev/null
sleep 1

TOKEN="$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent.env | head -1)"
[[ -n "$TOKEN" ]] || die "Agent token was not generated at /etc/tracecat/agent.env"

# 2) Controller with local auth on loopback. A random password is generated and
#    printed once; only its PBKDF2 hash is stored.
PASSWORD="$( (command -v openssl >/dev/null 2>&1 && openssl rand -base64 18) || head -c 18 /dev/urandom | base64 | tr -d '\n')"
log "installing Controller on 127.0.0.1:${CONTROLLER_PORT}"
printf '%s\n' "$PASSWORD" | TRACECAT_AGENT_TOKEN="$TOKEN" bash "$INSTALLER" controller \
  --auth local \
  --listen "127.0.0.1:${CONTROLLER_PORT}" \
  --public-origin "http://127.0.0.1:${CONTROLLER_PORT}" \
  --password-stdin \
  --agent "local,http://127.0.0.1:${AGENT_PORT},TRACECAT_AGENT_TOKEN,Local Agent" \
  ${version_args[@]+"${version_args[@]}"} ${force_args[@]+"${force_args[@]}"} >/dev/null

# 3) Wait until the dashboard answers, then print the one thing you need.
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${CONTROLLER_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 2 "http://127.0.0.1:${CONTROLLER_PORT}/healthz" >/dev/null 2>&1 \
  || die "Controller did not become healthy; check: journalctl -u tracecat-controller -n 50"

cat <<EOF

TraceCat is running.

  URL       http://127.0.0.1:${CONTROLLER_PORT}
  Password  ${PASSWORD}

  Services  tracecat-controller, tracecat-agent
  Logs      journalctl -u tracecat-controller -u tracecat-agent -f
  Data      /var/lib/tracecat/controller.db

This listens on loopback only. For remote access, put it behind Cloudflare
Access/a private overlay or see docs/DEPLOYMENT.md (do not expose dev/local
auth directly to the internet).
EOF
