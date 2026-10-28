#!/usr/bin/env bash
# Install TraceCat binaries, service units and example configs on a systemd host.
#
# Usage (as root):
#   ./scripts/install-systemd.sh controller
#   ./scripts/install-systemd.sh agent
#   ./scripts/install-systemd.sh both
#
# This script never starts a service automatically unless the config already
# exists; it never prints or generates secrets. Follow docs/DEPLOYMENT.md.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TARGET=${1:-}

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (sudo)" >&2
  exit 1
fi
if [[ "$TARGET" != "controller" && "$TARGET" != "agent" && "$TARGET" != "both" ]]; then
  echo "usage: $0 {controller|agent|both}" >&2
  exit 2
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: missing $1" >&2; exit 1; }; }
need install
need systemctl

create_user() {
  if ! id tracecat >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/tracecat --create-home \
      --shell /usr/sbin/nologin tracecat
  fi
  install -d -m 0755 /etc/tracecat
  install -d -m 0700 -o tracecat -g tracecat /var/lib/tracecat
}

install_controller() {
  local bin="$ROOT/bin/tracecat-controller"
  [[ -x "$bin" ]] || { echo "error: build first (make build-backend); missing $bin" >&2; exit 1; }
  install -m 0755 "$bin" /usr/local/bin/tracecat-controller
  install -m 0644 "$ROOT/deploy/systemd/tracecat-controller.service" /etc/systemd/system/
  if [[ ! -f /etc/tracecat/controller.json ]]; then
    install -m 0640 -o root -g tracecat "$ROOT/configs/controller.example.json" /etc/tracecat/controller.json
    echo "installed example /etc/tracecat/controller.json — EDIT IT before starting"
  fi
  if [[ ! -f /etc/tracecat/controller.env ]]; then
    install -m 0600 -o root -g tracecat "$ROOT/deploy/systemd/tracecat-controller.env.example" /etc/tracecat/controller.env
    echo "installed example /etc/tracecat/controller.env — set secrets before starting"
  fi
}

install_agent() {
  local bin="$ROOT/bin/tracecat-agent"
  [[ -x "$bin" ]] || { echo "error: build first (make build-backend); missing $bin" >&2; exit 1; }
  install -m 0755 "$bin" /usr/local/bin/tracecat-agent
  install -m 0644 "$ROOT/deploy/systemd/tracecat-agent.service" /etc/systemd/system/
  if [[ ! -f /etc/tracecat/agent.json ]]; then
    install -m 0640 -o root -g tracecat "$ROOT/configs/agent.example.json" /etc/tracecat/agent.json
    echo "installed example /etc/tracecat/agent.json — set node_id/listen/nexttrace path"
  fi
  if [[ ! -f /etc/tracecat/agent.env ]]; then
    install -m 0600 -o root -g root "$ROOT/deploy/systemd/tracecat-agent.env.example" /etc/tracecat/agent.env
    echo "installed example /etc/tracecat/agent.env — set a unique bearer token"
  fi
  command -v nexttrace >/dev/null 2>&1 || echo "warning: nexttrace not found in PATH; install it before starting the Agent"
}

create_user
case "$TARGET" in
  controller) install_controller ;;
  agent) install_agent ;;
  both) install_controller; install_agent ;;
esac

systemctl daemon-reload
echo "done. Review configs/secrets, then: systemctl enable --now tracecat-${TARGET/both/controller}"
