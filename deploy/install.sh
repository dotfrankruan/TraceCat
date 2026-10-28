#!/usr/bin/env bash
# TraceCat installer / updater for systemd hosts.
#
# Works two ways:
#   1. From a release tarball (extracted directory containing bin/, configs/,
#      deploy/):   sudo ./install.sh agent --listen 10.0.0.5:8443
#   2. Standalone (downloads the matching GitHub release asset):
#      curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/install.sh | sudo bash -s -- agent ...
#
# It installs the binary, a hardened systemd unit and a validated JSON config,
# generates secrets locally (never transmits them), and enables the service.
# Updates preserve an existing config unless --force is given.
set -euo pipefail

REPO="dotfrankruan/TraceCat"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COMPONENT=""
VERSION=""
TARBALL=""
CHECKSUMS=""
FORCE=0
NO_START=0
BIN_DIR="/usr/local/bin"
ETC_DIR="/etc/tracecat"
STATE_DIR="/var/lib/tracecat"
SERVICE_USER="tracecat"

# controller options
AUTH_MODE="cloudflare"
PUBLIC_ORIGIN=""
CONTROLLER_LISTEN="127.0.0.1:8080"
CF_TEAM_DOMAIN=""
CF_AUDIENCES=()
CF_EMAILS=()
CF_DOMAINS=()
PASSWORD_STDIN=0
AGENT_SPECS=()

# agent options
AGENT_LISTEN=""
AGENT_TOKEN=""
NEXTTRACE_PATH=""
ALLOW_PUBLIC_BIND=0
PROTOCOLS="icmp,tcp,udp"

TMPDIR=""

usage() {
  cat <<'EOF'
TraceCat installer

Usage:
  sudo ./install.sh controller [options]
  sudo ./install.sh agent [options]

Common options:
  --version <vX.Y.Z>   release to install (default: latest)
  --tarball <file>     install from a local release tarball (offline/CI)
  --checksums <file>   checksums file for --tarball verification
  --bin-dir <dir>      binary directory (default /usr/local/bin)
  --force              overwrite an existing config (old one is backed up)
  --no-start           install but do not enable/start the service
  -h, --help           show this help

Controller options:
  --auth <mode>            cloudflare | local | dev (default cloudflare)
  --public-origin <url>    public HTTPS origin (required for cloudflare/local;
                           e.g. https://trace.example.com)
  --listen <ip:port>       loopback/private bind (default 127.0.0.1:8080)
  --cf-team-domain <url>   e.g. https://team.cloudflareaccess.com
  --cf-audience <aud>      Access application Audience tag (repeatable)
  --cf-email <email>       allowed email (repeatable)
  --cf-domain <domain>     allowed email domain (repeatable)
  --password-stdin         read the local-auth password from stdin (min 12)
  --agent <spec>           Agent entry, repeatable:
                             id,url,token_env[,name[,location[,provider]]]
                           token_env is an environment variable name on the
                           Controller host holding that Agent's bearer token.

Agent options:
  --listen <ip:port>       required; an assigned non-public address, e.g.
                           10.0.0.5:8443 or 127.0.0.1:9481
  --token <token>          bearer token (default: generate a random one)
  --nexttrace <path>       NextTrace binary (default: discover in PATH)
  --protocols <csv>        enabled protocols (default icmp,tcp,udp)
  --allow-public-bind      permit binding a globally routable address (not
                           recommended; the Agent refuses public binds by default)

Examples:
  sudo ./install.sh agent --listen 10.0.0.5:8443
  sudo ./install.sh controller --auth cloudflare \
      --public-origin https://trace.example.com \
      --cf-team-domain https://team.cloudflareaccess.com --cf-audience AUD_TAG \
      --agent tokyo-1,http://10.0.0.5:8443,TRACECAT_TOKEN_TOKYO_1,Tokyo,Tokyo JP,DMIT
EOF
}

log()  { printf '[tracecat] %s\n' "$*"; }
warn() { printf '[tracecat] WARNING: %s\n' "$*" >&2; }
die()  { printf '[tracecat] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() { [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT

need_root() { [[ "${EUID}" -eq 0 ]] || die "run as root (sudo)"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

valid_simple() { # value must not break generated JSON / shell context
  local v="$1" name="$2"
  [[ -n "$v" ]] || die "$name must not be empty"
  [[ "$v" != *'"'* && "$v" != *'\'* && "$v" != *$'\n'* && "$v" != *$'\r'* ]] || die "$name contains invalid characters"
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

generate_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48 | tr -d '\n'
  else
    head -c 48 /dev/urandom | base64 | tr -d '\n'
  fi
}

json_escape() { # simple escaper for values already validated by valid_simple
  printf '%s' "$1"
}

add_agent_spec() {
  local spec="$1"
  IFS=',' read -r id url token_env name location provider <<<"$spec"
  [[ -n "$id" && -n "$url" && -n "$token_env" ]] || die "--agent requires id,url,token_env (got: $spec)"
  [[ "$id" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] || die "invalid agent id: $id"
  [[ "$url" =~ ^https?://[A-Za-z0-9._:\-\[\]/]+/?$ ]] || die "invalid agent url: $url"
  [[ "$token_env" =~ ^[A-Z][A-Z0-9_]{0,127}$ ]] || die "invalid token_env name: $token_env"
  name="${name:-$id}"
  valid_simple "$name" "agent name"
  valid_simple "${location:-}" "agent location"
  valid_simple "${provider:-}" "agent provider"
  AGENT_SPECS+=("$id|$url|$token_env|$name|${location:-}|${provider:-}")
}

parse_args() {
  [[ $# -gt 0 ]] || { usage; exit 2; }
  case "$1" in
    controller|agent) COMPONENT="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "expected 'controller' or 'agent' as the first argument" ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) VERSION="${2:?}"; shift 2 ;;
      --tarball) TARBALL="${2:?}"; shift 2 ;;
      --checksums) CHECKSUMS="${2:?}"; shift 2 ;;
      --bin-dir) BIN_DIR="${2:?}"; shift 2 ;;
      --force) FORCE=1; shift ;;
      --no-start) NO_START=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --auth) AUTH_MODE="${2:?}"; shift 2 ;;
      --public-origin) PUBLIC_ORIGIN="${2:?}"; shift 2 ;;
      --listen) if [[ "$COMPONENT" == "agent" ]]; then AGENT_LISTEN="${2:?}"; else CONTROLLER_LISTEN="${2:?}"; fi; shift 2 ;;
      --cf-team-domain) CF_TEAM_DOMAIN="${2:?}"; shift 2 ;;
      --cf-audience) CF_AUDIENCES+=("${2:?}"); shift 2 ;;
      --cf-email) CF_EMAILS+=("${2:?}"); shift 2 ;;
      --cf-domain) CF_DOMAINS+=("${2:?}"); shift 2 ;;
      --password-stdin) PASSWORD_STDIN=1; shift ;;
      --agent) add_agent_spec "${2:?}"; shift 2 ;;
      --token) AGENT_TOKEN="${2:?}"; shift 2 ;;
      --nexttrace) NEXTTRACE_PATH="${2:?}"; shift 2 ;;
      --protocols) PROTOCOLS="${2:?}"; shift 2 ;;
      --allow-public-bind) ALLOW_PUBLIC_BIND=1; shift ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
}

# ---------------------------------------------------------------- download ---
prepare_tree() {
  local arch; arch="$(detect_arch)"
  TMPDIR="$(mktemp -d)"

  # Local extracted release directory (bin/, configs/, deploy/ next to script)
  # or a source checkout (deploy/install.sh next to root bin/).
  if [[ -x "$SCRIPT_DIR/bin/tracecat-$COMPONENT" ]]; then
    TREE="$SCRIPT_DIR"
    log "installing from local release directory: $TREE"
    return
  fi
  local repo_root
  repo_root="$(cd "$SCRIPT_DIR/.." && pwd)"
  if [[ -x "$repo_root/bin/tracecat-$COMPONENT" && -d "$repo_root/deploy/systemd" ]]; then
    TREE="$repo_root"
    log "installing from source checkout: $TREE"
    return
  fi

  local tarball="$TARBALL"
  local checksums="$CHECKSUMS"
  if [[ -z "$tarball" ]]; then
    need_cmd curl
    local base
    if [[ -n "$VERSION" ]]; then
      base="https://github.com/$REPO/releases/download/v${VERSION#v}"
    else
      base="https://github.com/$REPO/releases/latest/download"
    fi
    local asset="tracecat-${COMPONENT}-linux-${arch}.tar.gz"
    log "downloading $asset ..."
    curl -fsSL --retry 3 --proto '=https' -o "$TMPDIR/asset.tar.gz" "$base/$asset" \
      || die "download failed: $base/$asset"
    tarball="$TMPDIR/asset.tar.gz"
    if [[ -z "$checksums" ]]; then
      if curl -fsSL --retry 3 --proto '=https' -o "$TMPDIR/checksums.txt" "$base/checksums.txt"; then
        checksums="$TMPDIR/checksums.txt"
      else
        warn "checksums.txt unavailable; cannot verify the download"
      fi
    fi
  fi

  [[ -f "$tarball" ]] || die "tarball not found: $tarball"
  if [[ -n "$checksums" ]]; then
    need_cmd sha256sum
    local expected actual
    expected="$(grep -E "tracecat-${COMPONENT}-linux-${arch}\.tar\.gz" "$checksums" | awk '{print $1}' | head -1)"
    [[ -n "$expected" ]] || die "no checksum entry for tracecat-${COMPONENT}-linux-${arch}.tar.gz"
    actual="$(sha256sum "$tarball" | awk '{print $1}')"
    [[ "$expected" == "$actual" ]] || die "checksum mismatch for $tarball"
    log "checksum verified"
  else
    warn "installing without checksum verification"
  fi

  mkdir -p "$TMPDIR/tree"
  tar -xzf "$tarball" -C "$TMPDIR/tree"
  TREE="$TMPDIR/tree"
  [[ -x "$TREE/bin/tracecat-$COMPONENT" ]] || die "tarball does not contain bin/tracecat-$COMPONENT"
}

# ---------------------------------------------------------------- install ----
create_user_and_dirs() {
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$STATE_DIR" --create-home \
      --shell /usr/sbin/nologin "$SERVICE_USER"
    log "created system user: $SERVICE_USER"
  fi
  install -d -m 0755 "$ETC_DIR"
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
  install -d -m 0755 "$BIN_DIR"
}

install_common() {
  install -m 0755 "$TREE/bin/tracecat-$COMPONENT" "$BIN_DIR/tracecat-$COMPONENT"
  log "installed $BIN_DIR/tracecat-$COMPONENT"
  install -m 0644 "$TREE/deploy/systemd/tracecat-$COMPONENT.service" /etc/systemd/system/
}

backup_existing() {
  local file="$1"
  if [[ -f "$file" && "$FORCE" -eq 1 ]]; then
    local bak="${file}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a "$file" "$bak"
    log "backed up $file -> $bak"
  fi
}

write_agent_config() {
  [[ -n "$AGENT_LISTEN" ]] || die "agent --listen is required (e.g. 10.0.0.5:8443)"
  [[ "$AGENT_LISTEN" =~ ^[0-9A-Fa-f:.]+:[0-9]{1,5}$ ]] || die "invalid --listen (expected ip:port): $AGENT_LISTEN"

  NEXTTRACE_PATH="${NEXTTRACE_PATH:-$(command -v nexttrace || true)}"
  [[ -n "$NEXTTRACE_PATH" ]] || die "NextTrace not found; install it or pass --nexttrace /path/to/nexttrace"
  [[ -x "$NEXTTRACE_PATH" ]] || die "NextTrace is not executable: $NEXTTRACE_PATH"
  valid_simple "$NEXTTRACE_PATH" "--nexttrace"

  [[ "$PROTOCOLS" =~ ^(icmp|tcp|udp)(,(icmp|tcp|udp))*$ ]] || die "invalid --protocols (want csv of icmp,tcp,udp)"

  local config="$ETC_DIR/agent.json"
  if [[ -f "$config" && "$FORCE" -eq 0 ]]; then
    warn "keeping existing $config (use --force to regenerate)"
  else
    backup_existing "$config"
    local public="false"
    [[ "$ALLOW_PUBLIC_BIND" -eq 1 ]] && public="true"
    cat >"$config" <<EOF
{
  "node_id": "$(hostname | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-' | cut -c1-32 | sed 's/-*$//')",
  "name": "$(hostname)",
  "listen": "$AGENT_LISTEN",
  "auth": {
    "token_env": "TRACECAT_AGENT_TOKEN"
  },
  "nexttrace": {
    "binary": "$NEXTTRACE_PATH",
    "max_concurrent_traces": 4,
    "probe_timeout_ms": 1000,
    "max_execution_ms": 60000,
    "max_stdout_bytes": 4194304,
    "max_raw_bytes": 1048576,
    "geo_provider": "",
    "allowed_protocols": [$(printf '"%s",' ${PROTOCOLS//,/ } | sed 's/,$//')]
  },
  "security": {
    "allow_private_targets": false,
    "allowed_cidrs": [],
    "allow_public_bind": $public
  },
  "rate_limit": {
    "requests_per_minute": 60,
    "burst": 10,
    "max_concurrent_http": 16
  },
  "log_level": "info"
}
EOF
    chmod 0640 "$config"
    chown root:"$SERVICE_USER" "$config"
    log "wrote $config"
  fi

  local envfile="$ETC_DIR/agent.env"
  if [[ -f "$envfile" && "$FORCE" -eq 0 ]]; then
    warn "keeping existing $envfile"
  else
    backup_existing "$envfile"
    [[ -n "$AGENT_TOKEN" ]] || AGENT_TOKEN="$(generate_token)"
    valid_simple "$AGENT_TOKEN" "agent token"
    ( umask 077; printf 'TRACECAT_AGENT_TOKEN=%s\n' "$AGENT_TOKEN" >"$envfile" )
    chmod 0600 "$envfile"
    chown root:root "$envfile"
    log "wrote $envfile (mode 0600)"
  fi

  if [[ ! -f "$TREE/deploy/systemd/tracecat-agent.env.example" ]]; then
    warn "release tarball has no agent env example (continuing)"
  fi

  if [[ "$NO_START" -eq 0 ]]; then
    systemctl daemon-reload
    systemctl enable --now tracecat-agent
    log "tracecat-agent enabled and started"
    log "configure the Controller host with:"
    echo
    echo "    token_env: TRACECAT_AGENT_TOKEN"
    echo "    token     : $(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' "$envfile")"
    echo "    url       : http://$AGENT_LISTEN"
    echo
    warn "treat the token as a secret; it is visible in this terminal only"
  else
    systemctl daemon-reload
    log "installed; start later with: systemctl enable --now tracecat-agent"
  fi
}

write_controller_config() {
  [[ "$AUTH_MODE" == "cloudflare" || "$AUTH_MODE" == "local" || "$AUTH_MODE" == "dev" ]] \
    || die "--auth must be cloudflare, local or dev"

  [[ "$CONTROLLER_LISTEN" =~ ^[0-9A-Fa-f:.]+:[0-9]{1,5}$ ]] || die "invalid --listen: $CONTROLLER_LISTEN"
  if [[ "$AUTH_MODE" == "dev" ]]; then
    [[ "$CONTROLLER_LISTEN" =~ ^(127\.0\.0\.1|\[::1\]): ]] || die "auth.mode=dev requires a loopback --listen"
    PUBLIC_ORIGIN="${PUBLIC_ORIGIN:-http://$CONTROLLER_LISTEN}"
  fi
  [[ -n "$PUBLIC_ORIGIN" ]] || die "--public-origin is required for auth mode $AUTH_MODE"
  [[ "$PUBLIC_ORIGIN" =~ ^https?://[A-Za-z0-9._:\-\[\]/]+$ ]] || die "invalid --public-origin"
  valid_simple "$PUBLIC_ORIGIN" "--public-origin"

  [[ ${#AGENT_SPECS[@]} -gt 0 ]] || die "at least one --agent id,url,token_env is required"

  local config="$ETC_DIR/controller.json"
  local envfile="$ETC_DIR/controller.env"

  if [[ -f "$config" && "$FORCE" -eq 0 ]]; then
    warn "keeping existing $config (use --force to regenerate)"
    if [[ "$NO_START" -eq 0 ]]; then
      systemctl daemon-reload
      systemctl enable --now tracecat-controller
      log "tracecat-controller enabled and started"
    fi
    return
  fi

  if [[ "$AUTH_MODE" == "cloudflare" ]]; then
    [[ -n "$CF_TEAM_DOMAIN" ]] || die "--cf-team-domain is required for cloudflare mode"
    [[ ${#CF_AUDIENCES[@]} -gt 0 ]] || die "--cf-audience is required for cloudflare mode"
    [[ "$CF_TEAM_DOMAIN" =~ ^https://[A-Za-z0-9._:-]+$ ]] || die "invalid --cf-team-domain"
    valid_simple "$CF_TEAM_DOMAIN" "--cf-team-domain"
  fi

  local local_hash=""
  if [[ "$AUTH_MODE" == "local" ]]; then
    local password
    if [[ "$PASSWORD_STDIN" -eq 1 ]]; then
      IFS= read -r password || die "could not read password from stdin"
    else
      [[ -t 0 ]] || die "no TTY; use --password-stdin"
      read -rs -p "Controller password (min 12 chars): " password; echo
      local confirm
      read -rs -p "Confirm password: " confirm; echo
      [[ "$password" == "$confirm" ]] || die "passwords do not match"
    fi
    [[ ${#password} -ge 12 ]] || die "password must be at least 12 characters"
    local_hash="$(printf '%s' "$password" | "$BIN_DIR/tracecat-controller" -hash-password)" \
      || die "could not hash the password"
    [[ "$local_hash" == pbkdf2-sha256\$* ]] || die "unexpected password hash output"
  fi

  local csrf_secret; csrf_secret="$(generate_token)"

  backup_existing "$config"
  backup_existing "$envfile"

  {
    cat <<EOF
{
  "listen": "$CONTROLLER_LISTEN",
  "public_origin": "$PUBLIC_ORIGIN",
  "auth": {
EOF
    case "$AUTH_MODE" in
      cloudflare)
        printf '    "mode": "cloudflare",\n'
        printf '    "cloudflare": {\n'
        printf '      "team_domain": "%s",\n' "$CF_TEAM_DOMAIN"
        printf '      "audience": ['
        local i
        for i in "${!CF_AUDIENCES[@]}"; do
          valid_simple "${CF_AUDIENCES[$i]}" "audience"
          [[ "$i" -gt 0 ]] && printf ', '
          printf '"%s"' "${CF_AUDIENCES[$i]}"
        done
        printf '],\n'
        printf '      "allowed_emails": ['
        for i in "${!CF_EMAILS[@]}"; do
          [[ "${CF_EMAILS[$i]}" =~ ^[^@]+@[^@]+$ ]] || die "invalid --cf-email"
          [[ "$i" -gt 0 ]] && printf ', '
          printf '"%s"' "${CF_EMAILS[$i]}"
        done
        printf '],\n'
        printf '      "allowed_email_domains": ['
        for i in "${!CF_DOMAINS[@]}"; do
          valid_simple "${CF_DOMAINS[$i]}" "allowed email domain"
          [[ "$i" -gt 0 ]] && printf ', '
          printf '"%s"' "${CF_DOMAINS[$i]}"
        done
        printf '],\n'
        printf '      "jwks_cache_ttl_seconds": 300,\n'
        printf '      "csrf_secret_env": "TRACECAT_CSRF_SECRET"\n'
        printf '    }\n'
        ;;
      local)
        printf '    "mode": "local",\n'
        printf '    "local": {\n'
        printf '      "password_hash_env": "TRACECAT_CONTROLLER_PASSWORD_HASH",\n'
        printf '      "session_ttl_seconds": 43200\n'
        printf '    }\n'
        ;;
      dev)
        printf '    "mode": "dev"\n'
        ;;
    esac
    cat <<EOF
  },
  "database": {
    "path": "$STATE_DIR/controller.db",
    "max_history_jobs": 200
  },
  "dns": {
    "timeout_ms": 4000,
    "max_addresses": 16
  },
  "limits": {
    "max_hops": 30,
    "max_queries": 3,
    "min_execution_ms": 5000,
    "max_execution_ms": 60000,
    "max_nodes_per_job": 8,
    "max_jobs_per_minute": 30,
    "max_concurrent_jobs": 4,
    "max_concurrent_traces": 4,
    "max_resolves_per_minute": 120,
    "max_raw_result_bytes": 1048576,
    "allowed_protocols": ["icmp", "tcp", "udp"]
  },
  "agents": [
EOF
    local idx=0 spec id url token_env name location provider
    for spec in "${AGENT_SPECS[@]}"; do
      IFS='|' read -r id url token_env name location provider <<<"$spec"
      [[ "$idx" -gt 0 ]] && printf ',\n'
      printf '    {\n'
      printf '      "id": "%s",\n' "$id"
      printf '      "name": "%s",\n' "$name"
      [[ -n "$location" ]] && printf '      "location": "%s",\n' "$location"
      [[ -n "$provider" ]] && printf '      "provider": "%s",\n' "$provider"
      printf '      "url": "%s",\n' "$url"
      printf '      "token_env": "%s",\n' "$token_env"
      printf '      "enabled": true,\n'
      printf '      "request_timeout_ms": 75000\n'
      printf '    }'
      idx=$((idx + 1))
    done
    cat <<EOF

  ],
  "security": {
    "allowed_cidrs": []
  },
  "trusted_proxies": ["127.0.0.1/32", "::1/128"],
  "log_level": "info"
}
EOF
  } >"$config"
  chmod 0640 "$config"
  chown root:"$SERVICE_USER" "$config"
  log "wrote $config"

  local missing_tokens=0 spec id url token_env name location provider token_value
  {
    if [[ "$AUTH_MODE" == "local" ]]; then
      printf 'TRACECAT_CONTROLLER_PASSWORD_HASH=%s\n' "$local_hash"
    fi
    if [[ "$AUTH_MODE" == "cloudflare" ]]; then
      printf 'TRACECAT_CSRF_SECRET=%s\n' "$csrf_secret"
    fi
    for spec in "${AGENT_SPECS[@]}"; do
      IFS='|' read -r id url token_env name location provider <<<"$spec"
      token_value="${!token_env-}"
      if [[ -n "$token_value" ]]; then
        valid_simple "$token_value" "$token_env"
        printf '%s=%s\n' "$token_env" "$token_value"
      else
        printf '# %s=REPLACE_WITH_THE_AGENT_TOKEN\n' "$token_env"
        missing_tokens=$((missing_tokens + 1))
      fi
    done
  } >"$envfile"
  chmod 0600 "$envfile"
  chown root:"$SERVICE_USER" "$envfile"
  log "wrote $envfile (mode 0600)"

  if [[ "$missing_tokens" -gt 0 ]]; then
    warn "$missing_tokens Agent token environment variable(s) were not set while installing."
    warn "Add them to $envfile (names shown as comments), then: systemctl enable --now tracecat-controller"
    NO_START=1
  fi

  if [[ "$NO_START" -eq 0 ]]; then
    systemctl daemon-reload
    systemctl enable --now tracecat-controller
    log "tracecat-controller enabled and started"
    log "listening on $CONTROLLER_LISTEN (public origin $PUBLIC_ORIGIN)"
    [[ "$AUTH_MODE" == "cloudflare" ]] && log "put the Access JWT verification settings in $config and the csrf secret in $envfile"
  else
    systemctl daemon-reload
    log "installed; start later with: systemctl enable --now tracecat-controller"
  fi
}

main() {
  need_root
  parse_args "$@"
  for cmd in install systemctl tar awk sed grep; do need_cmd "$cmd"; done
  prepare_tree
  create_user_and_dirs
  install_common
  case "$COMPONENT" in
    controller) write_controller_config ;;
    agent) write_agent_config ;;
  esac
  log "done. Docs: https://github.com/$REPO/blob/main/docs/DEPLOYMENT.md"
}

main "$@"
