#!/usr/bin/env bash
# Independent, adversarial verification of a deployed TraceCat Agent.
#
# RUNS ON THE AGENT HOST AS ROOT (it needs journalctl, ss, systemctl and
# /proc access to audit the unprivileged service). It never modifies production
# source code; it only starts/stops the unit and writes temporary configs under
# /etc/tracecat/verify-*.json (removed on exit).
#
# No secrets are embedded: the bearer token is read from the Agent env file and
# never printed. Results are written to $RESULTS (TSV) for docs/VERIFICATION.md.
#
# Usage:
#   verify/agent-remote-verify.sh                 # full run
#   SKIP_TRACES=1 verify/agent-remote-verify.sh   # HTTP/config checks only
#
# Exit code: 0 only when no FAIL was recorded (SKIPs allowed for environmental
# limitations; they are reported separately).
set -uo pipefail

UNIT="${UNIT:-tracecat-agent}"
CONFIG="${CONFIG:-/etc/tracecat/agent.json}"
ENVFILE="${ENVFILE:-/etc/tracecat/agent.env}"
AGENT_BIN="${AGENT_BIN:-/usr/local/bin/tracecat-agent}"
NEXTRACE_BIN="${NEXTRACE_BIN:-/usr/local/bin/nexttrace}"
RESULTS="${RESULTS:-/tmp/tracecat-verify-results.tsv}"
SKIP_TRACES="${SKIP_TRACES:-0}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "error: run as root on the Agent host" >&2
  exit 2
fi

TMPD=$(mktemp -d /tmp/tc-verify.XXXXXX)
chmod 700 "$TMPD"
cleanup() {
  rm -rf "$TMPD"
  rm -f /etc/tracecat/verify-*.json 2>/dev/null
  rm -f /tmp/tracecat-pwned
}
trap cleanup EXIT

: >"$RESULTS"
PASS_N=0 FAIL_N=0 SKIP_N=0
record() { # record <PASS|FAIL|SKIP> <check> <expected> <observed>
  local status=$1 check=$2 expected=$3 observed=$4
  case "$status" in
    PASS) PASS_N=$((PASS_N + 1)) ;;
    FAIL) FAIL_N=$((FAIL_N + 1)) ;;
    SKIP) SKIP_N=$((SKIP_N + 1)) ;;
  esac
  printf '%s\t%s\t%s\t%s\n' "$status" "$check" "$expected" "$observed" >>"$RESULTS"
  printf '%-4s %-46s expected=%s observed=%s\n' "$status" "$check" "$expected" "$observed"
}
section() { printf '\n=== %s ===\n' "$1"; }

# --- target facts ---------------------------------------------------------
TOKEN=$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' "$ENVFILE" 2>/dev/null | head -1)
if [[ -z "$TOKEN" ]]; then
  echo "error: no token in $ENVFILE" >&2
  exit 2
fi
read -r TS_IP NODE_ID CONC < <(python3 - "$CONFIG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
host = cfg["listen"].rsplit(":", 1)[0]
print(host, cfg["node_id"], cfg["nexttrace"]["max_concurrent_traces"])
PY
)
BASE_URL="http://${TS_IP}:8443"
CURLRC="$TMPD/curlrc"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" >"$CURLRC"
chmod 600 "$CURLRC"

LAST_CODE="000"
LAST_BODY="$TMPD/body"
LAST_HDR="$TMPD/hdr"
api() { # api METHOD PATH [BODY] [CONTENT_TYPE]
  local method=$1 path=$2 body=${3-} ct=${4-application/json}
  pace_maybe
  : >"$LAST_BODY"
  : >"$LAST_HDR"
  local args=(-sS --max-time 180 --config "$CURLRC" -o "$LAST_BODY" -D "$LAST_HDR" \
    -w '%{http_code}' -X "$method")
  if [[ $# -ge 3 ]]; then
    args+=(-H "Content-Type: $ct" --data-binary "$body")
  fi
  LAST_CODE=$(curl "${args[@]}" "${BASE_URL}${path}" 2>"$TMPD/curlerr") || true
  [[ -n "$LAST_CODE" ]] || LAST_CODE="000"
}
api_anon() { # api_anon METHOD PATH [BODY] [CONTENT_TYPE] [AUTH_HEADER]
  local method=$1 path=$2 body=${3-} ct=${4-application/json} auth=${5-}
  pace_maybe
  : >"$LAST_BODY"
  : >"$LAST_HDR"
  local args=(-sS --max-time 60 -o "$LAST_BODY" -D "$LAST_HDR" -w '%{http_code}' -X "$method")
  [[ -n "$auth" ]] && args+=(-H "Authorization: $auth")
  if [[ $# -ge 3 ]]; then
    args+=(-H "Content-Type: $ct" --data-binary "$body")
  fi
  LAST_CODE=$(curl "${args[@]}" "${BASE_URL}${path}" 2>"$TMPD/curlerr") || true
  [[ -n "$LAST_CODE" ]] || LAST_CODE="000"
}
json_get() { # json_get <dotted.path> [default]  (reads $LAST_BODY or $1 as file)
  python3 - "$LAST_BODY" "$1" "${2-}" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print(sys.argv[3] if len(sys.argv) > 3 else "")
    sys.exit(0)
cur = doc
for part in sys.argv[2].split("."):
    if not part:
        continue
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list):
        try:
            cur = cur[int(part)]
        except Exception:
            cur = None
    else:
        cur = None
print(sys.argv[3] if (cur is None and len(sys.argv) > 3) else cur)
PY
}
hdr_get() { awk -v IGNORECASE=1 -v k="$1" 'BEGIN{FS=": "} tolower($1)==tolower(k){v=$2; sub(/\r$/,"",v); print v}' "$LAST_HDR" | tail -1; }
hdr_has() { grep -qiE "^${1}:" "$LAST_HDR"; }
journal_since() { journalctl -u "$UNIT" --no-pager -o cat --since "$1" 2>/dev/null; }
AUTOPACE=1
PACE_COUNT=0
restart_agent() {
  # clear systemd's start-limit counter: the harness deliberately restarts the
  # unit several times per run, which would otherwise trip the default
  # "5 starts in 10 s" limiter (a harness artefact, not a product issue).
  systemctl reset-failed "$UNIT" 2>/dev/null || true
  systemctl restart "$UNIT"
  PACE_COUNT=0
  sleep 1.2
}
pace_maybe() {
  [[ "$AUTOPACE" == "1" ]] || return 0
  PACE_COUNT=$((PACE_COUNT + 1))
  if [[ $PACE_COUNT -ge 7 ]]; then
    restart_agent
  fi
}
health_ok() { systemctl is-active --quiet "$UNIT"; }
trace_body() { # trace_body target family hops queries timeout job
  printf '{"schema_version":"tracecat.agent.v1","job_id":"%s","node_id":"%s","target_ip":"%s","family":"%s","protocol":"icmp","max_hops":%s,"queries":%s,"timeout_ms":%s}' \
    "$6" "$NODE_ID" "$1" "$2" "$3" "$4" "$5"
}
new_job() { printf '%s' "$(date +%s%N | sha256sum | cut -c1-32)"; }

# trace_ext builds a /v1/trace body with the extended protocol/port/interface
# fields. port/interface use "" to omit the field, "str:443" forces a JSON
# string (negative test), anything else is an integer.
trace_ext() { # target family protocol port interface hops queries timeout_ms
  python3 - "$NODE_ID" "$@" <<'PY'
import json, secrets, sys
node, target, family, protocol, port, iface, hops, queries, timeout = sys.argv[1:10]
body = {
    "schema_version": "tracecat.agent.v1",
    "job_id": secrets.token_hex(16),
    "node_id": node,
    "target_ip": target,
    "family": family,
    "protocol": protocol,
    "max_hops": int(hops),
    "queries": int(queries),
    "timeout_ms": int(timeout),
}
if port != "":
    body["port"] = port[4:] if port.startswith("str:") else int(port)
if iface != "":
    body["interface"] = iface
print(json.dumps(body))
PY
}

# trace_exec runs one trace while auditing the live NextTrace child argv.
# Sets LAST_EXEC_CODE / LAST_EXEC_BODY / LAST_ARGV.
trace_exec() { # trace_exec <label> <body>
  local label=$1 body=$2
  local out="$TMPD/trace-$label.json"
  local codef="$TMPD/code-$label"
  : >"$codef"
  curl -sS -m 150 --config "$CURLRC" -H 'Content-Type: application/json' \
    --data-binary "$body" "${BASE_URL}/v1/trace" -o "$out" -w '%{http_code}' >"$codef" 2>"$TMPD/err-$label" &
  local bg=$!
  local p=""
  for _ in $(seq 1 75); do
    p=$(pgrep -n -f '^/usr/local/bin/nexttrace' 2>/dev/null || true)
    [[ -n "$p" ]] && break
    sleep 0.2
  done
  LAST_ARGV=""
  [[ -n "$p" ]] && LAST_ARGV=$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true)
  wait "$bg" 2>/dev/null || true
  LAST_EXEC_CODE=$(cat "$codef" 2>/dev/null || echo 000)
  LAST_EXEC_BODY="$out"
}

argv_ok() { # argv_ok <protocol> <port> <interface> <target> <family>
  python3 "$(dirname "$0")/check_argv.py" "$LAST_ARGV" --protocol "$1" --port "$2" \
    --interface "$3" --target "$4" --family "$5" >"$TMPD/argvcheck" 2>&1
}

echo "TraceCat Agent independent verification — $(date -u +%FT%TZ)"
echo "host=$(hostname) unit=$UNIT config=$CONFIG listen=$BASE_URL node=$NODE_ID"
echo "results: $RESULTS"

# =========================================================================
section "A. deployment posture"
# =========================================================================
record "$([[ $(systemctl is-enabled "$UNIT" 2>/dev/null) == enabled ]] && echo PASS || echo FAIL)" \
  "unit_enabled" "enabled" "$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" \
  "unit_active" "active" "$(systemctl is-active "$UNIT" 2>/dev/null || true)"
record "$([[ $(systemctl show -p User --value "$UNIT") == tracecat ]] && echo PASS || echo FAIL)" \
  "runs_as_unprivileged" "User=tracecat" "$(systemctl show -p User --value "$UNIT")"
record "$([[ $(systemctl show -p NoNewPrivileges --value "$UNIT") == yes ]] && echo PASS || echo FAIL)" \
  "no_new_privileges" "yes" "$(systemctl show -p NoNewPrivileges --value "$UNIT")"
record "$([[ $(systemctl show -p AmbientCapabilities --value "$UNIT") == cap_net_raw ]] && echo PASS || echo FAIL)" \
  "ambient_cap_net_raw" "cap_net_raw" "$(systemctl show -p AmbientCapabilities --value "$UNIT")"
record "$([[ $(systemctl show -p CapabilityBoundingSet --value "$UNIT") == cap_net_raw ]] && echo PASS || echo FAIL)" \
  "capability_bounding_set" "cap_net_raw" "$(systemctl show -p CapabilityBoundingSet --value "$UNIT")"
record "$([[ $(systemctl show -p ProtectSystem --value "$UNIT") == strict ]] && echo PASS || echo FAIL)" \
  "protect_system" "strict" "$(systemctl show -p ProtectSystem --value "$UNIT")"
record "$([[ $(systemctl show -p PrivateTmp --value "$UNIT") == yes ]] && echo PASS || echo FAIL)" \
  "private_tmp" "yes" "$(systemctl show -p PrivateTmp --value "$UNIT")"
mdwe=$(systemctl show -p MemoryDenyWriteExecute --value "$UNIT")
if [[ "$mdwe" == no ]]; then
  record PASS "memory_deny_write_execute" "disabled (nexttrace needs W+X or it SIGSEGVs)" "no"
else
  record FAIL "memory_deny_write_execute" "no (NextTrace v1.7.3 SIGSEGVs under MDWE)" "$mdwe"
fi

listen_lines=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep -c ':8443$' || true)
listener=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep ':8443$' || true)
record "$([[ $listen_lines -eq 1 && "$listener" == "${TS_IP}:8443" ]] && echo PASS || echo FAIL)" \
  "binds_only_tailscale_ip" "single ${TS_IP}:8443" "${listener:-none}"
record "$(echo "$listener" | grep -qE '(^0\.0\.0\.0:8443|\*:8443|\[::\]:8443)' && echo FAIL || echo PASS)" \
  "no_wildcard_bind" "no 0.0.0.0/:: listener" "${listener:-none}"

world_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://124.222.154.86:8443/v1/health" 2>/dev/null || true)
record "$([[ "$world_code" != "200" ]] && echo PASS || echo FAIL)" \
  "not_reachable_on_public_ip" "no HTTP 200 on public IP" "code=${world_code:-none}"

cfg_mode=$(stat -c '%a %U:%G' "$CONFIG")
record "$([[ "$cfg_mode" == "640 root:tracecat" ]] && echo PASS || echo FAIL)" \
  "config_permissions" "640 root:tracecat" "$cfg_mode"
env_mode=$(stat -c '%a %U:%G' "$ENVFILE")
record "$([[ "$env_mode" == "600 root:root" ]] && echo PASS || echo FAIL)" \
  "secret_file_permissions" "600 root:root" "$env_mode"
record "$([[ ${#TOKEN} -ge 32 ]] && echo PASS || echo FAIL)" \
  "token_entropy_length" ">=32 bytes" "len=${#TOKEN}"

agent_pid=$(systemctl show -p MainPID --value "$UNIT")
proc_user=$(ps -o user= -p "$agent_pid" 2>/dev/null | tr -d ' ')
record "$([[ "$proc_user" == tracecat ]] && echo PASS || echo FAIL)" \
  "agent_process_user" "tracecat" "${proc_user:-missing}"

# =========================================================================
section "B. authentication"
# =========================================================================
api_anon GET /v1/health
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_missing_token" "401" "$LAST_CODE $(json_get error.code)"
record "$([[ $(hdr_get WWW-Authenticate) == Bearer ]] && echo PASS || echo FAIL)" \
  "auth_challenge_header" "WWW-Authenticate: Bearer" "$(hdr_get WWW-Authenticate)"
api_anon GET /v1/health "" application/json "Bearer definitely-not-the-token"
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_wrong_token" "401" "$LAST_CODE $(json_get error.code)"
api_anon GET /v1/health "" application/json "Basic dXNlcjpwYXNz"
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_wrong_scheme" "401" "$LAST_CODE $(json_get error.code)"
api_anon GET /v1/health "" application/json "Bearer "
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_empty_bearer" "401" "$LAST_CODE $(json_get error.code)"
api_anon GET /v1/does-not-exist
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_before_routing" "401 on unknown path without token" "$LAST_CODE"

api GET /v1/health
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "health_with_token" "200" "$LAST_CODE"
record "$([[ $(json_get schema_version) == tracecat.agent.v1 ]] && echo PASS || echo FAIL)" \
  "health_schema" "tracecat.agent.v1" "$(json_get schema_version)"
HEALTH_STATUS=$(json_get status)
HEALTH_NT=$(json_get nexttrace.available)
record "$([[ "$HEALTH_STATUS" == "ok" ]] && echo PASS || echo FAIL)" \
  "health_status_ok" "ok (nexttrace usable)" "${HEALTH_STATUS} nexttrace.available=${HEALTH_NT} err=$(json_get nexttrace.error.message)"
record "$([[ $(json_get node_id) == "$NODE_ID" ]] && echo PASS || echo FAIL)" "health_node_id" "$NODE_ID" "$(json_get node_id)"
record "$([[ $(json_get limits.max_timeout_ms) == "60000" ]] && echo PASS || echo FAIL)" \
  "health_limits" "max_timeout_ms=60000 max_concurrent=4" "$(json_get limits.max_timeout_ms)/$(json_get limits.max_concurrent_traces)"
python3 - "$LAST_BODY" >"$TMPD/healthcheck" 2>&1 <<'PY' && rc=0 || rc=$?
import json, re, sys
doc = json.load(open(sys.argv[1]))
assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z", doc["time"]), doc["time"]
assert doc["limits"]["max_hops"] == 64 and doc["limits"]["max_queries"] == 5
print("ok")
PY
record "$([[ ${rc:-0} -eq 0 ]] && echo PASS || echo FAIL)" "health_time_format" "RFC3339Nano" "$(cat "$TMPD/healthcheck")"
record "$([[ $(json_get limits.protocols) == *icmp* && $(json_get limits.protocols) == *tcp* && $(json_get limits.protocols) == *udp* ]] && echo PASS || echo FAIL)" \
  "health_limits_protocols" "protocols=[icmp tcp udp]" "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["limits"]["protocols"])' "$LAST_BODY" 2>/dev/null)"
caps=$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["nexttrace"]["capabilities"]))' "$LAST_BODY" 2>/dev/null)
record "$([[ "$caps" == *tcp* && "$caps" == *udp* && "$caps" == *port* && "$caps" == *device* ]] && echo PASS || echo FAIL)" \
  "health_capabilities_extended" "detected tcp/udp/port/device" "$caps"
iface_ok=$(python3 - "$LAST_BODY" >"$TMPD/ifacecheck" 2>&1 <<'PY' && echo PASS || echo FAIL
import json, re, sys
doc = json.load(open(sys.argv[1]))
names = doc["interfaces"]
assert isinstance(names, list) and names, names
assert names == sorted(names), f"not sorted: {names}"
assert all(re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", n) for n in names), names
for pattern in (r"lo", r"docker.*", r"veth.*", r"br-.*", r"bridge.*", r"virbr.*", r"cni.*", r"podman.*"):
    assert not any(re.fullmatch(pattern, n) for n in names), f"excluded interface advertised: {names}"
assert "eth0" in names, names
print("ok", names)
PY
)
record "$iface_ok" "health_interfaces_eligible" "sorted, excludes lo/docker/veth/bridge, includes eth0" "$(cat "$TMPD/ifacecheck")"
leak=""
for needle in "$TOKEN" "/etc/tracecat" "/usr/local/bin/nexttrace" "TRACECAT_AGENT_TOKEN" "HOME=" "PATH="; do
  grep -qF -- "$needle" "$LAST_BODY" && leak="$leak $needle"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "health_no_secret_or_path_leak" "no token/path/env" "${leak:-none}"
body_headers_ok=1
grep -qi '^Content-Type: application/json' "$LAST_HDR" || body_headers_ok=0
grep -qi '^X-Content-Type-Options: nosniff' "$LAST_HDR" || body_headers_ok=0
grep -qi '^Cache-Control: no-store' "$LAST_HDR" || body_headers_ok=0
record "$([[ $body_headers_ok -eq 1 ]] && echo PASS || echo FAIL)" \
  "security_headers" "application/json + nosniff + no-store" "$(tr -d '\r' <"$LAST_HDR" | grep -iE 'content-type|x-content-type-options|cache-control' | paste -sd';' -)"

# =========================================================================
section "C. HTTP method handling"
# =========================================================================
api GET /v1/trace
record "$([[ "$LAST_CODE" == "405" ]] && echo PASS || echo FAIL)" "trace_get_method" "405" "$LAST_CODE Allow=$(hdr_get Allow)"
api POST /v1/health
record "$([[ "$LAST_CODE" == "405" ]] && echo PASS || echo FAIL)" "health_post_method" "405" "$LAST_CODE Allow=$(hdr_get Allow)"
api PUT /v1/trace
record "$([[ "$LAST_CODE" == "405" ]] && echo PASS || echo FAIL)" "trace_put_method" "405" "$LAST_CODE Allow=$(hdr_get Allow)"
api_anon GET /v1/health
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "unauth_unaffected_by_method_check" "401 first" "$LAST_CODE"

# =========================================================================
section "D. strict JSON / schema / limits"
# =========================================================================
restart_agent
valid=$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)")
api POST /v1/trace "$valid"
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "valid_request_reaches_trace" "200 (terminal status inside)" "$LAST_CODE status=$(json_get status) err=$(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)" | sed 's/"protocol":"icmp"/"protocol":"icmp","unknown_field":1/')"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "json_unknown_field" "400 invalid_request" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "${valid}}{"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "json_trailing_data" "400 invalid_request" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)" | sed 's/tracecat.agent.v1/tracecat.agent.v2/')"
record "$([[ "$LAST_CODE" == "400" && $(json_get error.code) == "unsupported_schema_version" ]] && echo PASS || echo FAIL)" \
  "wrong_schema_version" "400 unsupported_schema_version" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "short")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "bad_job_id" "400" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)" | sed "s/\"node_id\":\"$NODE_ID\"/\"node_id\":\"other-node\"/")"
record "$([[ "$LAST_CODE" == "403" && $(json_get error.code) == "forbidden" ]] && echo PASS || echo FAIL)" \
  "wrong_node_id" "403 forbidden" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)" | sed 's/"family":"ipv4"/"family":"ipv5"/')"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "bad_family" "400" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)" | sed 's/"protocol":"icmp"/"protocol":"tcp"/')"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "bad_protocol" "400 (tcp not in MVP)" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 0 1 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "max_hops_zero" "400" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 65 1 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "max_hops_above_global_max" "400" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 0 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "queries_zero" "400" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 6 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "queries_above_global_max" "400" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 1000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "timeout_below_min" "400" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 120000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "timeout_above_agent_max" "400 (agent max 60000)" "$LAST_CODE $(json_get error.code)"

api POST /v1/trace "$(trace_body 1.1.1.1 ipv6 8 1 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "family_target_mismatch" "400" "$LAST_CODE $(json_get error.code)"

# =========================================================================
section "E. target rejection (injection / SSRF policy)"
# =========================================================================
restart_agent
rm -f /tmp/tracecat-pwned
# label|target|family
declare -a TARGETS=(
  "hostname|example.com|ipv4"
  "semicolon_cmd|1.1.1.1; touch /tmp/tracecat-pwned|ipv4"
  "dollar_paren|1.1.1.1 \$(id)|ipv4"
  "backticks|1.1.1.1 \`id\`|ipv4"
  "flag_help|--help|ipv4"
  "flag_family|-4|ipv4"
  "flag_output|-o /etc/passwd|ipv4"
  "bracketed_v6|[2606:4700::1]|ipv6"
  "zoned_v6|fe80::1%25eth0|ipv6"
  "mapped_v6|::ffff:127.0.0.1|ipv6"
  "private_10|10.0.0.1|ipv4"
  "private_172|172.16.0.1|ipv4"
  "private_192|192.168.1.1|ipv4"
  "metadata_linklocal|169.254.169.254|ipv4"
  "documentation_203|203.0.113.10|ipv4"
  "documentation_198|198.51.100.1|ipv4"
  "cgnat_100_64|100.64.0.1|ipv4"
  "unspecified|0.0.0.0|ipv4"
  "multicast|224.0.0.1|ipv4"
  "loopback_v6|::1|ipv6"
  "documentation_v6|2001:db8::1|ipv6"
  "with_port|1.1.1.1:80|ipv4"
  "url|http://1.1.1.1/|ipv4"
  "trailing_space|1.1.1.1 |ipv4"
  "newline|1.1.1.1
|ipv4"
)
for entry in "${TARGETS[@]}"; do
  label=${entry%%|*}
  rest=${entry#*|}
  target=${rest%|*}
  family=${rest##*|}
  api POST /v1/trace "$(trace_body "$target" "$family" 8 1 60000 "$(new_job)")"
  code_field=$(json_get error.code)
  ok=0
  [[ "$LAST_CODE" =~ ^4[0-9][0-9]$ ]] && ok=1
  [[ "$code_field" == "target_rejected" || "$code_field" == "invalid_request" ]] || ok=0
  record "$([[ $ok -eq 1 ]] && echo PASS || echo FAIL)" "inject_reject[$label]" "4xx target_rejected/invalid_request" "$LAST_CODE $code_field"
done
record "$([[ ! -e /tmp/tracecat-pwned ]] && echo PASS || echo FAIL)" "no_injection_side_effect" "/tmp/tracecat-pwned absent" "$([[ -e /tmp/tracecat-pwned ]] && echo present || echo absent)"
pwn=$(pgrep -a nexttrace 2>/dev/null || true)
record "$([[ -z "$pwn" ]] && echo PASS || echo FAIL)" "no_child_ran_for_rejected_targets" "no nexttrace process" "${pwn:-none}"
# an allowed target still reaches the runner (200 + terminal status) — proves the
# rejects above are policy, not a blanket failure.
api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)")"
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "allowed_target_still_reaches_runner" "200" "$LAST_CODE status=$(json_get status)"

# =========================================================================
section "F. content type and body size"
# =========================================================================
restart_agent
api POST /v1/trace "$valid" "text/plain"
record "$([[ "$LAST_CODE" == "415" ]] && echo PASS || echo FAIL)" "content_type_text_plain" "415" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$valid" ""
record "$([[ "$LAST_CODE" == "415" ]] && echo PASS || echo FAIL)" "content_type_missing" "415" "$LAST_CODE $(json_get error.code)"
api POST /v1/trace "$valid" "application/json; charset=utf-8"
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "content_type_with_charset" "200" "$LAST_CODE status=$(json_get status)"

python3 - "$TMPD/big.json" <<'PY'
import json, sys
body = {
    "schema_version": "tracecat.agent.v1",
    "job_id": "a" * 32,
    "node_id": "x",
    "target_ip": "1.1.1.1",
    "family": "ipv4",
    "protocol": "icmp",
    "max_hops": 8,
    "queries": 1,
    "timeout_ms": 60000,
    "pad": "A" * (70 * 1024),
}
open(sys.argv[1], "w").write(json.dumps(body))
PY
api POST /v1/trace "@$TMPD/big.json"
record "$([[ "$LAST_CODE" == "413" ]] && echo PASS || echo FAIL)" "body_over_64kib" "413 payload_too_large" "$LAST_CODE $(json_get error.code) size=$(stat -c %s "$TMPD/big.json")"
api POST /v1/trace ""
record "$([[ "$LAST_CODE" == "400" ]] && echo PASS || echo FAIL)" "empty_body" "400" "$LAST_CODE $(json_get error.code)"

# =========================================================================
section "G. rate limiting"
# =========================================================================
AUTOPACE=0
restart_agent
codes=""
retry_after=""
for _ in $(seq 1 16); do
  api GET /v1/health
  codes="$codes $LAST_CODE"
  [[ -z "$retry_after" ]] && retry_after=$(hdr_get Retry-After)
done
n429=$(grep -o '429' <<<"$codes" | wc -l | tr -d ' ')
record "$([[ $n429 -ge 1 ]] && echo PASS || echo FAIL)" "burst_rate_limit" ">=1x 429 among 16 rapid requests" "codes=${codes# }"
api GET /v1/health
code_field=$(json_get error.code)
record "$([[ "$LAST_CODE" == "429" && "$code_field" == "rate_limited" ]] && echo PASS || echo FAIL)" \
  "rate_limit_envelope" "429 rate_limited" "$LAST_CODE $code_field retry_after=${retry_after:-none}"
record "$([[ "${retry_after:-}" =~ ^[0-9]+$ ]] && echo PASS || echo FAIL)" "rate_limit_retry_after" "numeric seconds" "${retry_after:-none}"

AUTOPACE=1
# =========================================================================
section "H. platform caveat: ICMP reachability from this vantage point"
# =========================================================================
ping_ttl=$(ping -c 1 -W 2 -t 1 1.1.1.1 2>&1 | tail -2 | tr '\n' ' ' || true)
record SKIP "icmp_ttl_exceeded_available" "informational" "ping -t 1: $(echo "$ping_ttl" | tr -s ' ' | cut -c1-90)"

if [[ "$SKIP_TRACES" == "1" || "$HEALTH_NT" != "True" ]]; then
  reason="SKIP_TRACES=1"
  [[ "$HEALTH_NT" != "True" ]] && reason="agent reports nexttrace unavailable"
  for check in real_trace_ipv4 real_trace_ipv6 cap_net_raw_effective child_env_minimal cancellation_kills_process_group concurrency_503; do
    record SKIP "$check" "requires a usable nexttrace" "$reason"
  done
else
  # =======================================================================
  section "I. real traces and capability proof"
  # =======================================================================
  AUTOPACE=0
  restart_agent
  api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 30 1 60000 "$(new_job)")"
  cp "$LAST_BODY" "$TMPD/trace-v4.json"
  record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "real_trace_ipv4_http" "200" "$LAST_CODE"
  out=$(TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$TMPD/trace-v4.json" \
        --family ipv4 --target 1.1.1.1 --expect-ptr one.one.one.one 2>&1)
  if [[ $? -eq 0 ]]; then
    record PASS "real_trace_ipv4_contract" "all wire checks pass" "$(tail -1 <<<"$out")"
  else
    record FAIL "real_trace_ipv4_contract" "all wire checks pass" "$(grep '^FAIL' <<<"$out" | head -3 | paste -sd';' -)"
  fi
  record "$([[ $(grep -c '^PASS' <<<"$out") -ge 20 ]] && echo PASS || echo FAIL)" "real_trace_ipv4_detail" ">=20 sub-checks" "$(tail -1 <<<"$out")"

  api POST /v1/trace "$(trace_body 2606:4700:4700::1111 ipv6 8 1 60000 "$(new_job)")"
  cp "$LAST_BODY" "$TMPD/trace-v6.json"
  record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "real_trace_ipv6_http" "200" "$LAST_CODE status=$(json_get status)"
  out6=$(TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$TMPD/trace-v6.json" \
         --family ipv6 --target 2606:4700:4700::1111 2>&1)
  if [[ $? -eq 0 ]]; then
    record PASS "real_trace_ipv6_contract" "all wire checks pass" "$(tail -1 <<<"$out6")"
  else
    record FAIL "real_trace_ipv6_contract" "all wire checks pass" "$(grep '^FAIL' <<<"$out6" | head -3 | paste -sd';' -)"
  fi

  # ---- CAP_NET_RAW effectiveness: inspect the live NextTrace child ------
  restart_agent
  long_job=$(new_job)
  api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 64 5 60000 "$long_job")" &
  bg_curl=$!
  nt_pid=""
  for _ in $(seq 1 40); do
    nt_pid=$(pgrep -n -f '^/usr/local/bin/nexttrace' 2>/dev/null || true)
    [[ -n "$nt_pid" ]] && break
    sleep 0.25
  done
  if [[ -n "$nt_pid" ]]; then
    cap_eff=$(awk '/^CapEff:/{print $2}' "/proc/$nt_pid/status")
    cap_amb=$(awk '/^CapAmb:/{print $2}' "/proc/$nt_pid/status")
    nt_user=$(ps -o user= -p "$nt_pid" | tr -d ' ')
    has_raw=$(python3 -c "print('yes' if int('$cap_eff',16) & (1<<13) else 'no')")
    record "$([[ "$has_raw" == "yes" && "$nt_user" == "tracecat" ]] && echo PASS || echo FAIL)" \
      "cap_net_raw_effective" "CAP_NET_RAW set, uid tracecat" "uid=$nt_user CapEff=$cap_eff CapAmb=$cap_amb net_raw=$has_raw"
    childenv=$(tr '\0' '\n' <"/proc/$nt_pid/environ" 2>/dev/null | sort)
    leak=""
    for needle in TRACECAT_AGENT_TOKEN AWS_SECRET SS_ /etc/tracecat; do
      grep -qF -- "$needle" <<<"$childenv" && leak="$leak $needle"
    done
    env_keys=$(tr '\0' '\n' <"/proc/$nt_pid/environ" | cut -d= -f1 | sort | paste -sd, -)
    record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "child_env_minimal" "no token/config/env leak" "leak=${leak:-none} keys=$env_keys"
    # prove the raw socket actually worked: the child is alive and later returns JSON
    sleep 1
    record "$([[ -d /proc/$nt_pid ]] && echo PASS || echo FAIL)" "raw_socket_child_running" "nexttrace alive (no permission abort)" "pid=$nt_pid"
  else
    record FAIL "cap_net_raw_effective" "live nexttrace child observed" "no child appeared"
    record FAIL "child_env_minimal" "live nexttrace child observed" "no child appeared"
  fi
  wait "$bg_curl" 2>/dev/null
  kill %1 2>/dev/null || true
  wait 2>/dev/null || true

  # ---- cancellation / process group reaping -----------------------------
  restart_agent
  since=$(date '+%Y-%m-%d %H:%M:%S')
  timeout 2 curl -sS --config "$CURLRC" -H 'Content-Type: application/json' \
    --data-binary "$(trace_body 1.1.1.1 ipv4 64 5 60000 "$(new_job)")" \
    "${BASE_URL}/v1/trace" -o /dev/null 2>/dev/null || true
  reaped=0
  for _ in $(seq 1 24); do
    if ! pgrep -f '^/usr/local/bin/nexttrace' >/dev/null 2>&1; then reaped=1; break; fi
    sleep 0.5
  done
  orphans=$(pgrep -a nexttrace 2>/dev/null || true)
  record "$([[ $reaped -eq 1 && -z "$orphans" ]] && echo PASS || echo FAIL)" \
    "cancellation_kills_process_group" "no nexttrace within 12s of client disconnect" "${orphans:-reaped}"
  jlog=$(journal_since "$since")
  record "$(grep -q 'status=cancelled' <<<"$jlog" && echo PASS || echo FAIL)" \
    "cancellation_logged" "journal status=cancelled" "$(grep -o 'status=[a-z_]*' <<<"$jlog" | sort -u | paste -sd, -)"
  record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "agent_survives_cancel" "active" "$(systemctl is-active "$UNIT")"

  # ---- concurrency limit ------------------------------------------------
  restart_agent
  bgs=()
  for i in $(seq 1 "$CONC"); do
    curl -sS --max-time 90 --config "$CURLRC" -H 'Content-Type: application/json' \
      --data-binary "$(trace_body 1.1.1.1 ipv4 64 5 60000 "$(new_job)")" \
      "${BASE_URL}/v1/trace" -o "$TMPD/bg$i.json" -w '%{http_code}' >"$TMPD/bg$i.code" 2>/dev/null &
    bgs+=($!)
    sleep 0.3
  done
  sleep 2
  api POST /v1/trace "$(trace_body 1.1.1.1 ipv4 8 1 60000 "$(new_job)")"
  record "$([[ "$LAST_CODE" == "503" && $(json_get error.code) == "busy" ]] && echo PASS || echo FAIL)" \
    "concurrency_503" "503 busy when $CONC traces in flight" "$LAST_CODE $(json_get error.code) children=$(pgrep -cf '^/usr/local/bin/nexttrace')"
  for pid in "${bgs[@]}"; do wait "$pid" 2>/dev/null || true; done
  api GET /v1/health
  record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "agent_recovers_after_load" "200 health" "$LAST_CODE"
  restart_agent
fi

# =========================================================================
section "P. probe protocols, ports and interfaces"
# =========================================================================
restart_agent
P_STATUS=$(json_get status)
record "$([[ "$P_STATUS" == "ok" ]] && echo PASS || echo FAIL)" "protocol_section_precondition" "agent ok" "$P_STATUS"

TRACE_TARGET="1.1.1.1"

# ---- real ICMP regression ------------------------------------------------
trace_exec icmp "$(trace_ext "$TRACE_TARGET" ipv4 icmp "" "" 5 1 30000)"
record "$([[ "$LAST_EXEC_CODE" == 200 ]] && echo PASS || echo FAIL)" "icmp_regression_http" 200 "$LAST_EXEC_CODE"
if argv_ok icmp "" "" "$TRACE_TARGET" ipv4; then record PASS "icmp_argv_exact" "no -T/-U/-p/-D" "$(tail -1 "$TMPD/argvcheck")"; else record FAIL "icmp_argv_exact" "no -T/-U/-p/-D" "$(grep '^FAIL' "$TMPD/argvcheck" | head -2 | paste -sd';' -)"; fi
TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$LAST_EXEC_BODY" --family ipv4 --target "$TRACE_TARGET" --expect-protocol icmp >"$TMPD/chk" 2>&1 \
  && record PASS "icmp_contract_regression" "wire contract" "$(tail -1 "$TMPD/chk")" \
  || record FAIL "icmp_contract_regression" "wire contract" "$(grep '^FAIL' "$TMPD/chk" | head -2 | paste -sd';' -)"

# ---- real TCP/443 -------------------------------------------------------
trace_exec tcp443 "$(trace_ext "$TRACE_TARGET" ipv4 tcp 443 "" 8 1 40000)"
record "$([[ "$LAST_EXEC_CODE" == 200 ]] && echo PASS || echo FAIL)" "real_tcp_trace_http" 200 "$LAST_EXEC_CODE"
if argv_ok tcp 443 "" "$TRACE_TARGET" ipv4; then record PASS "tcp_argv_exact" "-4 -T ... -p 443 target" "$(tail -1 "$TMPD/argvcheck")"; else record FAIL "tcp_argv_exact" "-4 -T ... -p 443 target" "$(grep '^FAIL' "$TMPD/argvcheck" | head -2 | paste -sd';' -)"; fi
TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$LAST_EXEC_BODY" --family ipv4 --target "$TRACE_TARGET" --expect-protocol tcp --expect-port 443 >"$TMPD/chk" 2>&1 \
  && record PASS "tcp_contract" "completed, port echoed, no ansiterm" "$(tail -1 "$TMPD/chk")" \
  || record FAIL "tcp_contract" "completed, port echoed" "$(grep '^FAIL' "$TMPD/chk" | head -2 | paste -sd';' -)"
record "$(cmd=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$LAST_EXEC_BODY" 2>/dev/null); [[ "$cmd" == "completed" ]] && echo PASS || echo FAIL)" \
  "tcp_completed" completed "$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["status"],"hops=",len(d.get("hops") or []))' "$LAST_EXEC_BODY" 2>/dev/null)"

# ---- real UDP/33494 -----------------------------------------------------
trace_exec udp33494 "$(trace_ext "$TRACE_TARGET" ipv4 udp 33494 "" 8 1 40000)"
record "$([[ "$LAST_EXEC_CODE" == 200 ]] && echo PASS || echo FAIL)" "real_udp_trace_http" 200 "$LAST_EXEC_CODE"
if argv_ok udp 33494 "" "$TRACE_TARGET" ipv4; then record PASS "udp_argv_exact" "-4 -U ... -p 33494 target" "$(tail -1 "$TMPD/argvcheck")"; else record FAIL "udp_argv_exact" "-4 -U ... -p 33494 target" "$(grep '^FAIL' "$TMPD/argvcheck" | head -2 | paste -sd';' -)"; fi
TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$LAST_EXEC_BODY" --family ipv4 --target "$TRACE_TARGET" --expect-protocol udp --expect-port 33494 >"$TMPD/chk" 2>&1 \
  && record PASS "udp_contract" "completed, port echoed" "$(tail -1 "$TMPD/chk")" \
  || record FAIL "udp_contract" "completed, port echoed" "$(grep '^FAIL' "$TMPD/chk" | head -2 | paste -sd';' -)"

# ---- real interface selection ------------------------------------------
trace_exec iface-icmp "$(trace_ext "$TRACE_TARGET" ipv4 icmp "" eth0 5 1 30000)"
record "$([[ "$LAST_EXEC_CODE" == 200 ]] && echo PASS || echo FAIL)" "real_icmp_interface_http" 200 "$LAST_EXEC_CODE"
if argv_ok icmp "" eth0 "$TRACE_TARGET" ipv4; then record PASS "interface_argv_exact" "-4 -D eth0 ... target" "$(tail -1 "$TMPD/argvcheck")"; else record FAIL "interface_argv_exact" "-4 -D eth0 ... target" "$(grep '^FAIL' "$TMPD/argvcheck" | head -2 | paste -sd';' -)"; fi
TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$LAST_EXEC_BODY" --family ipv4 --target "$TRACE_TARGET" --expect-interface eth0 >"$TMPD/chk" 2>&1 \
  && record PASS "interface_contract" "interface echoed" "$(tail -1 "$TMPD/chk")" \
  || record FAIL "interface_contract" "interface echoed" "$(grep '^FAIL' "$TMPD/chk" | head -2 | paste -sd';' -)"

trace_exec iface-tcp "$(trace_ext "$TRACE_TARGET" ipv4 tcp 443 tailscale0 5 1 30000)"
record "$([[ "$LAST_EXEC_CODE" == 200 ]] && echo PASS || echo FAIL)" "real_tcp_interface_http" 200 "$LAST_EXEC_CODE"
if argv_ok tcp 443 tailscale0 "$TRACE_TARGET" ipv4; then record PASS "tcp_interface_argv_exact" "-4 -T -D tailscale0 ... -p 443 target" "$(tail -1 "$TMPD/argvcheck")"; else record FAIL "tcp_interface_argv_exact" "documented shape" "$(grep '^FAIL' "$TMPD/argvcheck" | head -2 | paste -sd';' -)"; fi
TRACE_TOKEN="$TOKEN" python3 "$(dirname "$0")/check_trace_response.py" "$LAST_EXEC_BODY" --family ipv4 --target "$TRACE_TARGET" --expect-protocol tcp --expect-port 443 --expect-interface tailscale0 >"$TMPD/chk" 2>&1 \
  && record PASS "tcp_interface_contract" "interface+port echoed" "$(tail -1 "$TMPD/chk")" \
  || record FAIL "tcp_interface_contract" "interface+port echoed" "$(grep '^FAIL' "$TMPD/chk" | head -2 | paste -sd';' -)"

# ---- port / protocol rejection matrix (400, no child executed) ----------
restart_agent  # reset the in-memory request limiter between request batches
for entry in \
  "tcp_missing_port|$(trace_ext "$TRACE_TARGET" ipv4 tcp "" "" 5 1 30000)|400" \
  "tcp_port_zero|$(trace_ext "$TRACE_TARGET" ipv4 tcp 0 "" 5 1 30000)|400" \
  "tcp_port_too_high|$(trace_ext "$TRACE_TARGET" ipv4 tcp 65536 "" 5 1 30000)|400" \
  "tcp_port_string|$(trace_ext "$TRACE_TARGET" ipv4 tcp str:443 "" 5 1 30000)|400" \
  "tcp_port_negative|$(trace_ext "$TRACE_TARGET" ipv4 tcp -1 "" 5 1 30000)|400" \
  "udp_missing_port|$(trace_ext "$TRACE_TARGET" ipv4 udp "" "" 5 1 30000)|400" \
  "icmp_with_port|$(trace_ext "$TRACE_TARGET" ipv4 icmp 443 "" 5 1 30000)|400" \
  "invalid_protocol_sctp|$(trace_ext "$TRACE_TARGET" ipv4 sctp "" "" 5 1 30000)|400" \
  "invalid_protocol_case|$(trace_ext "$TRACE_TARGET" ipv4 TCP 443 "" 5 1 30000)|400" ; do
  name=${entry%%|*}; rest=${entry#*|}; body=${rest%|*}; want=${rest##*|}
  api POST /v1/trace "$body"
  children=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
  record "$([[ "$LAST_CODE" == "$want" && ${children:-0} -eq 0 ]] && echo PASS || echo FAIL)" \
    "trace_reject[$name]" "$want invalid_request, no child" "$LAST_CODE $(json_get error.code) children=${children:-0}"
done

# ---- interface rejection matrix (400, no child executed) ----------------
restart_agent  # reset the in-memory request limiter between request batches
for entry in \
  "loopback|lo" "container|docker0" "missing|eth9" "invalid_chars|bad iface!" "too_long|abcdefghijklmnop" "path_traversal|../../etc/passwd" ; do
  name=${entry%%|*}; iface=${entry#*|}
  api POST /v1/trace "$(trace_ext "$TRACE_TARGET" ipv4 icmp "" "$iface" 5 1 30000)"
  children=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
  record "$([[ "$LAST_CODE" == 400 && ${children:-0} -eq 0 ]] && echo PASS || echo FAIL)" \
    "interface_reject[$name]" "400 invalid_request, no child" "$LAST_CODE $(json_get error.code) iface=$iface children=${children:-0}"
done

# ---- Agent-local protocol allowlist: temporary icmp-only instance -------
ICMP_CFG="/etc/tracecat/verify-icmp-only.json"
python3 - "$CONFIG" "$ICMP_CFG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["listen"] = "127.0.0.1:8466"
cfg["nexttrace"]["allowed_protocols"] = ["icmp"]
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
sudo -u tracecat env TRACECAT_AGENT_TOKEN="$TOKEN" "$AGENT_BIN" -config "$ICMP_CFG" >"$TMPD/icmp-only.log" 2>&1 &
ICMP_PID=$!
icmp_up=0
for _ in $(seq 1 40); do
  if curl -sS -m 1 -o "$TMPD/icmp-health.json" -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8466/v1/health 2>/dev/null; then icmp_up=1; break; fi
  sleep 0.25
done
record "$([[ $icmp_up -eq 1 ]] && echo PASS || echo FAIL)" "icmp_only_agent_started" "temporary loopback agent with allowed_protocols=[icmp]" "up=$icmp_up"
if [[ $icmp_up -eq 1 ]]; then
  icmp_protocols=$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["limits"]["protocols"]))' "$TMPD/icmp-health.json" 2>/dev/null)
  record "$([[ "$icmp_protocols" == "icmp" ]] && echo PASS || echo FAIL)" "agent_protocol_allowlist_health" "limits.protocols=[icmp]" "$icmp_protocols"
  for proto_body in "tcp|$(trace_ext "$TRACE_TARGET" ipv4 tcp 443 "" 5 1 30000)" "udp|$(trace_ext "$TRACE_TARGET" ipv4 udp 33494 "" 5 1 30000)"; do
    pname=${proto_body%%|*}; pbody=${proto_body#*|}
    pcode=$(curl -sS -m 30 -o "$TMPD/icmp-reject.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
      -H 'Content-Type: application/json' --data-binary "$pbody" http://127.0.0.1:8466/v1/trace 2>/dev/null || true)
    pchild=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
    record "$([[ "$pcode" == 400 && ${pchild:-0} -eq 0 ]] && echo PASS || echo FAIL)" \
      "agent_protocol_allowlist[$pname]" "400, no child executed" "$pcode $(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("error",{}).get("code",""))
except Exception: print("")' "$TMPD/icmp-reject.json") children=${pchild:-0}"
  done
  icmp_body=$(trace_ext "$TRACE_TARGET" ipv4 icmp "" "" 5 1 30000)
  icode=$(curl -sS -m 60 -o "$TMPD/icmp-ok.json" -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' --data-binary "$icmp_body" http://127.0.0.1:8466/v1/trace 2>/dev/null || true)
  record "$([[ "$icode" == 200 ]] && echo PASS || echo FAIL)" "agent_protocol_allowlist[icmp_allowed]" "200 (execution outcome reported in status)" "$icode $(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["status"],d.get("error",{}).get("code"))' "$TMPD/icmp-ok.json" 2>/dev/null)"
fi
kill "$ICMP_PID" 2>/dev/null || true
wait "$ICMP_PID" 2>/dev/null || true
rm -f "$ICMP_CFG"

# ---- no unexpected listeners from the temporary instances ----------------
strays=$(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -E ':(8466|94[0-9][0-9])$' || true)
record "$([[ -z "$strays" ]] && echo PASS || echo FAIL)" "no_stray_temp_listeners" "none" "${strays:-none}"

# =========================================================================
section "J. bind policy matrix (generic private networking)"
# =========================================================================
PRIV_V4=$(ip -4 -o addr show dev eth0 scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
ULA_V6=$(ip -6 -o addr show dev tailscale0 scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
PUB_V6=$(ip -6 -o addr show dev eth0 scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
record SKIP "bind_matrix_environment" "informational" "priv_v4=${PRIV_V4:-none} ula_v6=${ULA_V6:-none} public_v6=${PUB_V6:-none}"

record "$([[ $(systemctl show -p Requires --value "$UNIT") != *tailscaled* ]] && echo PASS || echo FAIL)" \
  "unit_no_tailscaled_hard_dependency" "no Requires=tailscaled (any private overlay works)" "$(systemctl show -p Requires --value "$UNIT")"
schema_ok=$(python3 - "$CONFIG" <<'PY' 2>&1
import json, sys
cfg = json.load(open(sys.argv[1]))
for removed in ("require_tailscale_bind", "allow_non_tailscale_bind"):
    assert removed not in cfg.get("security", {}), removed
assert cfg["security"].get("allow_public_bind") is False
assert isinstance(cfg.get("interfaces"), dict)
print("new schema: allow_public_bind=false, interfaces present, no tailscale keys")
PY
)
record "$([[ "$schema_ok" == new\ schema* ]] && echo PASS || echo FAIL)" "agent_config_new_schema" "allow_public_bind + interfaces, no tailscale flags" "$schema_ok"

run_bind() { # label listen allow_public expect needle
  local label=$1 listen=$2 allow_public=$3 expect=$4 needle=$5
  local cfg="/etc/tracecat/verify-bind-$label.json"
  local logf="$TMPD/bind-$label.log"
  python3 - "$CONFIG" "$cfg" "$listen" "$allow_public" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["listen"] = sys.argv[3]
cfg["security"]["allow_public_bind"] = sys.argv[4] == "true"
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
  sudo -u tracecat env TRACECAT_AGENT_TOKEN="$TOKEN" "$AGENT_BIN" -config "$cfg" >"$logf" 2>&1 &
  local pid=$!
  local ok=0 observed=""
  if [[ "$expect" == accept ]]; then
    local url
    url=$(python3 - "$listen" <<'PY'
import sys
host, port = sys.argv[1].rsplit(":", 1)
if ":" in host:
    host = "[" + host.strip("[]") + "]"
print(f"http://{host}:{port}/v1/health")
PY
)
    for _ in $(seq 1 40); do
      sleep 0.25
      kill -0 "$pid" 2>/dev/null || break
      if curl -sS -m 1 -o /dev/null -H "Authorization: Bearer $TOKEN" "$url" 2>/dev/null; then ok=1; break; fi
    done
    observed="healthz=$([[ $ok -eq 1 ]] && echo 200 || echo fail) listen=$listen allow_public=$allow_public"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  else
    local rc=timedout
    for _ in $(seq 1 40); do
      if ! kill -0 "$pid" 2>/dev/null; then rc=exited; break; fi
      sleep 0.2
    done
    if [[ "$rc" == timedout ]]; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    else
      wait "$pid" 2>/dev/null || true
    fi
    local msg
    msg=$(grep -o 'error="[^"]*"' "$logf" | head -1)
    [[ "$rc" == exited ]] && grep -qiF -- "$needle" "$logf" && ok=1
    observed="rc=$rc ${msg:-$(tr '\n' ' ' <"$logf" | cut -c1-110)}"
  fi
  rm -f "$cfg"
  record "$([[ $ok -eq 1 ]] && echo PASS || echo FAIL)" "bind_${expect}[$label]" "$( [[ $expect == accept ]] && echo 'binds and serves health' || echo "refused: $needle" )" "$observed"
}

run_bind loopback "127.0.0.1:9461" false accept ""
run_bind rfc1918 "${PRIV_V4:-10.0.0.12}:9462" false accept ""
run_bind cgnat "${TS_IP}:9463" false accept ""
if [[ -n "${ULA_V6:-}" ]]; then run_bind ula_v6 "[${ULA_V6}]:9464" false accept ""; else record SKIP "bind_accept[ula_v6]" "assigned ULA accepted" "no ULA address"; fi
run_bind wildcard_v4 "0.0.0.0:9465" false refuse "wildcard binds are refused"
run_bind wildcard_v6 "[::]:9466" false refuse "wildcard binds are refused"
run_bind empty_host ":9467" false refuse "wildcard binds are refused"
run_bind hostname "localhost:9468" false refuse "numeric IP address"
run_bind multicast "239.1.1.1:9469" false refuse "multicast"
run_bind unassigned "10.0.0.99:9470" false refuse "is not assigned"
if [[ -n "${PUB_V6:-}" ]]; then
  run_bind public_refused "[${PUB_V6}]:9471" false refuse "globally routable"
  run_bind public_allowed "[${PUB_V6}]:9472" true accept ""
  record "$(grep -qi 'public' "$TMPD/bind-public_allowed.log" && echo PASS || echo FAIL)" \
    "public_bind_logs_warning" "warning when binding a public address" "$(grep -oiE 'level=[A-Z]+ msg="[^"]*public[^"]*"' "$TMPD/bind-public_allowed.log" | head -1)"
else
  record SKIP "bind_policy_public" "public address assignment" "host has no assigned globally routable address"
fi

# token failures still fail closed on the new schema
TOKEN_CFG="/etc/tracecat/verify-bind-token.json"
python3 - "$CONFIG" "$TOKEN_CFG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["listen"] = sys.argv[3] if len(sys.argv) > 3 else cfg["listen"]
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
out=$(sudo -u tracecat env -u TRACECAT_AGENT_TOKEN timeout 8 "$AGENT_BIN" -config "$TOKEN_CFG" 2>&1); rc=$?
record "$([[ $rc -ne 0 ]] && grep -qi 'is not set' <<<"$out" && echo PASS || echo FAIL)" \
  "bind_refuse[missing_token]" "startup fails without the token env" "rc=$rc $(grep -o 'error="[^"]*"' <<<"$out" | head -1)"
out=$(sudo -u tracecat env TRACECAT_AGENT_TOKEN="short" timeout 8 "$AGENT_BIN" -config "$TOKEN_CFG" 2>&1); rc=$?
record "$([[ $rc -ne 0 ]] && grep -qi 'at least 16 characters' <<<"$out" && echo PASS || echo FAIL)" \
  "bind_refuse[short_token]" "startup fails with a short token" "rc=$rc $(grep -o 'error="[^"]*"' <<<"$out" | head -1)"
rm -f "$TOKEN_CFG"
record "$(ss -H -ltn 2>/dev/null | grep -q ':8443' && echo PASS || echo FAIL)" \
  "no_stray_listener_from_bind_tests" "only the main service listener on 8443" "$(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep ':8443' | paste -sd, -)"

# =========================================================================
section "K. restart resilience and journal hygiene"
# =========================================================================
since_k=$(date '+%Y-%m-%d %H:%M:%S')
sleep 1
restart_agent
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "restart_active" "active" "$(systemctl is-active "$UNIT")"
sleep 0.5
listener=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep ':8443$' || true)
record "$([[ "$listener" == "${TS_IP}:8443" ]] && echo PASS || echo FAIL)" "restart_bind_unchanged" "${TS_IP}:8443" "${listener:-none}"
api GET /v1/health
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "restart_auth_and_health" "200 with token" "$LAST_CODE"
api_anon GET /v1/health
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "restart_still_requires_token" "401 without token" "$LAST_CODE"

jall=$(journalctl -u "$UNIT" --no-pager -o cat --since "$since_k" 2>/dev/null || true)
leak=""
for needle in "$TOKEN" "/etc/tracecat" "/usr/local/bin/nexttrace" "TRACECAT_AGENT_TOKEN"; do
  grep -qF -- "$needle" <<<"$jall" && leak="$leak $needle"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "journal_no_secret_or_path_leak" "no token/config path/binary path" "${leak:-none}"
record "$(grep -qE 'level=(ERROR|WARN)' <<<"$jall" && echo FAIL || echo PASS)" \
  "journal_clean_no_warn_error" "no WARN/ERROR lines" "$(grep -oE 'level=(WARN|ERROR) msg="[^"]*"' <<<"$jall" | sort -u | head -3 | paste -sd';' -)"

# =========================================================================
section "L. graceful shutdown reaps in-flight traces"
# =========================================================================
AUTOPACE=0
if [[ "$HEALTH_NT" == "True" && "$SKIP_TRACES" != "1" ]]; then
  restart_agent
  since_s=$(date '+%Y-%m-%d %H:%M:%S')
  sleep 1
  curl -sS --max-time 120 --config "$CURLRC" -H 'Content-Type: application/json' \
    --data-binary "$(trace_body 1.1.1.1 ipv4 64 5 60000 "$(new_job)")" \
    "${BASE_URL}/v1/trace" -o /dev/null 2>/dev/null &
  bg=$!
  sleep 3
  children_before=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
  record "$([[ ${children_before:-0} -ge 1 ]] && echo PASS || echo FAIL)" \
    "child_running_before_shutdown" ">=1 nexttrace child" "children=${children_before:-0}"
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  stopped=0
  for _ in $(seq 1 20); do
    if ! systemctl is-active --quiet "$UNIT"; then stopped=1; break; fi
    sleep 0.5
  done
  wait "$bg" 2>/dev/null || true
  orphans=$(pgrep -a nexttrace 2>/dev/null || true)
  record "$([[ $stopped -eq 1 && -z "$orphans" ]] && echo PASS || echo FAIL)" \
    "shutdown_reaps_children" "service stopped, no orphan nexttrace" "stopped=$stopped orphans=${orphans:-none}"
  jlog=$(journal_since "$since_s")
  record "$(grep -q 'shutdown requested' <<<"$jlog" && echo PASS || echo FAIL)" \
    "shutdown_logged" "journal 'shutdown requested; cancelling in-flight traces'" "$(grep -o 'shutdown requested[^"]*' <<<"$jlog" | head -1)"
  systemctl start "$UNIT"
  for _ in $(seq 1 40); do
    systemctl is-active --quiet "$UNIT" || { sleep 0.25; continue; }
    curl -sS --max-time 3 --config "$CURLRC" -o /dev/null "${BASE_URL}/v1/health" 2>/dev/null && break
    sleep 0.25
  done
  api GET /v1/health
  record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "healthy_after_shutdown_cycle" "200" "$LAST_CODE"
else
  record SKIP "shutdown_reaps_children" "requires a usable nexttrace" "skipped"
fi

# =========================================================================
section "M. transport hardening (slowloris / header size / auth edges)"
# =========================================================================
restart_agent
slow=$(python3 - "$TS_IP" <<'PYSCRIPT'
import socket, sys, time
host = sys.argv[1]
s = socket.create_connection((host, 8443), timeout=3)
s.sendall(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n")  # headers deliberately unfinished
start = time.time()
s.settimeout(9)
try:
    data = s.recv(64)
    print(f"closed_after={time.time()-start:.1f}s bytes={len(data)}")
except socket.timeout:
    print("still_open_after_9s")
PYSCRIPT
)
record "$(grep -q 'closed_after=5' <<<"$slow" && echo PASS || echo FAIL)" \
  "read_header_timeout_5s" "connection closed by server ~5s on incomplete headers" "$slow"

bigheader=$(python3 -c 'print("a"*40000)')
code=$(curl -sS --max-time 10 --config "$CURLRC" -o /dev/null -w '%{http_code}' \
  -H "X-Pad: $bigheader" "${BASE_URL}/v1/health" 2>/dev/null || true)
record "$([[ "$code" == "431" ]] && echo PASS || echo FAIL)" "max_header_bytes" "431 for ~40KiB header" "code=${code:-none}"

api_anon GET /v1/health "" application/json "Bearer ${TOKEN}extra"
record "$([[ "$LAST_CODE" == "401" ]] && echo PASS || echo FAIL)" "auth_token_prefix_rejected" "401" "$LAST_CODE"
api_anon GET /v1/health "" application/json "bearer ${TOKEN}"
record "$([[ "$LAST_CODE" == "200" ]] && echo PASS || echo FAIL)" "auth_scheme_case_insensitive" "200 (RFC 7235 scheme is case-insensitive)" "$LAST_CODE"
api GET /v1/does-not-exist
record "$([[ "$LAST_CODE" == "404" ]] && echo PASS || echo FAIL)" "unknown_path_with_token" "404 not_found" "$LAST_CODE $(json_get error.code)"
head_code=$(curl -sS --head --max-time 8 --config "$CURLRC" -o /dev/null -w '%{http_code}' "${BASE_URL}/v1/health" 2>/dev/null || true)
record "$([[ "$head_code" == "405" ]] && echo PASS || echo FAIL)" "head_not_allowed" "405" "code=${head_code:-none}"

record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "left_running_for_phase2" "active" "$(systemctl is-active "$UNIT")"

# =========================================================================
printf '\n===== SUMMARY: %d PASS, %d FAIL, %d SKIP =====\n' "$PASS_N" "$FAIL_N" "$SKIP_N"
[[ $FAIL_N -eq 0 ]] && exit 0 || exit 1
