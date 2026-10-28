#!/usr/bin/env bash
# Independent, adversarial verification of the deployed TraceCat Controller
# (dev-auth instance on 127.0.0.1:8080) and of the embedded dashboard assets.
#
# RUNS ON THE TEST HOST AS ROOT (needs journalctl/ss and the local secrets to
# prove they never leak). No secrets are printed or embedded: they are read
# from /etc/tracecat/*.env for leak checks only.
#
# Usage: verify/controller-remote-verify.sh
# Exit: 0 when every check passed.
set -uo pipefail

UNIT="${UNIT:-tracecat-controller}"
BASE="${BASE:-http://127.0.0.1:8080}"
ORIGIN="${ORIGIN:-http://127.0.0.1:18090}"
CONFIG="${CONFIG:-/etc/tracecat/controller.json}"
ENVFILE="${ENVFILE:-/etc/tracecat/controller.env}"
DB="${DB:-/var/lib/tracecat/controller.db}"
RESULTS="${RESULTS:-/tmp/tracecat-controller-verify.tsv}"
AGENT_A="${AGENT_A:-debian-test-1}"
AGENT_B="${AGENT_B:-debian-test-2}"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "error: run as root on the host" >&2; exit 2; }

TMPD=$(mktemp -d /tmp/tc-ctrl-verify.XXXXXX)
chmod 700 "$TMPD"
ALLOW_PID=""
cleanup_harness() { [[ -n "$ALLOW_PID" ]] && kill "$ALLOW_PID" 2>/dev/null || true; rm -rf "$TMPD"; }
trap cleanup_harness EXIT
: >"$RESULTS"

PASS_N=0 FAIL_N=0 SKIP_N=0
record() {
  local status=$1 check=$2 expected=$3 observed=$4
  case "$status" in PASS) PASS_N=$((PASS_N+1));; FAIL) FAIL_N=$((FAIL_N+1));; SKIP) SKIP_N=$((SKIP_N+1));; esac
  printf '%s\t%s\t%s\t%s\n' "$status" "$check" "$expected" "$observed" >>"$RESULTS"
  printf '%-4s %-48s expected=%s observed=%s\n' "$status" "$check" "$expected" "$observed"
}
section() { printf '\n=== %s ===\n' "$1"; }

TOKEN_A=$(sed -n 's/^TRACECAT_AGENT_TOKEN_1=//p' "$ENVFILE")
TOKEN_B=$(sed -n 's/^TRACECAT_AGENT_TOKEN_2=//p' "$ENVFILE")
CSRF=""

BODY="$TMPD/body"; HDR="$TMPD/hdr"
CODE="000"
req() { # req METHOD PATH [BODY] [extra curl args...]
  local method=$1 path=$2 body=${3-}
  if [[ $# -ge 3 ]]; then shift 3; else shift $#; fi
  : >"$BODY"; : >"$HDR"
  local args=(-sS --max-time 120 -o "$BODY" -D "$HDR" -w '%{http_code}' -X "$method")
  if [[ $method != "GET" && $method != "HEAD" ]]; then
    args+=(-H "Content-Type: application/json" -H "Origin: $ORIGIN")
    [[ -n "$CSRF" ]] && args+=(-H "X-TraceCat-CSRF: $CSRF")
  fi
  [[ -n "$body" ]] && args+=(--data-binary "$body")
  CODE=$(curl "${args[@]}" "$@" "${BASE}${path}" 2>"$TMPD/err") || true
  [[ -n "$CODE" ]] || CODE="000"
}
req_anon() { # same but without CSRF/Origin defaults
  local method=$1 path=$2 body=${3-}
  if [[ $# -ge 3 ]]; then shift 3; else shift $#; fi
  : >"$BODY"; : >"$HDR"
  local args=(-sS --max-time 60 -o "$BODY" -D "$HDR" -w '%{http_code}' -X "$method")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  CODE=$(curl "${args[@]}" "$@" "${BASE}${path}" 2>"$TMPD/err") || true
  [[ -n "$CODE" ]] || CODE="000"
}
jget() { # jget <dotted.path> [default]  (reads $BODY)
  python3 - "$BODY" "$1" "${2-}" <<'PY'
import json, sys
try:
    doc = json.load(open(sys.argv[1]))
except Exception:
    print(sys.argv[3] if len(sys.argv) > 3 else ""); raise SystemExit
cur = doc
for part in sys.argv[2].split('.'):
    if not part: continue
    if isinstance(cur, dict): cur = cur.get(part)
    elif isinstance(cur, list):
        try: cur = cur[int(part)]
        except Exception: cur = None
    else: cur = None
print(sys.argv[3] if (cur is None and len(sys.argv) > 3) else cur)
PY
}
hdr_get() { awk -v IGNORECASE=1 -v k="$1" 'BEGIN{FS=": "} tolower($1)==tolower(k){v=$2; sub(/\r$/,"",v); print v}' "$HDR" | tail -1; }
hdr_has() { grep -qiE "^$1:" "$HDR"; }
refresh_csrf() {
  req_anon GET /api/v1/session
  CSRF=$(jget csrf_token)
}
restart_ctrl() {
  systemctl restart "$UNIT"
  for _ in $(seq 1 40); do sleep 0.3; curl -sS -m 2 -o /dev/null "$BASE/healthz" && break; done
  refresh_csrf
}
jsonfile() { python3 -c 'import json,sys;json.dump(json.load(open(sys.argv[1])),open(sys.argv[2],"w"),indent=2)' "$1" "$2" 2>/dev/null; }

echo "TraceCat Controller independent verification — $(date -u +%FT%TZ)"
echo "host=$(hostname) base=$BASE unit=$UNIT agents=$AGENT_A,$AGENT_B"

# =========================================================================
section "A. deployment posture"
# =========================================================================
record "$([[ $(systemctl is-enabled "$UNIT" 2>/dev/null) == enabled ]] && echo PASS || echo FAIL)" \
  "unit_enabled" enabled "$(systemctl is-enabled "$UNIT" 2>/dev/null)"
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "unit_active" active "$(systemctl is-active "$UNIT")"
record "$([[ $(systemctl show -p User --value "$UNIT") == tracecat ]] && echo PASS || echo FAIL)" \
  "runs_as_unprivileged" tracecat "$(systemctl show -p User --value "$UNIT")"
record "$([[ $(systemctl show -p NoNewPrivileges --value "$UNIT") == yes ]] && echo PASS || echo FAIL)" \
  "no_new_privileges" yes "$(systemctl show -p NoNewPrivileges --value "$UNIT")"
record "$([[ $(systemctl show -p ProtectSystem --value "$UNIT") == strict ]] && echo PASS || echo FAIL)" \
  "protect_system" strict "$(systemctl show -p ProtectSystem --value "$UNIT")"
record "$([[ $(systemctl show -p MemoryDenyWriteExecute --value "$UNIT") == yes ]] && echo PASS || echo FAIL)" \
  "memory_deny_write_execute" "yes (Controller never execs nexttrace)" "$(systemctl show -p MemoryDenyWriteExecute --value "$UNIT")"
listener=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep ':8080$' || true)
record "$([[ "$listener" == "127.0.0.1:8080" ]] && echo PASS || echo FAIL)" \
  "loopback_only_listener" "127.0.0.1:8080" "${listener:-none}"
record "$(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE '(^0\.0\.0\.0:8080|\*:8080|\[::\]:8080)' && echo FAIL || echo PASS)" \
  "no_wildcard_listener" "no 0.0.0.0/:: on 8080" "${listener:-none}"
public_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://124.222.154.86:8080/healthz 2>/dev/null || true)
record "$([[ "$public_code" != "200" ]] && echo PASS || echo FAIL)" "not_publicly_reachable" "no HTTP 200" "code=${public_code:-none}"
record "$([[ $(stat -c '%a %U:%G' "$CONFIG") == "640 root:tracecat" ]] && echo PASS || echo FAIL)" \
  "config_permissions" "640 root:tracecat" "$(stat -c '%a %U:%G' "$CONFIG")"
record "$([[ $(stat -c '%a %U:%G' "$ENVFILE") == "600 root:root" ]] && echo PASS || echo FAIL)" \
  "env_file_permissions" "600 root:root" "$(stat -c '%a %U:%G' "$ENVFILE")"
dbmode=$(stat -c '%a %U:%G' "$DB" 2>/dev/null)
record "$([[ "$dbmode" == 600* ]] && echo PASS || echo FAIL)" "database_permissions" "0600 owner tracecat" "${dbmode:-absent}"
proc_user=$(ps -o user= -p "$(systemctl show -p MainPID --value "$UNIT")" 2>/dev/null | tr -d ' ')
record "$([[ "$proc_user" == tracecat ]] && echo PASS || echo FAIL)" "process_user" tracecat "${proc_user:-missing}"

# =========================================================================
section "A2. target allowlist configuration (security.allowed_cidrs)"
# =========================================================================
AGENT_A="$AGENT_A" python3 - "$CONFIG" "$TMPD" <<'PYCFG'
import json, os, sys
base = json.load(open(sys.argv[1]))
out = sys.argv[2]
for name, cidrs, listen in (
    ("allow-bad-default", ["0.0.0.0/0"], "127.0.0.1:8099"),
    ("allow-bad-cidr", ["10.0.0.0/8", "not-a-cidr"], "127.0.0.1:8099"),
    ("allow-lab", ["10.0.0.0/8"], "127.0.0.1:8099"),
):
    cfg = json.loads(json.dumps(base))
    cfg["listen"] = listen
    cfg["public_origin"] = f"http://{listen}"
    cfg["database"] = {"path": os.path.join(out, f"{name}.db"), "max_history_jobs": 20}
    cfg["security"] = {"allowed_cidrs": cidrs}
    json.dump(cfg, open(os.path.join(out, f"{name}.json"), "w"), indent=2)
PYCFG
run_cfg() { # run_cfg <cfg> ; sets CFG_RC/CFG_OUT
  CFG_OUT=$(TRACECAT_AGENT_TOKEN_1="$TOKEN_A" TRACECAT_AGENT_TOKEN_2="$TOKEN_B" \
    timeout 8 /usr/local/bin/tracecat-controller -config "$1" 2>&1)
  CFG_RC=$?
}
run_cfg "$TMPD/allow-bad-default.json"
record "$([[ $CFG_RC -ne 0 ]] && grep -qi 'default route' <<<"$CFG_OUT" && echo PASS || echo FAIL)" \
  "allowlist_rejects_default_route" "startup fails: 0.0.0.0/0 rejected" "rc=$CFG_RC $(grep -o 'configuration error:.*' <<<"$CFG_OUT" | cut -c1-90)"
run_cfg "$TMPD/allow-bad-cidr.json"
record "$([[ $CFG_RC -ne 0 ]] && grep -qi 'invalid' <<<"$CFG_OUT" && echo PASS || echo FAIL)" \
  "allowlist_rejects_invalid_cidr" "startup fails on malformed CIDR" "rc=$CFG_RC $(grep -o 'configuration error:.*' <<<"$CFG_OUT" | cut -c1-90)"

# positive: a temporary instance with 10.0.0.0/8 allowlisted accepts the target
TRACECAT_AGENT_TOKEN_1="$TOKEN_A" TRACECAT_AGENT_TOKEN_2="$TOKEN_B" \
  /usr/local/bin/tracecat-controller -config "$TMPD/allow-lab.json" >"$TMPD/allow-lab.log" 2>&1 &
ALLOW_PID=$!
allow_up=0
for _ in $(seq 1 40); do
  if curl -sS -m 1 -o /dev/null http://127.0.0.1:8099/healthz 2>/dev/null; then allow_up=1; break; fi
  sleep 0.25
done
record "$([[ $allow_up -eq 1 ]] && echo PASS || echo FAIL)" "allowlist_instance_started" "temporary controller with 10.0.0.0/8 allowlist" "up=$allow_up"
if [[ $allow_up -eq 1 ]]; then
  allow_csrf=$(curl -sS -m 5 http://127.0.0.1:8099/api/v1/session | python3 -c 'import json,sys;print(json.load(sys.stdin).get("csrf_token",""))' 2>/dev/null)
  allow_code=$(curl -sS -m 8 -o "$TMPD/allow-resolve.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8099' -H "X-TraceCat-CSRF: $allow_csrf" \
    --data-binary '{"target":"10.0.0.1"}' http://127.0.0.1:8099/api/v1/resolve 2>/dev/null || true)
  allow_kind=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("kind",""))
except Exception: print("")' "$TMPD/allow-resolve.json")
  record "$([[ "$allow_code" == 200 && "$allow_kind" == ip ]] && echo PASS || echo FAIL)" \
    "allowlist_allows_configured_cidr" "10.0.0.1 resolves (200 kind=ip)" "code=$allow_code kind=$allow_kind"
  # default policy of the main instance still rejects the same target
  refresh_csrf
  req POST /api/v1/resolve '{"target":"10.0.0.1"}'
  record "$([[ "$CODE" == 422 ]] && echo PASS || echo FAIL)" "default_policy_still_denies" "main instance 422 target_rejected" "$CODE $(jget error.code)"
fi
kill "$ALLOW_PID" 2>/dev/null || true
wait "$ALLOW_PID" 2>/dev/null || true
ALLOW_PID=""

# =========================================================================
section "B. health and session (dev auth mode)"
# =========================================================================
req_anon GET /healthz
record "$([[ "$CODE" == 200 && $(jget status) == ok ]] && echo PASS || echo FAIL)" "healthz_ok" "200 {status:ok}" "$CODE $(jget status)"
fields=$(python3 - "$BODY" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(",".join(sorted(d.keys())))
PY
)
record "$([[ "$fields" == "schema_version,status" ]] && echo PASS || echo FAIL)" \
  "healthz_minimal" "only status+schema_version" "$fields"

req_anon GET /api/v1/session
record "$([[ "$CODE" == 200 && $(jget authenticated) == True ]] && echo PASS || echo FAIL)" \
  "dev_session_authenticated" "200 authenticated=true" "$CODE $(jget authenticated) mode=$(jget mode)"
CSRF=$(jget csrf_token)
record "$([[ ${#CSRF} -ge 32 ]] && echo PASS || echo FAIL)" "session_csrf_token" ">=32 chars" "len=${#CSRF}"
record "$([[ $(jget limits.max_hops) == 30 && $(jget limits.max_queries) == 3 ]] && echo PASS || echo FAIL)" \
  "session_limits_match_config" "max_hops=30 max_queries=3" "$(jget limits.max_hops)/$(jget limits.max_queries)/$(jget limits.max_execution_ms)"
protocols=$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["limits"]["protocols"]))' "$BODY" 2>/dev/null)
record "$([[ "$protocols" == "icmp,tcp,udp" ]] && echo PASS || echo FAIL)" "session_limits_protocols" "protocols=[icmp tcp udp]" "$protocols"
record "$(grep -qi 'dev authentication bypass' "$BODY" && echo PASS || echo FAIL)" \
  "dev_mode_warning" "warning about dev bypass in session" "$(jget warnings.0)"

req_anon GET /api/v1/session "" -H 'X-Forwarded-For: 203.0.113.9'
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "dev_rejects_xff" "403" "$CODE $(jget error.code)"
req_anon GET /api/v1/session "" -H 'X-Real-IP: 203.0.113.9'
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "dev_rejects_x_real_ip" "403" "$CODE $(jget error.code)"
req_anon GET /api/v1/session "" -H 'X-Forwarded-Host: evil.example'
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "dev_rejects_xfh" "403" "$CODE $(jget error.code)"

req_anon POST /api/v1/auth/login '{"password":"whatever-password"}'
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "login_absent_in_dev" "404" "$CODE $(jget error.code)"
req_anon POST /api/v1/auth/logout
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "logout_absent_in_dev" "404" "$CODE $(jget error.code)"

# fake agent JWT / identity headers must never authenticate (no cloudflare mode)
req_anon GET /api/v1/session "" -H 'Cf-Access-Jwt-Assertion: forged.jwt.token'
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" \
  "identity_headers_ignored" "200 dev (forged JWT ignored in dev mode)" "$CODE mode=$(jget mode)"
req_anon GET /api/v1/session "" -H 'Cf-Access-Authenticated-User-Email: admin@example.com'
record "$([[ "$CODE" == 200 && $(jget user.email) == "dev@localhost" ]] && echo PASS || echo FAIL)" \
  "identity_email_header_not_trusted" "user stays dev@localhost" "$CODE user=$(jget user.email)"

# =========================================================================
section "C. node registry"
# =========================================================================
req GET /api/v1/nodes
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "nodes_ok" 200 "$CODE"
ncount=$(python3 - "$BODY" <<'PY'
import json,sys
print(len(json.load(open(sys.argv[1]))["nodes"]))
PY
)
record "$([[ "$ncount" == 2 ]] && echo PASS || echo FAIL)" "nodes_count" 2 "$ncount"
healths=$(python3 - "$BODY" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(",".join(f'{n["id"]}={n["health"]}/{n["nexttrace_version"]}' for n in d["nodes"]))
PY
)
record "$(grep -q 'debian-test-1=ok/v1.7.3' <<<"$healths" && grep -q 'debian-test-2=ok/v1.7.3' <<<"$healths" && echo PASS || echo FAIL)" \
  "agents_health_ok" "both agents ok with v1.7.3" "$healths"
leak=""
for needle in "$TOKEN_A" "$TOKEN_B" "100.81.98.125" "/etc/tracecat" "TRACECAT_"; do
  grep -qF -- "$needle" "$BODY" && leak="$leak $needle"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "nodes_no_url_or_secret_leak" "no agent URLs/tokens/paths" "${leak:-none}"
ifaces=$(python3 - "$BODY" >"$TMPD/node-ifaces" 2>&1 <<'PY' && echo PASS || echo FAIL
import json, sys
nodes = json.load(open(sys.argv[1]))["nodes"]
assert len(nodes) == 2, nodes
for node in nodes:
    names = node.get("interfaces") or []
    assert names, f"node {node['id']} advertises no interfaces"
    assert names == sorted(names), names
    assert "eth0" in names, names
    assert not any(n == "lo" or n.startswith(("docker", "veth", "br-", "bridge", "virbr")) for n in names), names
print("nodes=" + ",".join(f"{n['id']}:{','.join(n['interfaces'])}" for n in nodes))
PY
)
record "$ifaces" "nodes_expose_interfaces" "each node advertises sorted eligible interfaces incl. eth0" "$(cat "$TMPD/node-ifaces")"

# =========================================================================
section "D. central DNS resolution"
# =========================================================================
req POST /api/v1/resolve '{"target":"1.1.1.1"}'
record "$([[ "$CODE" == 200 && $(jget kind) == ip ]] && echo PASS || echo FAIL)" \
  "resolve_literal" "200 kind=ip" "$CODE kind=$(jget kind) n=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["addresses"]))' "$BODY")"
record "$([[ $(jget requires_selection) == False ]] && echo PASS || echo FAIL)" "literal_preselectable" "requires_selection=false" "$(jget requires_selection)"

req POST /api/v1/resolve '{"target":"example.com"}'
cp "$BODY" "$TMPD/resolve-example.json"
record "$([[ "$CODE" == 200 && $(jget kind) == domain ]] && echo PASS || echo FAIL)" \
  "resolve_domain" "200 kind=domain" "$CODE kind=$(jget kind)"
python3 - "$BODY" >"$TMPD/resolve-summary" <<'PY'
import json,sys
from ipaddress import ip_address
d=json.load(open(sys.argv[1]))
addrs=d["addresses"]
fams=sorted({a["family"] for a in addrs})
for a in addrs:
    assert a["family"] in ("ipv4","ipv6"), a
    assert str(ip_address(a["ip"])) == a["ip"], a
print(f"{len(addrs)} addresses families={','.join(fams)} selection={d['requires_selection']} trunc={d['truncated']} warnings={len(d['warnings'])}")
PY
record "PASS" "domain_addresses_valid" "valid canonical A/AAAA entries" "$(cat "$TMPD/resolve-summary")"
record "$([[ $(jget warnings.0) == *"centrally resolved IP"* ]] && echo PASS || echo FAIL)" \
  "domain_cdn_warning" "GeoDNS warning present" "$(jget warnings.0)"
naddr=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["addresses"]))' "$BODY")
selreq=$(jget requires_selection)
if [[ "$naddr" -gt 1 && "$selreq" == "True" ]] || [[ "$naddr" -eq 1 && "$selreq" == "False" ]]; then
  record PASS "resolution_selection_semantics" "requires_selection == (count>1)" "n=$naddr selection=$selreq"
else
  record FAIL "resolution_selection_semantics" "requires_selection == (count>1)" "n=$naddr selection=$selreq"
fi

req POST /api/v1/resolve '{"target":"www.google.com"}'
python3 - "$BODY" >"$TMPD/google-summary" 2>&1 <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
addrs=d["addresses"]
print(f"{len(addrs)} addresses families={','.join(sorted({a['family'] for a in addrs}))} selection={d['requires_selection']}")
PY
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "resolve_multi_address_domain" "200 with multiple choices" "$CODE $(cat "$TMPD/google-summary")"

for bad in '{"target":"not a domain"}' '{"target":"example.com;id"}' '{"target":"10.0.0.1"}' '{"target":"203.0.113.10"}' '{"target":"http://example.com/"}'; do
  req POST /api/v1/resolve "$bad"
  code_field=$(jget error.code)
  ok=0
  if [[ "$CODE" =~ ^(400|422)$ ]] && [[ "$code_field" == "invalid_request" || "$code_field" == "target_rejected" ]]; then
    ok=1
  fi
  record "$([[ $ok -eq 1 ]] && echo PASS || echo FAIL)" "resolve_reject[$(echo "$bad" | cut -c12-40)]" "400/422" "$CODE $code_field"
done

python3 -c 'import json;print(json.dumps({"target":"a"*2000}))' >"$TMPD/big-resolve.json"
req POST /api/v1/resolve "@$TMPD/big-resolve.json"
record "$([[ "$CODE" == 413 ]] && echo PASS || echo FAIL)" "resolve_body_over_1kib" 413 "$CODE $(jget error.code) size=$(stat -c %s "$TMPD/big-resolve.json")"

# =========================================================================
section "E. multi-node job, SSE, history, export"
# =========================================================================
req POST /api/v1/resolve '{"target":"1.1.1.1"}'
TARGET_IP=$(jget addresses.0.ip)
record "$([[ "$TARGET_IP" == "1.1.1.1" ]] && echo PASS || echo FAIL)" "resolve_ip_for_job" "1.1.1.1" "$TARGET_IP"

JOB_BODY=$(printf '{"target_ip":"%s","original_target":"1.1.1.1","node_ids":["%s","%s"],"protocol":"icmp","max_hops":20,"queries":1,"timeout_ms":60000}' "$TARGET_IP" "$AGENT_A" "$AGENT_B")
req POST /api/v1/jobs "$JOB_BODY"
JOB_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "job_create_multi_node" "202" "$CODE"
record "$( [[ "$JOB_ID" =~ ^[0-9a-f]{32}$ ]] && echo PASS || echo FAIL)" "job_id_shape" "32 hex" "$JOB_ID"
record "$([[ $(jget job.nodes.0.status) == pending || $(jget job.nodes.0.status) == running ]] && echo PASS || echo FAIL)" \
  "job_initial_status" pending/running "$(jget job.status)"

# SSE: connect while the job runs; expect bare job snapshots and a clean close.
SSE_HDR="$TMPD/sse.hdr"; SSE_BODY="$TMPD/sse.txt"
sse_code=$(curl -sS -N --max-time 120 -o "$SSE_BODY" -D "$SSE_HDR" -w '%{http_code}' \
  -H "Origin: $ORIGIN" "$BASE/api/v1/jobs/$JOB_ID/events" 2>"$TMPD/sse.err")
sse_rc=$?
record "$([[ "${sse_code:-000}" == 200 ]] && echo PASS || echo FAIL)" "sse_connect" 200 "${sse_code:-000}"
sse_ct=$(awk -v IGNORECASE=1 'BEGIN{FS=": "} tolower($1)=="content-type"{v=$2; sub(/\r$/,"",v); print v}' "$SSE_HDR" | tail -1)
record "$([[ "$sse_ct" == text/event-stream* ]] && echo PASS || echo FAIL)" \
  "sse_content_type" "text/event-stream" "${sse_ct:-none}"
record "$(grep -q '^event: job' "$SSE_BODY" && echo PASS || echo FAIL)" "sse_event_job" "event: job snapshot(s)" "events=$(grep -c '^event: job' "$SSE_BODY")"
python3 - "$SSE_BODY" "$JOB_ID" >"$TMPD/sse-summary" 2>&1 <<'PY' && sse_ok=0 || sse_ok=$?
import json,sys
lines=open(sys.argv[1]).read().splitlines()
datas=[l[6:] for l in lines if l.startswith("data: ")]
assert datas, "no data lines"
objs=[json.loads(d) for d in datas]
assert all(o["schema_version"]=="tracecat.controller.v1" for o in objs)
assert all(o["id"]==sys.argv[2] for o in objs)
terminal=[o for o in objs if o["status"] in ("completed","partial","failed","cancelled")]
assert terminal, f"last status {objs[-1]['status']}"
print(f"{len(objs)} snapshots, terminal={terminal[-1]['status']}, nodes={len(terminal[-1]['nodes'])}")
PY
record "$([[ ${sse_ok:-1} -eq 0 ]] && echo PASS || echo FAIL)" "sse_snapshots_bare_json" "job snapshots, terminal close" "$(cat "$TMPD/sse-summary")"
record "$([[ $sse_rc -eq 0 && ${sse_code:-000} == 200 ]] && echo PASS || echo FAIL)" \
  "sse_closed_on_terminal" "server closed stream (curl exit 0, not timeout)" "curl_exit=$sse_rc code=${sse_code:-000}"

# Poll the job to terminal independently of the SSE result.
job_status=""; attempts=0
while [[ $attempts -lt 90 ]]; do
  req GET "/api/v1/jobs/$JOB_ID"
  job_status=$(jget job.status)
  [[ "$job_status" =~ ^(completed|partial|failed|cancelled)$ ]] && break
  sleep 1; attempts=$((attempts+1))
done
cp "$BODY" "$TMPD/job.json"
record "$([[ "$job_status" == "completed" ]] && echo PASS || echo FAIL)" "job_completed" completed "$job_status"
icmp_shape=$(python3 - "$TMPD/job.json" 2>&1 <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["job"]
assert j["protocol"] == "icmp", j["protocol"]
assert "port" not in j, "icmp job must not carry a port"
for n in j["nodes"]:
    assert "port" not in n, (n["node_id"], "icmp node must not echo a port")
    assert not n.get("interface"), (n["node_id"], n.get("interface"))
print("icmp job: no port/interface keys, both nodes auto")
PY
)
record "$([[ "$icmp_shape" != *Traceback* ]] && echo PASS || echo FAIL)" "icmp_job_has_no_port_or_interface" "no port/interface keys on icmp" "$icmp_shape"
nodeinfo=$(python3 - "$TMPD/job.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
parts=[]
for n in j["nodes"]:
    parts.append(f'{n["node_id"]}={n["status"]}/hops={len(n.get("hops") or [])}')
print(" ".join(parts))
PY
)
record "$(grep -q 'debian-test-1=completed/hops=' <<<"$nodeinfo" && grep -q 'debian-test-2=completed/hops=' <<<"$nodeinfo" && echo PASS || echo FAIL)" \
  "both_nodes_completed_with_hops" "both completed, hops parsed" "$nodeinfo"
summ_ok=$(python3 - "$TMPD/job.json" 2>&1 <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
for n in j["nodes"]:
    assert n.get("summary",{}).get("probes",0) > 0, n["node_id"]
print(" | ".join(f'{n["node_id"]}: {n["summary"]}' for n in j["nodes"]))
PY
)
record "$([[ "$summ_ok" != *Traceback* ]] && echo PASS || echo FAIL)" "job_node_summaries" "per-node summaries present" "$summ_ok"

ptr_info=$(python3 - "$TMPD/job.json" 2>&1 <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["job"]
records = []
for n in j["nodes"]:
    for hop in n.get("hops") or []:
        for probe in hop.get("probes") or []:
            if probe.get("success") and probe.get("ptr"):
                records.append(f'{n["node_id"]}/{probe["address"]}={probe["ptr"]}')
ok = any("one.one.one.one" in r.lower() for r in records)
print(f"reverse_dns={ok} records={records[:6]}")
assert ok, "1.1.1.1 destination hop has no PTR from NextTrace Hostname"
PY
)
record "$([[ "$ptr_info" != *Traceback* ]] && echo PASS || echo FAIL)" \
  "destination_ptr_reverse_dns" "1.1.1.1 hop shows one.one.one.one" "$ptr_info"

req GET "/api/v1/jobs/$JOB_ID/export"
EXPORT_CODE=$CODE
cp "$BODY" "$TMPD/export.json"
record "$([[ "$EXPORT_CODE" == 200 ]] && echo PASS || echo FAIL)" "export_ok" 200 "$EXPORT_CODE"
record "$(grep -qi '^Content-Disposition: attachment' "$HDR" && echo PASS || echo FAIL)" \
  "export_content_disposition" "attachment filename" "$(hdr_get Content-Disposition)"
python3 - "$TMPD/export.json" >"$TMPD/export-summary" 2>&1 <<'PY' && exp_ok=0 || exp_ok=$?
import json,sys
d=json.load(open(sys.argv[1]))
assert d["schema_version"]=="tracecat.controller.v1", d.get("schema_version")
assert d["job"]["id"], "job"
raw=d["raw_results"]
assert len(raw)==2, raw.keys()
for node,doc in raw.items():
    assert isinstance(doc,dict) and "Hops" in doc, node
    text=json.dumps(doc)
    for bad in ("NextTrace","setcap","普通用户","/usr/local/bin","/etc/tracecat"):
        assert bad not in text, (node,bad)
print(f"raw_results={sorted(raw)} sizes={ {k:len(json.dumps(v)) for k,v in raw.items()} }")
PY
record "$([[ ${exp_ok:-1} -eq 0 ]] && echo PASS || echo FAIL)" "export_structure_bounded_raw" "2 raw results, pure JSON, no banner" "$(cat "$TMPD/export-summary")"
record "$(grep -q '普通用户' "$TMPD/export.json" && echo FAIL || echo PASS)" "export_no_banner_text" "no NextTrace advisory" "none"

req GET '/api/v1/jobs?limit=5'
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "history_list" 200 "$CODE"
record "$(python3 - "$BODY" "$JOB_ID" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
ids=[j["id"] for j in d["jobs"]]
assert sys.argv[2] in ids, ids
assert all("hops" not in j for j in d["jobs"]), "history must omit hops"
print(f"{len(ids)} jobs, hops omitted")
PY
)" "history_contains_job_no_hops" "job present, hops omitted" "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["jobs"]),"jobs")' "$BODY")"

# Persistence across restart (SQLite).
restart_ctrl
req GET "/api/v1/jobs/$JOB_ID"
record "$([[ "$CODE" == 200 && $(jget job.id) == "$JOB_ID" ]] && echo PASS || echo FAIL)" \
  "history_persists_across_restart" "job retrievable after restart" "$CODE id=$(jget job.id)"
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "controller_restart_healthy" active "$(systemctl is-active "$UNIT")"

# =========================================================================
section "E2. TCP/UDP and per-node interface dispatch"
# =========================================================================
capture_children_loop() { # background: sample live nexttrace children argv
  local label=$1 argvf="$TMPD/argv-$label" maxf="$TMPD/maxchildren-$label"
  : >"$argvf"; echo 0 >"$maxf"
  while [[ -f "$TMPD/capture-$label.on" ]]; do
    local pids n prev
    pids=$(pgrep -f '^/usr/local/bin/nexttrace' 2>/dev/null || true)
    n=$(wc -w <<<"$pids"); n=${n:-0}
    prev=$(cat "$maxf" 2>/dev/null || echo 0)
    [[ "$n" -gt "$prev" ]] && echo "$n" >"$maxf"
    local p
    for p in $pids; do
      tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null >>"$argvf" || true
      echo >>"$argvf"
    done
    sleep 0.15
  done
}
start_capture() { local label=$1; touch "$TMPD/capture-$label.on"; capture_children_loop "$label" & CAP_BG=$!; }
stop_capture() { local label=$1; rm -f "$TMPD/capture-$label.on"; wait "$CAP_BG" 2>/dev/null || true; sort -u "$TMPD/argv-$label" | grep . >"$TMPD/argv-$label.uniq" || true; }

poll_job() { # poll_job <id> ; sets JOB_TERMINAL_STATUS / writes $BODY
  local id=$1 st="" i=0
  while [[ $i -lt 120 ]]; do
    req GET "/api/v1/jobs/$id"
    st=$(jget job.status)
    [[ "$st" =~ ^(completed|partial|failed|cancelled)$ ]] && break
    sleep 1; i=$((i+1))
  done
  JOB_TERMINAL_STATUS="$st"
}
job_body_ext() { # target protocol port node_interfaces-json hops queries timeout
  python3 - "$1" "$2" "$3" "$4" "$AGENT_A" "$AGENT_B" "$5" "$6" "$7" <<'PY'
import json, secrets, sys
target, protocol, port, ifaces, a, b, hops, queries, timeout = sys.argv[1:10]
body = {
    "target_ip": target,
    "original_target": target,
    "node_ids": [a, b],
    "protocol": protocol,
    "max_hops": int(hops),
    "queries": int(queries),
    "timeout_ms": int(timeout),
    "job_note": secrets.token_hex(8),
}
if port != "":
    body["port"] = int(port)
sel = json.loads(ifaces)
if sel:
    body["node_interfaces"] = sel
body.pop("job_note", None)
print(json.dumps(body))
PY
}

# ---- TCP/443 across both nodes ------------------------------------------
restart_ctrl
start_capture tcp
req POST /api/v1/jobs "$(job_body_ext 1.1.1.1 tcp 443 '{}' 8 1 40000)"
TCP_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "job_create_tcp" 202 "$CODE $(jget job.protocol)/$(jget job.port)"
poll_job "$TCP_ID"
cp "$BODY" "$TMPD/job-tcp.json"
stop_capture tcp
record "$([[ "$JOB_TERMINAL_STATUS" == completed ]] && echo PASS || echo FAIL)" "tcp_job_completed" completed "$JOB_TERMINAL_STATUS"
record "$([[ $(cat "$TMPD/maxchildren-tcp") -ge 2 ]] && echo PASS || echo FAIL)" "tcp_dispatched_to_both_nodes" ">=2 concurrent nexttrace children" "max_children=$(cat "$TMPD/maxchildren-tcp")"
tcp_echo=$(python3 - "$TMPD/job-tcp.json" 2>&1 <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["job"]
assert j["protocol"] == "tcp" and j["port"] == 443, (j["protocol"], j["port"])
for n in j["nodes"]:
    assert n["status"] == "completed", (n["node_id"], n["status"])
    assert "port" not in n, "node results are job-level port only"
    assert not n.get("interface"), n.get("interface")
print("tcp job: protocol=tcp port=443, both completed, no per-node port/interface")
PY
)
record "$([[ "$tcp_echo" != *Traceback* ]] && echo PASS || echo FAIL)" "tcp_job_echo_and_contract" "protocol=tcp port=443, both completed" "$tcp_echo"
tcp_argv_ok=0
if [[ -s "$TMPD/argv-tcp.uniq" ]]; then
  while IFS= read -r line; do
    if python3 "$(dirname "$0")/check_argv.py" "$line" --protocol tcp --port 443 --target 1.1.1.1 --family ipv4 >"$TMPD/argvcheck-tcp" 2>&1; then tcp_argv_ok=1; fi
  done <"$TMPD/argv-tcp.uniq"
fi
record "$([[ $tcp_argv_ok -eq 1 ]] && echo PASS || echo FAIL)" "tcp_child_argv_exact" "-4 -T ... -p 443 target" "$(tail -1 "$TMPD/argvcheck-tcp" 2>/dev/null): $(head -1 "$TMPD/argv-tcp.uniq" 2>/dev/null | cut -c1-120)"

# ---- UDP/33494 across both nodes ----------------------------------------
start_capture udp
req POST /api/v1/jobs "$(job_body_ext 1.1.1.1 udp 33494 '{}' 8 1 40000)"
UDP_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "job_create_udp" 202 "$CODE $(jget job.protocol)/$(jget job.port)"
poll_job "$UDP_ID"
cp "$BODY" "$TMPD/job-udp.json"
stop_capture udp
record "$([[ "$JOB_TERMINAL_STATUS" == completed ]] && echo PASS || echo FAIL)" "udp_job_completed" completed "$JOB_TERMINAL_STATUS"
udp_argv_ok=0
if [[ -s "$TMPD/argv-udp.uniq" ]]; then
  while IFS= read -r line; do
    if python3 "$(dirname "$0")/check_argv.py" "$line" --protocol udp --port 33494 --target 1.1.1.1 --family ipv4 >"$TMPD/argvcheck-udp" 2>&1; then udp_argv_ok=1; fi
  done <"$TMPD/argv-udp.uniq"
fi
record "$([[ $udp_argv_ok -eq 1 ]] && echo PASS || echo FAIL)" "udp_child_argv_exact" "-4 -U ... -p 33494 target" "$(tail -1 "$TMPD/argvcheck-udp" 2>/dev/null): $(head -1 "$TMPD/argv-udp.uniq" 2>/dev/null | cut -c1-120)"

# ---- per-node interface selection (A=eth0, B=automatic) -----------------
start_capture iface
req POST /api/v1/jobs "$(job_body_ext 1.1.1.1 icmp "" "{\"$AGENT_A\":\"eth0\"}" 5 1 30000)"
IFACE_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "job_create_interface" 202 "$CODE"
poll_job "$IFACE_ID"
cp "$BODY" "$TMPD/job-iface.json"
stop_capture iface
iface_echo=$(python3 - "$TMPD/job-iface.json" "$AGENT_A" "$AGENT_B" 2>&1 <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["job"]
a, b = sys.argv[2], sys.argv[3]
by = {n["node_id"]: n for n in j["nodes"]}
assert by[a]["interface"] == "eth0", by[a].get("interface")
assert not by[b].get("interface"), by[b].get("interface")
assert "interface" not in j, "job level must not carry a single interface"
assert all(n["status"] == "completed" for n in j["nodes"]), [n["status"] for n in j["nodes"]]
print("node A interface=eth0, node B automatic, both completed")
PY
)
record "$([[ "$iface_echo" != *Traceback* ]] && echo PASS || echo FAIL)" "interface_job_echo" "per-node interface echoed, mismatch isolated" "$iface_echo"
iface_flag=0; auto_flag=0
while IFS= read -r line; do
  [[ "$line" == *"-D eth0"* ]] && iface_flag=1
  [[ "$line" != *"-D "* ]] && auto_flag=1
  python3 "$(dirname "$0")/check_argv.py" "$line" --protocol icmp --target 1.1.1.1 --family ipv4 >/dev/null 2>&1 || true
done <"$TMPD/argv-iface.uniq"
record "$([[ $iface_flag -eq 1 && $auto_flag -eq 1 ]] && echo PASS || echo FAIL)" "interface_child_argv_mixed" "one child -D eth0, one child auto (no -D)" "iface_line=$iface_flag auto_line=$auto_flag lines=$(wc -l <"$TMPD/argv-iface.uniq" 2>/dev/null || echo 0)"

# ---- Controller protocol allowlist (independent instance) ---------------
PROTO_CFG="$TMPD/controller-icmp-only.json"
python3 - "$CONFIG" "$PROTO_CFG" "$TMPD/proto.db" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["listen"] = "127.0.0.1:8098"
cfg["public_origin"] = "http://127.0.0.1:8098"
cfg["database"] = {"path": sys.argv[3], "max_history_jobs": 10}
cfg["limits"]["allowed_protocols"] = ["icmp"]
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
TRACECAT_AGENT_TOKEN_1="$TOKEN_A" TRACECAT_AGENT_TOKEN_2="$TOKEN_B" \
  /usr/local/bin/tracecat-controller -config "$PROTO_CFG" >"$TMPD/proto-controller.log" 2>&1 &
PROTO_PID=$!
proto_up=0
for _ in $(seq 1 40); do
  if curl -sS -m 1 -o "$TMPD/proto-session.json" http://127.0.0.1:8098/api/v1/session 2>/dev/null; then proto_up=1; break; fi
  sleep 0.25
done
record "$([[ $proto_up -eq 1 ]] && echo PASS || echo FAIL)" "controller_protocol_allowlist_instance" "temporary controller with allowed_protocols=[icmp]" "up=$proto_up"
if [[ $proto_up -eq 1 ]]; then
  proto_csrf=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["csrf_token"])' "$TMPD/proto-session.json")
  proto_protocols=$(python3 -c 'import json,sys;print(",".join(json.load(open(sys.argv[1]))["limits"]["protocols"]))' "$TMPD/proto-session.json")
  record "$([[ "$proto_protocols" == "icmp" ]] && echo PASS || echo FAIL)" "controller_protocol_allowlist_session" "session limits.protocols=[icmp]" "$proto_protocols"
  pcode=$(curl -sS -m 10 -o "$TMPD/proto-reject.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8098' -H "X-TraceCat-CSRF: $proto_csrf" \
    --data-binary "$(job_body_ext 1.1.1.1 tcp 443 '{}' 5 1 30000)" http://127.0.0.1:8098/api/v1/jobs 2>/dev/null || true)
  pchildren=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
  record "$([[ "$pcode" == 400 && ${pchildren:-0} -eq 0 ]] && echo PASS || echo FAIL)" \
    "controller_protocol_allowlist_rejects_tcp" "400 before dispatch, no child" "$pcode $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("error",{}).get("code",""))' "$TMPD/proto-reject.json") children=${pchildren:-0}"
  pcode=$(curl -sS -m 10 -o "$TMPD/proto-ok.json" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8098' -H "X-TraceCat-CSRF: $proto_csrf" \
    --data-binary "$(job_body_ext 1.1.1.1 icmp "" '{}' 2 1 10000)" http://127.0.0.1:8098/api/v1/jobs 2>/dev/null || true)
  record "$([[ "$pcode" == 202 ]] && echo PASS || echo FAIL)" "controller_protocol_allowlist_allows_icmp" 202 "$pcode"
fi
kill "$PROTO_PID" 2>/dev/null || true
wait "$PROTO_PID" 2>/dev/null || true
rm -f "$PROTO_CFG" "$TMPD"/proto.db*

# ---- Controller-side port/interface rejection matrix --------------------
restart_ctrl
for _ in $(seq 1 60); do pgrep -f '^/usr/local/bin/nexttrace' >/dev/null 2>&1 || break; sleep 0.5; done
port_job() { # port_job <protocol> <port-token> <ifaces-json>
  python3 - "$1" "$2" "$3" "$AGENT_A" "$AGENT_B" <<'PY'
import json, sys
protocol, port, ifaces, a, b = sys.argv[1:6]
body = {"target_ip": "1.1.1.1", "node_ids": [a, b], "protocol": protocol,
        "max_hops": 5, "queries": 1, "timeout_ms": 30000}
if port != "":
    body["port"] = port[4:] if port.startswith("str:") else int(port)
sel = json.loads(ifaces)
if sel:
    body["node_interfaces"] = sel
print(json.dumps(body))
PY
}
for entry in \
  "tcp_missing_port|$(port_job tcp "" '{}')|400" \
  "tcp_port_zero|$(port_job tcp 0 '{}')|400" \
  "tcp_port_too_high|$(port_job tcp 65536 '{}')|400" \
  "tcp_port_string|$(port_job tcp str:443 '{}')|400" \
  "udp_missing_port|$(port_job udp "" '{}')|400" \
  "icmp_with_port|$(port_job icmp 443 '{}')|400" \
  "invalid_protocol|$(port_job sctp "" '{}')|400" \
  "interface_loopback|$(port_job icmp "" "{\"$AGENT_A\":\"lo\"}")|400" \
  "interface_not_advertised|$(port_job icmp "" "{\"$AGENT_A\":\"eth9\"}")|400" \
  "interface_invalid_name|$(port_job icmp "" "{\"$AGENT_A\":\"bad iface!\"}")|400" \
  "interface_unselected_node|$(python3 - "$AGENT_A" "$AGENT_B" <<'PY'
import json, sys
a, b = sys.argv[1], sys.argv[2]
print(json.dumps({"target_ip": "1.1.1.1", "node_ids": [a], "protocol": "icmp",
                  "node_interfaces": {b: "eth0"}, "max_hops": 5, "queries": 1,
                  "timeout_ms": 30000}))
PY
)|400" \
  "interface_unknown_node|$(port_job icmp "" '{"nope-1":"eth0"}')|400" ; do
  name=${entry%%|*}; rest=${entry#*|}; body=${rest%|*}; want=${rest##*|}
  req POST /api/v1/jobs "$body"
  children=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
  record "$([[ "$CODE" == "$want" && ${children:-0} -eq 0 ]] && echo PASS || echo FAIL)" \
    "job_reject[$name]" "$want before dispatch, no child" "$CODE $(jget error.code) children=${children:-0}"
done

# =========================================================================
section "F. cancellation across both Agents"
# =========================================================================
restart_ctrl
req POST /api/v1/jobs "$(printf '{"target_ip":"1.1.1.1","original_target":"1.1.1.1","node_ids":["%s","%s"],"protocol":"icmp","max_hops":30,"queries":3,"timeout_ms":60000}' "$AGENT_A" "$AGENT_B")"
CANCEL_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "cancel_job_created" 202 "$CODE id=$CANCEL_ID"
sleep 3
children_before=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
record "$([[ ${children_before:-0} -ge 1 ]] && echo PASS || echo FAIL)" "agents_running_traces" ">=1 nexttrace child" "children=${children_before:-0}"
req POST "/api/v1/jobs/$CANCEL_ID/cancel"
cancel_status=$(jget job.status)
record "$([[ "$CODE" == 200 && $(jget job.id) == "$CANCEL_ID" ]] && echo PASS || echo FAIL)" \
  "cancel_request_accepted" "200 with job id (cancellation is asynchronous)" "$CODE id=$(jget job.id) status=$cancel_status"
reaped=0
for _ in $(seq 1 30); do
  if ! pgrep -f '^/usr/local/bin/nexttrace' >/dev/null 2>&1; then reaped=1; break; fi
  sleep 0.5
done
orphans=$(pgrep -a nexttrace 2>/dev/null || true)
record "$([[ $reaped -eq 1 && -z "$orphans" ]] && echo PASS || echo FAIL)" \
  "cancel_reaps_agent_children" "no nexttrace child within 15s" "${orphans:-reaped}"
poll_status=""
for _ in $(seq 1 30); do
  req GET "/api/v1/jobs/$CANCEL_ID"
  poll_status=$(jget job.status)
  [[ "$poll_status" == "cancelled" ]] && break
  sleep 1
done
nodes_status=$(python3 - "$BODY" <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
print(",".join(n["node_id"]+":"+n["status"] for n in j["nodes"]))
PY
)
record "$([[ "$poll_status" == "cancelled" ]] && echo PASS || echo FAIL)" "cancel_terminal_state" cancelled "$poll_status nodes=$nodes_status"
record "$([[ "$nodes_status" == *":cancelled"* ]] && echo PASS || echo FAIL)" "cancelled_nodes" "node statuses cancelled" "$nodes_status"
req POST "/api/v1/jobs/$JOB_ID/cancel"
record "$([[ "$CODE" == 409 ]] && echo PASS || echo FAIL)" "cancel_terminal_job_conflict" "409 conflict" "$CODE $(jget error.code)"
req POST "/api/v1/jobs/0123456789abcdef0123456789abcdef/cancel"
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "cancel_unknown_job" "404" "$CODE $(jget error.code)"

# =========================================================================
section "F2. restart reconciliation (no stale running jobs)"
# =========================================================================
since_recon=$(date '+%Y-%m-%d %H:%M:%S')
req POST /api/v1/jobs "$(printf '{"target_ip":"1.1.1.1","original_target":"1.1.1.1","node_ids":["%s","%s"],"protocol":"icmp","max_hops":30,"queries":3,"timeout_ms":60000}' "$AGENT_A" "$AGENT_B")"
RECON_ID=$(jget job.id)
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "recon_job_created" 202 "$CODE"
sleep 2
live_children=$(pgrep -cf '^/usr/local/bin/nexttrace' || true)
record "$([[ ${live_children:-0} -ge 1 ]] && echo PASS || echo FAIL)" "recon_job_running" ">=1 nexttrace child" "children=${live_children:-0}"
old_pid=$(systemctl show -p MainPID --value "$UNIT")
kill -9 "$old_pid" 2>/dev/null || true
killed_ok=0
for _ in $(seq 1 40); do
  new_pid=$(systemctl show -p MainPID --value "$UNIT")
  if [[ -n "$new_pid" && "$new_pid" != "$old_pid" && "$new_pid" != "0" ]] && systemctl is-active --quiet "$UNIT"; then killed_ok=1; break; fi
  sleep 0.5
done
record "$([[ $killed_ok -eq 1 ]] && echo PASS || echo FAIL)" "controller_auto_restarted_after_crash" "systemd Restart=on-failure restarted it" "old=$old_pid new=$new_pid"
for _ in $(seq 1 40); do curl -sS -m 2 -o /dev/null "$BASE/healthz" && break; sleep 0.3; done
refresh_csrf
req GET "/api/v1/jobs/$RECON_ID"
recon_summary=$(python3 - "$BODY" 2>&1 <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["job"]
assert j["status"] == "failed", j["status"]
for n in j["nodes"]:
    assert n["status"] == "failed", (n["node_id"], n["status"])
    assert (n.get("error") or {}).get("code") == "internal", (n["node_id"], n.get("error"))
print("job=failed nodes=" + ",".join(f'{n["node_id"]}:{n["status"]}/{n["error"]["code"]}' for n in j["nodes"]))
PY
)
record "$([[ "$recon_summary" != *Traceback* ]] && echo PASS || echo FAIL)" "interrupted_job_marked_failed" \
  "failed job + failed nodes with internal error" "$recon_summary"
jlog=$(journalctl -u "$UNIT" --no-pager -o cat --since "$since_recon" 2>/dev/null || true)
record "$(grep -q 'marked jobs interrupted by a previous Controller process' <<<"$jlog" && echo PASS || echo FAIL)" \
  "reconciliation_logged" "journal warns about reconciled jobs" "$(grep -o 'marked jobs interrupted[^"]*' <<<"$jlog" | head -1)"
req GET '/api/v1/jobs?limit=50'
stale=$(python3 - "$BODY" 2>&1 <<'PY'
import json, sys
jobs = json.load(open(sys.argv[1]))["jobs"]
stale = [j["id"] for j in jobs if j["status"] in ("pending", "running")]
print(f"stale_running={stale}")
assert not stale
PY
)
record "$([[ "$stale" != *Traceback* ]] && echo PASS || echo FAIL)" "history_has_no_stale_running_jobs" "history clean after restart" "$stale"
# a fresh job still works after the crash/restart cycle
req POST /api/v1/jobs "$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":1,"queries":1,"timeout_ms":5000}' "$AGENT_A")"
record "$([[ "$CODE" == 202 ]] && echo PASS || echo FAIL)" "job_creation_after_reconciliation" 202 "$CODE"

# =========================================================================
section "G. limits, validation and API surface"
# =========================================================================
for entry in \
  "hops31|$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":31,"queries":1,"timeout_ms":60000}' "$AGENT_A")|400" \
  "queries4|$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":10,"queries":4,"timeout_ms":60000}' "$AGENT_A")|400" \
  "timeout_low|$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":4000}' "$AGENT_A")|400" \
  "timeout_high|$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":70000}' "$AGENT_A")|400" \
  "empty_nodes|$(printf '{"target_ip":"1.1.1.1","node_ids":[],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":60000}')|400" \
  "unknown_node|$(printf '{"target_ip":"1.1.1.1","node_ids":["nope-1"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":60000}')|403" \
  "private_target|$(printf '{"target_ip":"10.0.0.1","node_ids":["%s"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":60000}' "$AGENT_A")|422" \
  "bad_protocol|$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"tcp","max_hops":10,"queries":1,"timeout_ms":60000}' "$AGENT_A")|400" ; do
  name=${entry%%|*}; rest=${entry#*|}; body=${rest%|*}; want=${rest##*|}
  name=${name// /_}
  req POST /api/v1/jobs "$body"
  record "$([[ "$CODE" == "$want" ]] && echo PASS || echo FAIL)" "jobs_reject[$name]" "$want" "$CODE $(jget error.code)"
done

req POST /api/v1/jobs '{"target_ip":"1.1.1.1","node_ids":["debian-test-1"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":60000,"bogus":true}'
record "$([[ "$CODE" == 400 ]] && echo PASS || echo FAIL)" "jobs_unknown_field" 400 "$CODE $(jget error.code)"
req POST /api/v1/jobs '{bad json'
record "$([[ "$CODE" == 400 ]] && echo PASS || echo FAIL)" "jobs_malformed_json" 400 "$CODE $(jget error.code)"
python3 -c 'import json;print(json.dumps({"target_ip":"1.1.1.1","original_target":"x"*9000,"node_ids":["debian-test-1"],"protocol":"icmp","max_hops":10,"queries":1,"timeout_ms":60000}))' >"$TMPD/big-job.json"
req POST /api/v1/jobs "@$TMPD/big-job.json"
record "$([[ "$CODE" == 413 ]] && echo PASS || echo FAIL)" "jobs_body_over_8kib" 413 "$CODE $(jget error.code) size=$(stat -c %s "$TMPD/big-job.json")"

req GET /api/v1/jobs/0123456789abcdef0123456789abcdef
record "$([[ "$CODE" == 404 && $(jget error.code) == not_found ]] && echo PASS || echo FAIL)" "unknown_job_get" "404 not_found" "$CODE $(jget error.code)"
req GET /api/v1/nope
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "api_unknown_path_json" "404 JSON" "$CODE $(jget error.code) ct=$(hdr_get Content-Type)"
req GET /api/
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "api_root_json_not_spa" "404 JSON" "$CODE $(jget error.code)"
req DELETE "/api/v1/jobs/$JOB_ID"
record "$([[ "$CODE" == 405 && $(hdr_get Allow) == "GET" ]] && echo PASS || echo FAIL)" "method_not_allowed_json" "405 Allow: GET" "$CODE Allow=$(hdr_get Allow)"
req_anon POST /healthz '{}'
record "$([[ "$CODE" == 405 ]] && echo PASS || echo FAIL)" "healthz_post_method" 405 "$CODE Allow=$(hdr_get Allow)"
req GET /api/v1/jobs?limit=999
record "$([[ "$CODE" == 200 || "$CODE" == 400 ]] && echo PASS || echo FAIL)" "history_limit_validation" "clamped or 400" "$CODE $(jget error.code)"

# =========================================================================
section "H. embedded dashboard and security headers"
# =========================================================================
req_anon GET /
cp "$BODY" "$TMPD/index.html"
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "dashboard_root" 200 "$CODE"
record "$(grep -qi '^Content-Type: text/html' "$HDR" && echo PASS || echo FAIL)" "dashboard_content_type" "text/html" "$(hdr_get Content-Type)"
csp=$(hdr_get Content-Security-Policy)
record "$([[ "$csp" == *"default-src 'self'"* && "$csp" == *"frame-ancestors 'none'"* ]] && echo PASS || echo FAIL)" \
  "csp_present" "default-src 'self' + frame-ancestors 'none'" "${csp:0:120}"
for hname in X-Content-Type-Options X-Frame-Options Referrer-Policy Permissions-Policy Cross-Origin-Opener-Policy; do
  record "$(hdr_has "$hname" && echo PASS || echo FAIL)" "security_header[$hname]" present "$(hdr_get "$hname")"
done
record "$([[ $(hdr_get X-Content-Type-Options) == nosniff ]] && echo PASS || echo FAIL)" "nosniff" nosniff "$(hdr_get X-Content-Type-Options)"
record "$([[ $(hdr_get X-Frame-Options) == DENY ]] && echo PASS || echo FAIL)" "frame_deny" DENY "$(hdr_get X-Frame-Options)"
html_cc=$(hdr_get Cache-Control)
record "$([[ "$html_cc" == *no-store* || "$html_cc" == *no-cache* ]] && echo PASS || echo FAIL)" \
  "html_never_reused_without_validation" "no-store or no-cache" "$html_cc"

asset=$(grep -oE '/assets/[A-Za-z0-9._-]+\.js' "$TMPD/index.html" | head -1)
css=$(grep -oE '/assets/[A-Za-z0-9._-]+\.css' "$TMPD/index.html" | head -1)
record "$([[ -n "$asset" ]] && echo PASS || echo FAIL)" "html_references_committed_assets" "hashed JS asset" "${asset:-none}"
req_anon GET "$asset"
record "$([[ "$CODE" == 200 ]] && grep -qi 'javascript' <<<"$(hdr_get Content-Type)" && echo PASS || echo FAIL)" \
  "js_asset_served" "200 text/javascript" "$CODE $(hdr_get Content-Type)"
record "$(grep -qi 'immutable' <<<"$(hdr_get Cache-Control)" && echo PASS || echo FAIL)" "js_asset_immutable_cache" immutable "$(hdr_get Cache-Control)"
if [[ -n "$css" ]]; then
  req_anon GET "$css"
  record "$([[ "$CODE" == 200 ]] && grep -qi 'text/css' <<<"$(hdr_get Content-Type)" && echo PASS || echo FAIL)" "css_asset_served" "200 text/css" "$CODE $(hdr_get Content-Type)"
fi
req_anon GET /assets/
assets_body=$(head -c 4000 "$BODY" 2>/dev/null || true)
if [[ "$CODE" == "404" ]]; then
  record PASS "no_directory_listing" "404 for /assets/" "$CODE"
elif [[ "$CODE" == "200" ]] && ! grep -qiE 'Index of|Directory listing|<title>Index' <<<"$assets_body" && grep -qi 'text/html' <<<"$(hdr_get Content-Type)"; then
  record PASS "no_directory_listing" "404 or SPA fallback, never a listing" "200 SPA fallback (no listing), ct=$(hdr_get Content-Type)"
else
  record FAIL "no_directory_listing" "404 or SPA fallback, never a listing" "$CODE ct=$(hdr_get Content-Type)"
fi
for traversal in '/assets/../../../../etc/passwd' '/assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd' '/..%2f..%2fetc%2fpasswd'; do
  req_anon GET "$traversal" "" --path-as-is
  if grep -q 'root:x:0:0' "$BODY" 2>/dev/null; then
    record FAIL "path_traversal[$traversal]" "no file disclosure" "leaked /etc/passwd"
  else
    record PASS "path_traversal[$traversal]" "no file disclosure" "$CODE $(hdr_get Content-Type)"
  fi
done
req_anon GET /assets/definitely-missing.js
record "$([[ "$CODE" == 404 ]] && echo PASS || echo FAIL)" "missing_asset_404" 404 "$CODE"
req_anon GET /some-spa-route
record "$([[ "$CODE" == 200 ]] && grep -qi 'text/html' <<<"$(hdr_get Content-Type)" && echo PASS || echo FAIL)" \
  "spa_fallback_extensionless" "200 HTML" "$CODE $(hdr_get Content-Type)"
req_anon GET /favicon.svg
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "favicon_served" 200 "$CODE"

# frontend bundle must not contain credentials or node addresses
req_anon GET "$asset"; cp "$BODY" "$TMPD/app.js"
leak=""
for needle in "$TOKEN_A" "$TOKEN_B" "100.81.98.125" "/etc/tracecat" "TRACECAT_" "pbkdf2-sha256"; do
  grep -qF -- "$needle" "$TMPD/app.js" && leak="$leak $needle"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "bundle_no_secret_or_node_ip" "no tokens/node IPs/paths" "${leak:-none}"

# =========================================================================
section "I. cleanup and journal hygiene"
# =========================================================================
since_clean=$(date '+%Y-%m-%d %H:%M:%S')
sleep 1
restart_ctrl
jlog=$(journalctl -u "$UNIT" --no-pager -o cat --since "$since_clean" 2>/dev/null || true)
leak=""
for needle in "$TOKEN_A" "$TOKEN_B" "/etc/tracecat" "pbkdf2-sha256"; do
  grep -qF -- "$needle" <<<"$jlog" && leak="$leak $needle"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "journal_no_secret_or_path_leak" "no tokens/hashes/paths" "${leak:-none}"
record "$(grep -qE 'level":"(WARN|ERROR)' <<<"$jlog" && echo FAIL || echo PASS)" \
  "journal_clean_no_warn_error" "no WARN/ERROR" "$(grep -oE '"level":"(WARN|ERROR)","msg":"[^"]*"' <<<"$jlog" | sort -u | head -2 | paste -sd';' -)"

printf '\n===== SUMMARY: %d PASS, %d FAIL, %d SKIP =====\n' "$PASS_N" "$FAIL_N" "$SKIP_N"
[[ $FAIL_N -eq 0 ]] && exit 0 || exit 1
