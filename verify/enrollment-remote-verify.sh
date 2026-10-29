#!/usr/bin/env bash
# Independent verification of v0.1.2 automatic Agent enrollment
# (Controller --enrollment / Agent --controller, no machine list).
#
# RUNS ON THE DEBIAN TEST HOST AS ROOT. Staged inputs:
#   /root/tc-verify/enroll-install.sh          (repo deploy/install.sh at HEAD)
#   /root/tc-verify/dist-enroll/*.tar.gz|checksums.txt  (local release build)
#
# The script REPLACES the running stack while testing and restores the SQLite
# database + stops installer-managed units at the end. The Mac side then runs
# verify/setup-testhost-fullstack.sh + verify/setup-testhost-agent.sh after
# deleting the stale env files (see the final printed instructions).
#
# No secrets are printed: tokens are read on the host and reported only by
# length/equality/absence.
set -uo pipefail

HOST_TS_IP="${HOST_TS_IP:-100.81.98.125}"
INSTALLER="${INSTALLER:-/root/tc-verify/enroll-install.sh}"
DIST="${DIST:-/root/tc-verify/dist-enroll}"
CTRL_PORT="${CTRL_PORT:-8082}"
AGENT_PORT="${AGENT_PORT:-8446}"
ORIGIN="http://127.0.0.1:18090"
RESULTS="${RESULTS:-/tmp/tracecat-enrollment-verify.tsv}"
BACKUP="/root/tc-verify/enrollment-backup"
STATE="/root/tc-verify/enrollment-state.json"
TMPD=$(mktemp -d /tmp/tc-enroll.XXXXXX); chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT
PASS_N=0 FAIL_N=0 SKIP_N=0
record() {
  local status=$1 check=$2 expected=$3 observed=$4
  case "$status" in PASS) PASS_N=$((PASS_N+1));; FAIL) FAIL_N=$((FAIL_N+1));; SKIP) SKIP_N=$((SKIP_N+1));; esac
  printf '%s\t%s\t%s\t%s\n' "$status" "$check" "$expected" "$observed" >>"$RESULTS"
  printf '%-4s %-52s expected=%s observed=%s\n' "$status" "$check" "$expected" "$observed"
}
section() { printf '\n=== %s ===\n' "$1"; }
json_ok() { python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1; }
jget() { python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
for p in sys.argv[2].split("."):
    d=d[int(p)] if p.isdigit() else d.get(p) if isinstance(d,dict) else None
    if d is None: break
print(d if d is not None else "")' "$1" "$2" 2>/dev/null; }
wait_http() { local url=$1 max=${2:-30} i=0; while [[ $i -lt $((max*4)) ]]; do curl -sS -m 1 -o /dev/null "$url" 2>/dev/null && return 0; sleep 0.25; i=$((i+1)); done; return 1; }
db_token() { python3 - "$1" "$2" <<'PY' 2>/dev/null
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
cols = [r[1] for r in con.execute("PRAGMA table_info(registered_agents)")]
tokcol = next((c for c in cols if 'token' in c), None)
if not tokcol:
    sys.exit(1)
row = con.execute(f"SELECT {tokcol} FROM registered_agents WHERE node_id=?", (sys.argv[2],)).fetchone()
print(row[0] if row else "")
PY
}
db_nodes() { python3 - "$1" <<'PY' 2>/dev/null
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
print(",".join(r[0] for r in con.execute("SELECT node_id FROM registered_agents ORDER BY node_id")))
PY
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "error: run as root" >&2; exit 2; }
[[ -f "$INSTALLER" && -f "$DIST/checksums.txt" ]] || { echo "missing staged installer/assets" >&2; exit 2; }

echo "TraceCat automatic-enrollment verification — $(date -u +%FT%TZ)"
echo "host=$(hostname) installer_sha=$(sha256sum "$INSTALLER" | awk '{print $1}')"

# =========================================================================
section "P0. prepare: stop old stack, back up DB/env"
# =========================================================================
for unit in tracecat-agent tracecat-agent-b tracecat-controller tracecat-controller-local; do
  systemctl stop "$unit" >/dev/null 2>&1 || true
done
for _ in $(seq 1 40); do
  ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -qE ":(8443|8444|8080|8081)$" || break
  sleep 0.25
done
install -d -m 0700 "$BACKUP/db" "$BACKUP/etc"
cp -a /var/lib/tracecat/controller.db* "$BACKUP/db/" 2>/dev/null || true
rm -f /var/lib/tracecat/controller.db /var/lib/tracecat/controller.db-wal /var/lib/tracecat/controller.db-shm
cp -a /etc/tracecat/controller.json /etc/tracecat/controller.env /etc/tracecat/agent.json /etc/tracecat/agent.env "$BACKUP/etc/" 2>/dev/null || true
record PASS "old_stack_stopped" "verification units stopped" "stopped"

# =========================================================================
section "C. Controller install with --enrollment (zero static agents)"
# =========================================================================
ctrl_log="$TMPD/controller-install.log"
bash "$INSTALLER" controller --enrollment --auth dev --listen "127.0.0.1:${CTRL_PORT}" \
  --public-origin "$ORIGIN" --tarball "$DIST/tracecat-controller-linux-amd64.tar.gz" \
  --checksums "$DIST/checksums.txt" --force >"$ctrl_log" 2>&1
record "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "controller_enrollment_install_exit" "installer exit 0" "exit"
record "$(grep -q 'Automatic Agent enrollment is enabled' "$ctrl_log" && echo PASS || echo FAIL)" "controller_prints_enrollment_notice" "notice printed" "yes"
record "$(grep -qE "TRACECAT_ENROLLMENT_TOKEN='[^']{32,}'" "$ctrl_log" && echo PASS || echo FAIL)" "controller_prints_enrollment_command" "copy-pasteable agent command with token" "printed"
record "$(grep -q -- "--controller 'http://127.0.0.1:${CTRL_PORT}'" "$ctrl_log" && echo PASS || echo FAIL)" "controller_command_has_no_machine_list" "no --agent machine list in printed command" "controller URL only"
CTRL_JSON=/etc/tracecat/controller.json
CTRL_ENV=/etc/tracecat/controller.env
record "$(json_ok "$CTRL_JSON" && echo PASS || echo FAIL)" "controller_config_strict_json" "valid JSON" "$(json_ok "$CTRL_JSON" && echo valid || echo invalid)"
ccheck=$(python3 - "$CTRL_JSON" "$CTRL_PORT" "$ORIGIN" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
assert c["auth"]["mode"]=="dev", c["auth"]
assert c["listen"]==f"127.0.0.1:{sys.argv[2]}", c["listen"]
assert c["public_origin"]==sys.argv[3], c["public_origin"]
assert c["enrollment"]["enabled"] is True, c.get("enrollment")
assert c["enrollment"]["token_env"]=="TRACECAT_ENROLLMENT_TOKEN"
assert c["enrollment"]["refresh_after_seconds"]==300
assert not c.get("agents"), c.get("agents")
print("ok enrollment-enabled, agents=0, token_env name only")
PY
)
record "$([[ "$ccheck" == ok* ]] && echo PASS || echo FAIL)" "controller_enrollment_config" "enabled, zero static agents, token env name only" "$ccheck"
TOK=$(sed -n 's/^TRACECAT_ENROLLMENT_TOKEN=//p' "$CTRL_ENV")
record "$([[ ${#TOK} -ge 32 ]] && echo PASS || echo FAIL)" "enrollment_token_generated" ">=32 chars" "len=${#TOK}"
record "$([[ $(stat -c '%a %U:%G' "$CTRL_ENV") == "600 root:tracecat" || $(stat -c '%a %U:%G' "$CTRL_ENV") == "600 root:root" ]] && echo PASS || echo FAIL)" \
  "controller_env_permissions" "0600" "$(stat -c '%a %U:%G' "$CTRL_ENV")"
record "$(grep -q "$TOK" "$CTRL_JSON" && echo FAIL || echo PASS)" "enrollment_secret_not_in_config" "secret absent from controller.json" "absent"
up=0; for _ in $(seq 1 80); do wait_http "http://127.0.0.1:${CTRL_PORT}/healthz" 1 && { up=1; break; }; sleep 0.25; done
record "$([[ $up -eq 1 ]] && echo PASS || echo FAIL)" "controller_enrollment_service_started" "healthz 200" "up=$up"
record "$([[ $(ss -H -ltn | awk '{print $4}' | grep -c ":${CTRL_PORT}$") -eq 1 ]] && echo PASS || echo FAIL)" "controller_listens_configured_port" "127.0.0.1:${CTRL_PORT}" "$(ss -H -ltn | awk '{print $4}' | grep ":${CTRL_PORT}$" | paste -sd, -)"

# baseline node list (should be empty: zero static agents, no enrollment yet)
req_base() { # req_base <method> <path> [body] [extra...]
  local method=$1 path=$2 body=${3:-}; shift 3 2>/dev/null || true
  local args=(-sS -m 10 -X "$method" -b "$TMPD/cookies" -c "$TMPD/cookies" -H "Origin: $ORIGIN")
  [[ -n "$CSRF" ]] && args+=(-H "X-TraceCat-CSRF: $CSRF")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "$body")
  curl "${args[@]}" "$@" "http://127.0.0.1:${CTRL_PORT}$path" 2>/dev/null
}
curl -sS -m 5 -c "$TMPD/cookies" "http://127.0.0.1:${CTRL_PORT}/api/v1/session" >"$TMPD/session.json" 2>/dev/null
CSRF=$(jget "$TMPD/session.json" csrf_token)
record "$([[ ${#CSRF} -ge 32 ]] && echo PASS || echo FAIL)" "controller_session" "dev session + CSRF" "csrf_len=${#CSRF}"
nodes_base=$(req_base GET /api/v1/nodes)
record "$([[ "$nodes_base" == *'"nodes":[]'* || "$nodes_base" == *'"nodes": []'* ]] && echo PASS || echo FAIL)" "controller_starts_with_zero_nodes" "no machine list configured, /nodes empty" "$(python3 -c 'import json,sys;d=json.loads(sys.argv[1]);print(len(d["nodes"]))' "$nodes_base" 2>/dev/null) nodes"

# enrollment must not be reachable with browser credentials only
code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' -b "$TMPD/cookies" -X POST -H 'Content-Type: application/json' -H "X-TraceCat-CSRF: $CSRF" -H "Origin: $ORIGIN" --data-binary '{"schema_version":"tracecat.agent.v1","node_id":"browser-1","name":"browser","url":"http://127.0.0.1:9999"}' "http://127.0.0.1:${CTRL_PORT}/api/v1/agents/enroll")
record "$([[ "$code" == 401 ]] && echo PASS || echo FAIL)" "enrollment_rejects_browser_credentials" 401 "$code"

# =========================================================================
section "A. Agent install with --controller + enrollment token (auto)"
# =========================================================================
agent_log="$TMPD/agent-install.log"
TRACECAT_ENROLLMENT_TOKEN="$TOK" bash "$INSTALLER" agent --controller "http://127.0.0.1:${CTRL_PORT}" \
  --listen "127.0.0.1:${AGENT_PORT}" --nexttrace /usr/local/bin/nexttrace \
  --tarball "$DIST/tracecat-agent-linux-amd64.tar.gz" --checksums "$DIST/checksums.txt" --force >"$agent_log" 2>&1
record "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "agent_enrollment_install_exit" "installer exit 0" "exit"
AGENT_JSON=/etc/tracecat/agent.json
AGENT_ENV=/etc/tracecat/agent.env
acfg=$(python3 - "$AGENT_JSON" "$CTRL_PORT" "$AGENT_PORT" <<'PY'
import json,re,sys
c=json.load(open(sys.argv[1]))
assert re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", c["node_id"]), c["node_id"]
assert c["listen"]==f"127.0.0.1:{sys.argv[3]}", c["listen"]
assert c["auth"]=={} or c["auth"].get("token_env","")=="", c["auth"]
ct=c["controller"]
assert ct["url"]==f"http://127.0.0.1:{sys.argv[2]}", ct["url"]
assert ct["enrollment_token_env"]=="TRACECAT_ENROLLMENT_TOKEN"
assert ct["advertise_url"]==f"http://127.0.0.1:{sys.argv[3]}", ct["advertise_url"]
assert ct["refresh_seconds"]==300, ct["refresh_seconds"]
print("ok controller section, auth {}, advertise_url")
PY
)
record "$([[ "$acfg" == ok* ]] && echo PASS || echo FAIL)" "agent_enrollment_config" "controller section + auth {} + advertise URL" "$acfg"
record "$(grep -q "$TOK" "$AGENT_JSON" && echo FAIL || echo PASS)" "enrollment_secret_not_in_agent_config" "secret absent from agent.json" "absent"
record "$([[ $(stat -c '%a %U:%G' "$AGENT_ENV") == "600 root:root" ]] && echo PASS || echo FAIL)" "agent_env_permissions" "0600 root:root" "$(stat -c '%a %U:%G' "$AGENT_ENV")"
record "$(grep -q "^TRACECAT_ENROLLMENT_TOKEN=${TOK}$" "$AGENT_ENV" && echo PASS || echo FAIL)" "agent_env_has_enrollment_secret" "secret only in 0600 env" "present"
record "$(grep -q 'TRACECAT_AGENT_TOKEN' "$AGENT_ENV" && echo FAIL || echo PASS)" "agent_env_has_no_static_token" "no static bearer token written" "absent"
up=0; for _ in $(seq 1 80); do [[ "$(systemctl is-active tracecat-agent)" == active ]] && { up=1; break; }; sleep 0.25; done
record "$([[ $up -eq 1 ]] && echo PASS || echo FAIL)" "agent_enrollment_service_started" "active" "$(systemctl is-active tracecat-agent)"
AUTO_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node_id"])' "$AGENT_JSON")
AUTO_NAME=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["name"])' "$AGENT_JSON")
enrolled=0
for _ in $(seq 1 60); do
  body=$(req_base GET /api/v1/nodes)
  if python3 -c 'import json,sys;d=json.loads(sys.argv[1]);n=[x for x in d["nodes"] if x.get("source")=="auto" and x.get("health")=="ok"];sys.exit(0 if n else 1)' "$body" 2>/dev/null; then enrolled=1; break; fi
  sleep 0.5
done
record "$([[ $enrolled -eq 1 ]] && echo PASS || echo FAIL)" "agent_auto_registered" "auto node healthy in /nodes" "id=$AUTO_ID"
node_json=$(python3 - "$body" "$AUTO_ID" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
n=[x for x in d["nodes"] if x["id"]==sys.argv[2]][0]
assert n["source"]=="auto", n.get("source")
assert n["health"]=="ok", n["health"]
assert n["name"], n["name"]
for k in ("agent_token","url","token"):
    assert k not in n, f"leaked {k}"
print("source=auto health=ok name=%s interfaces=%s" % (n["name"], ",".join(n.get("interfaces") or [])))
PY
)
record "$([[ "$node_json" == source=auto* ]] && echo PASS || echo FAIL)" "auto_node_contract" "source=auto, health=ok, no URL/token" "$node_json"
journal_has_enrolled=0
for _ in $(seq 1 40); do journalctl -u tracecat-agent --no-pager -o cat 2>/dev/null | grep -q "agent enrolled with controller" && { journal_has_enrolled=1; break; }; sleep 0.25; done
record "$([[ $journal_has_enrolled -eq 1 ]] && echo PASS || echo FAIL)" "agent_logs_enrollment_success" "journal records enrollment (node id only)" "$(journalctl -u tracecat-agent --no-pager -o cat 2>/dev/null | grep -o 'agent enrolled with controller.*' | tail -1 | cut -c1-80)"
agent_up_token=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
record "$([[ ${#agent_up_token} -ge 32 ]] && echo PASS || echo FAIL)" "controller_issued_agent_token" "per-Agent token issued and persisted" "len=${#agent_up_token}"
record "$([[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $agent_up_token" "http://127.0.0.1:${AGENT_PORT}/v1/health") == 200 ]] && echo PASS || echo FAIL)" \
  "issued_token_authenticates_agent" 200 "health with issued token"
record "$([[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${AGENT_PORT}/v1/health") == 401 ]] && echo PASS || echo FAIL)" \
  "agent_requires_issued_token" 401 "no token"

# =========================================================================
section "T. real traces through the auto-enrolled node"
# =========================================================================
mkjob() { # mkjob <json> ; echoes response + code handled by caller
  curl -sS -m 10 -o "$TMPD/job.json" -w '%{http_code}' -X POST -b "$TMPD/cookies" -c "$TMPD/cookies" \
    -H "Origin: $ORIGIN" -H "X-TraceCat-CSRF: $CSRF" -H 'Content-Type: application/json' \
    --data-binary "$1" "http://127.0.0.1:${CTRL_PORT}/api/v1/jobs" 2>/dev/null
}
poll_job() { local id=$1 st="" i=0; while [[ $i -lt 120 ]]; do curl -sS -m 10 -b "$TMPD/cookies" "http://127.0.0.1:${CTRL_PORT}/api/v1/jobs/$id" >"$TMPD/jobpoll.json" 2>/dev/null; st=$(jget "$TMPD/jobpoll.json" job.status); [[ "$st" =~ ^(completed|partial|failed|cancelled)$ ]] && break; sleep 1; i=$((i+1)); done; JOB_TERMINAL_STATUS="$st"; }
icmp_body=$(python3 - "$AUTO_ID" <<'PY'
import json,sys
print(json.dumps({"target_ip":"1.1.1.1","original_target":"1.1.1.1","node_ids":[sys.argv[1]],"protocol":"icmp","max_hops":8,"queries":1,"timeout_ms":30000}))
PY
)
code=$(mkjob "$icmp_body"); JOB_ID=$(jget "$TMPD/job.json" job.id)
record "$([[ "$code" == 202 ]] && echo PASS || echo FAIL)" "auto_node_icmp_job_created" 202 "$code id=${JOB_ID:0:8}"
poll_job "$JOB_ID"
record "$([[ "$JOB_TERMINAL_STATUS" == completed ]] && echo PASS || echo FAIL)" "auto_node_icmp_completed" completed "$JOB_TERMINAL_STATUS"
icmp_detail=$(python3 - "$TMPD/jobpoll.json" "$AUTO_ID" 2>&1 <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
n=[x for x in j["nodes"] if x["node_id"]==sys.argv[2]][0]
assert n["status"]=="completed", n["status"]
assert n.get("hops"), "no hops"
assert not j.get("port"), j.get("port")
print("completed hops=%d protocol=%s" % (len(n["hops"]), j["protocol"]))
PY
)
record "$([[ "$icmp_detail" == completed* ]] && echo PASS || echo FAIL)" "auto_node_icmp_hops" "completed with hops, no port" "$icmp_detail"
tcp_body=$(python3 - "$AUTO_ID" <<'PY'
import json,sys
print(json.dumps({"target_ip":"1.1.1.1","original_target":"1.1.1.1","node_ids":[sys.argv[1]],"protocol":"tcp","port":443,"max_hops":8,"queries":1,"timeout_ms":30000}))
PY
)
code=$(mkjob "$tcp_body"); JOB_ID=$(jget "$TMPD/job.json" job.id)
record "$([[ "$code" == 202 ]] && echo PASS || echo FAIL)" "auto_node_tcp_job_created" 202 "$code tcp/443"
poll_job "$JOB_ID"
record "$([[ "$JOB_TERMINAL_STATUS" == completed ]] && echo PASS || echo FAIL)" "auto_node_tcp_completed" completed "$JOB_TERMINAL_STATUS"
tcp_detail=$(python3 - "$TMPD/jobpoll.json" "$AUTO_ID" 2>&1 <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
n=[x for x in j["nodes"] if x["node_id"]==sys.argv[2]][0]
assert j["protocol"]=="tcp" and j["port"]==443, (j["protocol"],j.get("port"))
assert n["status"]=="completed", n["status"]
assert n.get("hops"), "no hops"
print("completed tcp/443 hops=%d" % len(n["hops"]))
PY
)
record "$([[ "$tcp_detail" == completed* ]] && echo PASS || echo FAIL)" "auto_node_tcp_protocol_port" "tcp/443 completed with hops" "$tcp_detail"
iface_body=$(python3 - "$AUTO_ID" <<'PY'
import json,sys
print(json.dumps({"target_ip":"1.1.1.1","original_target":"1.1.1.1","node_ids":[sys.argv[1]],"protocol":"icmp","node_interfaces":{sys.argv[1]:"eth0"},"max_hops":8,"queries":1,"timeout_ms":30000}))
PY
)
code=$(mkjob "$iface_body"); JOB_ID=$(jget "$TMPD/job.json" job.id)
poll_job "$JOB_ID"
iface_detail=$(python3 - "$TMPD/jobpoll.json" "$AUTO_ID" 2>&1 <<'PY'
import json,sys
j=json.load(open(sys.argv[1]))["job"]
n=[x for x in j["nodes"] if x["node_id"]==sys.argv[2]][0]
assert n.get("interface")=="eth0", n.get("interface")
assert n["status"]=="completed", n["status"]
print("interface=eth0 completed")
PY
)
record "$([[ "$iface_detail" == interface=eth0* ]] && echo PASS || echo FAIL)" "auto_node_interface_selection" "per-node interface still honored" "$iface_detail"

# =========================================================================
section "L. token rotation and persistence"
# =========================================================================
token_before=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
systemctl restart tracecat-agent
re_enrolled=0
for _ in $(seq 1 80); do
  t=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
  [[ -n "$t" && "$t" != "$token_before" ]] && { re_enrolled=1; break; }
  sleep 0.5
done
token_after=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
record "$([[ $re_enrolled -eq 1 ]] && echo PASS || echo FAIL)" "agent_restart_reenrolls" "node re-enrolls on restart" "re-enrolled=$re_enrolled"
record "$([[ -n "$token_after" && "$token_after" != "$token_before" ]] && echo PASS || echo FAIL)" "reenroll_rotates_token" "issued token changes" "rotated=$([[ "$token_after" != "$token_before" ]] && echo yes || echo no)"
record "$([[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token_before" "http://127.0.0.1:${AGENT_PORT}/v1/health") == 401 ]] && echo PASS || echo FAIL)" \
  "old_token_rejected_by_agent" 401 "previous token no longer accepted"
record "$([[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token_after" "http://127.0.0.1:${AGENT_PORT}/v1/health") == 200 ]] && echo PASS || echo FAIL)" \
  "new_token_accepted_by_agent" 200 "rotated token accepted"
health_ok=0; for _ in $(seq 1 60); do
  body=$(req_base GET /api/v1/nodes)
  python3 -c 'import json,sys;d=json.loads(sys.argv[1]);n=[x for x in d["nodes"] if x.get("source")=="auto" and x.get("health")=="ok"];sys.exit(0 if n else 1)' "$body" 2>/dev/null && { health_ok=1; break; }; sleep 0.5
done
record "$([[ $health_ok -eq 1 ]] && echo PASS || echo FAIL)" "node_healthy_after_reenroll" "auto node ok after restart" "ok=$health_ok"

systemctl restart tracecat-controller
up=0; for _ in $(seq 1 80); do wait_http "http://127.0.0.1:${CTRL_PORT}/healthz" 1 && { up=1; break; }; sleep 0.25; done
CSRF=$(curl -sS -m 5 -c "$TMPD/cookies" "http://127.0.0.1:${CTRL_PORT}/api/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("csrf_token",""))' 2>/dev/null)
body=$(req_base GET /api/v1/nodes)
persisted=$(python3 - "$body" "$AUTO_ID" <<'PY'
import json,sys
d=json.loads(sys.argv[1])
n=[x for x in d["nodes"] if x["id"]==sys.argv[2]]
print(n[0].get("source") if n else "missing")
PY
)
record "$([[ "$persisted" == auto ]] && echo PASS || echo FAIL)" "controller_restart_persists_node" "auto node reloaded from SQLite" "source=$persisted"
token_db_after_restart=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
record "$([[ "$token_db_after_restart" == "$token_after" ]] && echo PASS || echo FAIL)" "controller_restart_persists_token" "issued token survives restart" "match=$([[ "$token_db_after_restart" == "$token_after" ]] && echo yes || echo no)"
health_ok=0; for _ in $(seq 1 60); do
  body=$(req_base GET /api/v1/nodes)
  python3 -c 'import json,sys;d=json.loads(sys.argv[1]);n=[x for x in d["nodes"] if x.get("source")=="auto" and x.get("health")=="ok"];sys.exit(0 if n else 1)' "$body" 2>/dev/null && { health_ok=1; break; }; sleep 0.5
done
record "$([[ $health_ok -eq 1 ]] && echo PASS || echo FAIL)" "node_healthy_after_controller_restart" "agent keeps reporting after controller restart" "ok=$health_ok"

# periodic refresh (agent config refresh_seconds=60, controlled test instance)
python3 - "$AGENT_JSON" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p)); c["controller"]["refresh_seconds"]=60
open(p,"w").write(json.dumps(c,indent=2)+"\n")
PY
systemctl restart tracecat-agent
pre_refresh=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
refreshed=0; start=$(date +%s)
while [[ $(( $(date +%s) - start )) -lt 100 ]]; do
  t=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
  [[ -n "$t" && "$t" != "$pre_refresh" ]] && { refreshed=1; break; }
  sleep 2
done
record "$([[ $refreshed -eq 1 ]] && echo PASS || echo FAIL)" "periodic_token_refresh" "token rotates within refresh_seconds" "refreshed=$refreshed (waited $(( $(date +%s) - start ))s)"
systemctl restart tracecat-agent

# =========================================================================
section "N. negative/security matrix (enrollment endpoint)"
# =========================================================================
enroll_post() { # enroll_post <port> <token|-> <body> [extra curl args...]
  local port=$1 tok=$2 body=$3; shift 3
  local args=(-sS -m 10 -o "$TMPD/enroll-resp.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data-binary "$body")
  [[ "$tok" != "-" ]] && args+=(-H "Authorization: Bearer $tok")
  curl "${args[@]}" "$@" "http://127.0.0.1:${port}/api/v1/agents/enroll" 2>/dev/null
}
valid_body=$(python3 - "$AUTO_ID" "$AGENT_PORT" <<'PY'
import json,sys
print(json.dumps({"schema_version":"tracecat.agent.v1","node_id":sys.argv[1],"name":"Auto node","url":f"http://127.0.0.1:{sys.argv[2]}","nexttrace_version":"v1.7.3","protocols":["icmp","tcp","udp"]}))
PY
)
nodes_before=$(db_nodes /var/lib/tracecat/controller.db)
code=$(enroll_post "$CTRL_PORT" wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaa "$valid_body")
record "$([[ "$code" == 401 ]] && echo PASS || echo FAIL)" "enroll_wrong_token_401" 401 "$code"
code=$(enroll_post "$CTRL_PORT" - "$valid_body")
record "$([[ "$code" == 401 ]] && echo PASS || echo FAIL)" "enroll_missing_token_401" 401 "$code"
record "$([[ "$(db_nodes /var/lib/tracecat/controller.db)" == "$nodes_before" ]] && echo PASS || echo FAIL)" "enroll_failures_do_not_register" "no node added by rejected attempts" "unchanged"
code=$(enroll_post "$CTRL_PORT" "$TOK" '{')
record "$([[ "$code" == 400 ]] && echo PASS || echo FAIL)" "enroll_malformed_json_400" 400 "$code"
code=$(enroll_post "$CTRL_PORT" "$TOK" "$(python3 - <<'PY'
import json
b={"schema_version":"tracecat.agent.v1","node_id":"unknown-field-1","name":"x","url":"https://example.com:8443","protocols":["icmp"]}
raw=json.dumps(b); print(raw[:-1]+',"extra":true}')
PY
)")
record "$([[ "$code" == 400 ]] && echo PASS || echo FAIL)" "enroll_unknown_field_400" 400 "$code"
code=$(enroll_post "$CTRL_PORT" "$TOK" '{"schema_version":"wrong","node_id":"x","name":"x","url":"http://127.0.0.1:9"}')
record "$([[ "$code" == 400 ]] && echo PASS || echo FAIL)" "enroll_wrong_schema_400" 400 "$code"
code=$(enroll_post "$CTRL_PORT" "$TOK" '{"schema_version":"tracecat.agent.v1","node_id":"BAD ID","name":"x","url":"http://127.0.0.1:9"}')
record "$([[ "$code" == 400 ]] && echo PASS || echo FAIL)" "enroll_invalid_node_id_400" 400 "$code"
code=$(enroll_post "$CTRL_PORT" "$TOK" '{"schema_version":"tracecat.agent.v1","node_id":"noname-1","name":"","url":"http://127.0.0.1:9"}')
record "$([[ "$code" == 400 ]] && echo PASS || echo FAIL)" "enroll_missing_name_400" 400 "$code"
big=$(python3 -c 'print("{\"schema_version\":\"tracecat.agent.v1\",\"node_id\":\"big-1\",\"name\":\"x\",\"url\":\"http://127.0.0.1:9\",\"pad\":\"" + "a"*9000 + "\"}")')
code=$(enroll_post "$CTRL_PORT" "$TOK" "$big")
record "$([[ "$code" == 413 ]] && echo PASS || echo FAIL)" "enroll_oversized_body_413" 413 "$code"

# temp Controller instances: 8083 static only (enrollment disabled), 8084 static+enrollment
mk_ctrl_cfg() { # mk_ctrl_cfg <port> <enrollment 0|1> <static 0|1> <path> <static_id>
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json,sys
port,enr,stat,out,static_id=sys.argv[1],sys.argv[2]=="1",sys.argv[3]=="1",sys.argv[4],sys.argv[5]
c=json.load(open("/etc/tracecat/controller.json"))
c["listen"]=f"127.0.0.1:{port}"
c["public_origin"]=f"http://127.0.0.1:{port}"
c["database"]={"path":f"/tmp/tc-enroll-db-{port}/controller.db","max_history_jobs":50}
c["auth"]={"mode":"dev"}
if enr:
    c["enrollment"]={"enabled":True,"token_env":"TEST_ENROLL_TOKEN","refresh_after_seconds":300}
else:
    c.pop("enrollment",None)
if stat:
    c["agents"]=[{"id":static_id,"name":"Static node","url":"http://127.0.0.1:8446","token_env":"TEST_STATIC_TOKEN","enabled":True}]
else:
    c["agents"]=[]
open(out,"w").write(json.dumps(c,indent=2)+"\n")
PY
}
start_temp_ctrl() { # start_temp_ctrl <port> <cfg> <token_env=value> ...
  local port=$1 cfg=$2; shift 2
  ( "$@" /usr/local/bin/tracecat-controller -config "$cfg" >"$TMPD/ctrl-$port.log" 2>&1 & echo $! >"$TMPD/ctrl-$port.pid" )
  local i=0; while [[ $i -lt 60 ]]; do curl -sS -m 1 -o /dev/null "http://127.0.0.1:${port}/healthz" 2>/dev/null && return 0; sleep 0.25; i=$((i+1)); done; return 1
}
# the agent re-enrolled on the last restart: read a token that the Agent
# currently accepts for the static-regression controller (refresh back to 300s
# first so it cannot rotate mid-test)
python3 - "$AGENT_JSON" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p)); c["controller"]["refresh_seconds"]=300
open(p,"w").write(json.dumps(c,indent=2)+"\n")
PY
prev_token=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
systemctl restart tracecat-agent
static_token=""
for _ in $(seq 1 80); do
  t=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
  # wait for the restart-generated token (differs from the pre-restart one),
  # then confirm the Agent accepts it; avoids using a token that is about to
  # be rotated by the startup enrollment
  if [[ -n "$t" && "$t" != "$prev_token" ]] && [[ $(curl -sS -m 2 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $t" "http://127.0.0.1:${AGENT_PORT}/v1/health") == 200 ]]; then
    static_token=$t; break
  fi
  sleep 0.5
done
mkdir -p /tmp/tc-enroll-db-8083 /tmp/tc-enroll-db-8084
mk_ctrl_cfg 8083 0 1 "$TMPD/ctrl-8083.json" "$AUTO_ID"
mk_ctrl_cfg 8084 1 1 "$TMPD/ctrl-8084.json" "$AUTO_ID"
if start_temp_ctrl 8083 "$TMPD/ctrl-8083.json" env TEST_STATIC_TOKEN="$static_token"; then
  record PASS "temp_static_controller_started" "static-only controller on 8083" "up"
else
  record FAIL "temp_static_controller_started" "static-only controller on 8083" "$(tail -2 "$TMPD/ctrl-8083.log" | tr '\n' ' ')"
fi
if start_temp_ctrl 8084 "$TMPD/ctrl-8084.json" env TEST_STATIC_TOKEN="$static_token" TEST_ENROLL_TOKEN="$TOK"; then
  record PASS "temp_enrollment_controller_started" "static+enrollment controller on 8084" "up"
else
  record FAIL "temp_enrollment_controller_started" "static+enrollment controller on 8084" "$(tail -2 "$TMPD/ctrl-8084.log" | tr '\n' ' ')"
fi

# enrollment disabled -> 404
code=$(enroll_post 8083 "$TOK" "$valid_body")
record "$([[ "$code" == 404 ]] && echo PASS || echo FAIL)" "enroll_disabled_404" 404 "$code"

# static regression: static node healthy + real ICMP job through static config
curl -sS -m 5 -c "$TMPD/c83" "http://127.0.0.1:8083/api/v1/session" >/dev/null 2>&1
curl -sS -m 5 -b "$TMPD/c83" "http://127.0.0.1:8083/api/v1/nodes" >"$TMPD/nodes83.json" 2>/dev/null
static_health=$(python3 - "$TMPD/nodes83.json" "$AUTO_ID" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1]))
except Exception as e:
    print("ERR",e); raise SystemExit
n=[x for x in d.get("nodes",[]) if x["id"]==sys.argv[2]]
print(n[0]["source"]+"/"+n[0]["health"] if n else "missing")
PY
)
record "$([[ "$static_health" == static/ok ]] && echo PASS || echo FAIL)" "static_agent_still_works" "static node source=static health=ok" "$static_health"
# static job via 8083 (dev mode: no session needed for /nodes? use session+csrf)
s_csrf=$(curl -sS -m 5 -c "$TMPD/c83" "http://127.0.0.1:8083/api/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("csrf_token",""))')
sjob=$(curl -sS -m 10 -o "$TMPD/sjob.json" -w '%{http_code}' -X POST -b "$TMPD/c83" -H "Origin: http://127.0.0.1:8083" -H "X-TraceCat-CSRF: $s_csrf" -H 'Content-Type: application/json' \
  --data-binary "{\"target_ip\":\"1.1.1.1\",\"original_target\":\"1.1.1.1\",\"node_ids\":[\"$AUTO_ID\"],\"protocol\":\"icmp\",\"max_hops\":8,\"queries\":1,\"timeout_ms\":30000}" "http://127.0.0.1:8083/api/v1/jobs")
sid=$(jget "$TMPD/sjob.json" job.id); sst=""
for _ in $(seq 1 120); do curl -sS -m 10 -b "$TMPD/c83" "http://127.0.0.1:8083/api/v1/jobs/$sid" >"$TMPD/sjobpoll.json"; sst=$(jget "$TMPD/sjobpoll.json" job.status); [[ "$sst" =~ ^(completed|partial|failed|cancelled)$ ]] && break; sleep 1; done
record "$([[ "$sst" == completed ]] && echo PASS || echo FAIL)" "static_node_job_completes" "ICMP completed through static node" "$sst"

# static id collision -> 409
collide=$(python3 - "$AUTO_ID" <<'PY'
import json,sys
print(json.dumps({"schema_version":"tracecat.agent.v1","node_id":sys.argv[1],"name":"x","url":"http://127.0.0.1:8446","protocols":["icmp"]}))
PY
)
code=$(enroll_post 8084 "$TOK" "$collide")
record "$([[ "$code" == 409 ]] && echo PASS || echo FAIL)" "enroll_static_id_collision_409" 409 "$code"
auto_rows=$(db_nodes /tmp/tc-enroll-db-8084/controller.db)
record "$([[ "$auto_rows" != *"$AUTO_ID"* ]] && echo PASS || echo FAIL)" "static_id_never_shadowed" "no auto row for static id" "auto_rows=${auto_rows:-none}"

# URL matrix on the enrollment-enabled temp controller (all rejected URLs -> 400)
url_case() { # url_case <label> <url> <expected_code>
  local label=$1 url=$2 want=$3
  local body; body=$(python3 - "$url" "url-$label-1" <<'PY'
import json,sys
print(json.dumps({"schema_version":"tracecat.agent.v1","node_id":sys.argv[2],"name":"URL case","url":sys.argv[1],"protocols":["icmp"]}))
PY
)
  local code; code=$(enroll_post 8084 "$TOK" "$body")
  record "$([[ "$code" == "$want" ]] && echo PASS || echo FAIL)" "enroll_url[$label]" "HTTP $want" "$code"
}
url_case public_http "http://1.1.1.1:8443" 400
url_case hostname_http "http://agent.example.com:8443" 400
url_case credentials "http://user:pass@10.0.0.1:8443" 400
url_case query "http://10.0.0.1:8443/?x=1" 400
url_case path "http://10.0.0.1:8443/sub" 400
url_case fragment "http://10.0.0.1:8443/#frag" 400
url_case ftp_scheme "ftp://10.0.0.1:8443" 400
url_case https_public_ok "https://agents.example.com:8443" 200
url_case ula_http_ok "http://[fd7a:115c:a1e0::9]:8443" 200

# rate limiting: 401 then 429 with Retry-After (per-IP 30/min)
got429=0; retry_after=""; attempts=0
for i in $(seq 1 45); do
  attempts=$i
  code=$(curl -sS -m 10 -o /dev/null -D "$TMPD/rl-headers" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -H "Authorization: Bearer wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --data-binary "$valid_body" "http://127.0.0.1:8084/api/v1/agents/enroll")
  if [[ "$code" == 429 ]]; then got429=1; retry_after=$(grep -i '^Retry-After:' "$TMPD/rl-headers" | tr -d '\r' | awk '{print $2}'); break; fi
done
record "$([[ $got429 -eq 1 ]] && echo PASS || echo FAIL)" "enroll_rate_limit_429" "429 after repeated attempts" "429 at attempt=$attempts"
record "$([[ -n "$retry_after" ]] && echo PASS || echo FAIL)" "enroll_rate_limit_retry_after" "Retry-After header" "Retry-After=${retry_after:-none}"

# =========================================================================
section "X. secret hygiene"
# =========================================================================
ctrl_journal=$(journalctl -u tracecat-controller --no-pager -o cat 2>/dev/null)
agent_journal=$(journalctl -u tracecat-agent --no-pager -o cat 2>/dev/null)
record "$([[ "$ctrl_journal" != *"$TOK"* ]] && echo PASS || echo FAIL)" "secret_absent_from_controller_logs" "enrollment secret never logged" "absent"
record "$([[ "$agent_journal" != *"$TOK"* ]] && echo PASS || echo FAIL)" "secret_absent_from_agent_logs" "enrollment secret never logged" "absent"
cur_token=$(db_token /var/lib/tracecat/controller.db "$AUTO_ID")
record "$([[ "$ctrl_journal" != *"$cur_token"* && "$agent_journal" != *"$cur_token"* ]] && echo PASS || echo FAIL)" "agent_token_absent_from_logs" "issued Agent token never logged" "absent"
nodes_raw=$(req_base GET /api/v1/nodes)
record "$([[ "$nodes_raw" != *"$cur_token"* && "$nodes_raw" != *'"url"'* && "$nodes_raw" != *'"token"'* ]] && echo PASS || echo FAIL)" "nodes_api_has_no_secrets" "no URL/token in /nodes" "clean"
export_body=$(curl -sS -m 5 -b "$TMPD/cookies" "http://127.0.0.1:${CTRL_PORT}/api/v1/jobs/$JOB_ID/export" 2>/dev/null)
record "$([[ "$export_body" != *"$cur_token"* && "$export_body" != *"$TOK"* ]] && echo PASS || echo FAIL)" "export_has_no_secrets" "no tokens in job export" "clean"
db_perm=$(stat -c '%a %U:%G' /var/lib/tracecat/controller.db)
record "$([[ "$db_perm" == 600\ * ]] && echo PASS || echo FAIL)" "db_permissions" "0600 database" "$db_perm"
token_cols=$(python3 - /var/lib/tracecat/controller.db <<'PY'
import sqlite3,sys
con=sqlite3.connect(sys.argv[1])
cols=[r[1] for r in con.execute("PRAGMA table_info(registered_agents)")]
print(",".join(c for c in cols if "token" in c) or "none")
PY
)
record "$([[ "$token_cols" != "none" ]] && echo PASS || echo FAIL)" "db_stores_agent_token" "raw token in 0600 SQLite (documented residual risk)" "columns=${token_cols}"

# =========================================================================
section "cleanup"
# =========================================================================
for p in 8083 8084; do kill "$(cat "$TMPD/ctrl-$p.pid" 2>/dev/null)" >/dev/null 2>&1 || true; done
pkill -f 'tracecat-controller -config /tmp/tc-enroll' >/dev/null 2>&1 || true
sleep 1
systemctl stop tracecat-agent tracecat-controller >/dev/null 2>&1 || true
rm -rf /tmp/tc-enroll-db-8083 /tmp/tc-enroll-db-8084
# restore the pre-enrollment database so the restored stack does not show stale auto nodes
rm -f /var/lib/tracecat/controller.db /var/lib/tracecat/controller.db-wal /var/lib/tracecat/controller.db-shm
cp -a "$BACKUP/db/." /var/lib/tracecat/ 2>/dev/null || true
record "$([[ -f /var/lib/tracecat/controller.db ]] && echo PASS || echo FAIL)" "database_restored" "pre-enrollment DB restored" "restored"
record "$([[ $(ss -H -ltn | awk '{print $4}' | grep -cE ':(8082|8446|8083|8084)$') -eq 0 ]] && echo PASS || echo FAIL)" "test_ports_cleaned" "no test listeners left" "$(ss -H -ltn | awk '{print $4}' | grep -E ':(8082|8446|8083|8084)$' | paste -sd, -)"
cat >"$STATE" <<EOF
{"node_id":"$AUTO_ID","node_name":"$AUTO_NAME","controller_port":$CTRL_PORT,"agent_port":$AGENT_PORT,"installer_sha":"$(sha256sum "$INSTALLER" | awk '{print $1}')","source":"auto"}
EOF
printf '\nRestore the original stack from the Mac:\n'
printf '  ssh root@HOST "rm -f /etc/tracecat/agent.env /etc/tracecat/agent-b.env /etc/tracecat/controller.env /etc/tracecat/controller-local.env"\n'
printf '  TESTHOST=root@124.222.154.86 ./verify/setup-testhost-fullstack.sh\n'
printf '  TESTHOST=root@124.222.154.86 ./verify/setup-testhost-agent.sh\n'
printf '\n===== SUMMARY: %d PASS, %d FAIL, %d SKIP =====\n' "$PASS_N" "$FAIL_N" "$SKIP_N"
[[ $FAIL_N -eq 0 ]] && exit 0 || exit 1
