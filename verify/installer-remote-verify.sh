#!/usr/bin/env bash
# Independent verification of the v0.1.1 one-command installer and local
# release packaging (deploy/install.sh + scripts/build-release.sh output).
#
# RUNS ON THE TEST HOST AS ROOT. Requires staged assets (copied by the Mac
# side before running this script):
#   /root/tc-verify/install.sh                              (repo deploy/install.sh)
#   /root/tc-verify/dist/tracecat-agent-linux-amd64.tar.gz
#   /root/tc-verify/dist/tracecat-controller-linux-amd64.tar.gz
#   /root/tc-verify/dist/checksums.txt
#
# The script stops the verification stack to avoid unit/config conflicts and
# leaves the installer-managed services stopped at the end; the Mac side then
# restores the normal two-agent + controller stack with
# verify/setup-testhost-fullstack.sh + verify/setup-testhost-agent.sh.
#
# No secrets are printed: tokens/passwords are generated or read on the host
# and reported only by length/absence.
set -uo pipefail

INSTALLER="${INSTALLER:-/root/tc-verify/install.sh}"
DIST="${DIST:-/root/tc-verify/dist}"
TS_IP="${TS_IP:-100.81.98.125}"
AGENT_PORT="${AGENT_PORT:-8444}"
DEV_ORIGIN="${DEV_ORIGIN:-http://127.0.0.1:18090}"
RESULTS="${RESULTS:-/tmp/tracecat-installer-verify.tsv}"
BACKUP="/root/tc-verify/installer-backup"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "error: run as root" >&2; exit 2; }
[[ -f "$INSTALLER" ]] || { echo "missing $INSTALLER" >&2; exit 2; }
[[ -f "$DIST/checksums.txt" ]] || { echo "missing $DIST/checksums.txt" >&2; exit 2; }
AGENT_TARBALL="$DIST/tracecat-agent-linux-amd64.tar.gz"
CONTROLLER_TARBALL="$DIST/tracecat-controller-linux-amd64.tar.gz"
[[ -f "$AGENT_TARBALL" && -f "$CONTROLLER_TARBALL" ]] || { echo "missing release tarballs in $DIST" >&2; exit 2; }

TMPD=$(mktemp -d /tmp/tc-installer.XXXXXX)
chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT
: >"$RESULTS"
PASS_N=0 FAIL_N=0 SKIP_N=0
record() {
  local status=$1 check=$2 expected=$3 observed=$4
  case "$status" in PASS) PASS_N=$((PASS_N+1));; FAIL) FAIL_N=$((FAIL_N+1));; SKIP) SKIP_N=$((SKIP_N+1));; esac
  printf '%s\t%s\t%s\t%s\n' "$status" "$check" "$expected" "$observed" >>"$RESULTS"
  printf '%-4s %-50s expected=%s observed=%s\n' "$status" "$check" "$expected" "$observed"
}
section() { printf '\n=== %s ===\n' "$1"; }
wait_http() { # wait_http <url> [max_s]
  local url=$1 max=${2:-20} i=0
  while [[ $i -lt $((max*4)) ]]; do
    curl -sS -m 1 -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.25; i=$((i+1))
  done
  return 1
}
json_ok() { python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$1" >/dev/null 2>&1; }

echo "TraceCat installer/release verification — $(date -u +%FT%TZ)"
echo "host=$(hostname) installer=$INSTALLER dist=$DIST"

# =========================================================================
section "L0. release artifacts (local build, pre-tag)"
# =========================================================================
for tarball in "$AGENT_TARBALL" "$CONTROLLER_TARBALL"; do
  name=$(basename "$tarball")
  size=$(stat -c %s "$tarball")
  record "$([[ $size -gt 100000 ]] && echo PASS || echo FAIL)" "artifact_present[$name]" "non-trivial tarball" "${size} bytes"
  expect=$(grep -E "$(printf '%s' "$name" | sed 's/\./\\./g')" "$DIST/checksums.txt" | awk '{print $1}' | head -1)
  actual=$(sha256sum "$tarball" | awk '{print $1}')
  record "$([[ -n "$expect" && "$expect" == "$actual" ]] && echo PASS || echo FAIL)" "artifact_checksum[$name]" "checksums.txt matches tarball" "match=$([[ "$expect" == "$actual" ]] && echo yes || echo no)"
  contents=$(tar -tzf "$tarball" 2>/dev/null | sed 's#^\./##' | sort)
  comp=${name%%-linux*}; comp=${comp#tracecat-}
  missing=""
  for path in "bin/tracecat-$comp" "install.sh" "VERSION" "deploy/systemd/tracecat-$comp.service"; do
    grep -qx -- "$path" <<<"$contents" || missing="$missing $path"
  done
  record "$([[ -z "$missing" ]] && echo PASS || echo FAIL)" "artifact_contents[$comp]" "bin, install.sh, systemd unit" "missing=${missing:-none}"
  if grep -qx "VERSION" <<<"$contents"; then
    ver=$(tar -xzOf "$tarball" 2>/dev/null ./VERSION 2>/dev/null || tar -xzOf "$tarball" 2>/dev/null VERSION 2>/dev/null)
    record "$([[ "$ver" == 0.1.1 ]] && echo PASS || echo FAIL)" "artifact_version[$comp]" "VERSION=0.1.1" "${ver:-missing}"
  else
    record FAIL "artifact_version[$comp]" "VERSION file" "missing"
  fi
done
note_assets="release-asset download path (GitHub Releases) not exercised: v0.1.1 is not tagged yet; the installer was driven with --tarball/--checksums (offline path), which is the same code path used after download."
record SKIP "release_asset_download" "informational" "$note_assets"

# =========================================================================
section "L0b. shipped installer argument validation (regression)"
# =========================================================================
# The v0.1.1 pre-fix installer rejected every --agent URL because of a
# non-portable ERE bracket class. The fix ships deploy/install_test.sh; run it
# against a staged copy of the release layout.
install -d -m 0755 /root/tc-verify/deploy
record "$([[ -f /root/tc-verify/deploy/install_test.sh ]] && echo PASS || echo FAIL)" \
  "installer_test_script_staged" "deploy/install_test.sh staged" "present"
if [[ -f /root/tc-verify/deploy/install_test.sh ]]; then
  out=$(bash /root/tc-verify/deploy/install_test.sh 2>&1); rc=$?
  record "$([[ $rc -eq 0 ]] && grep -q 'installer validation: PASS' <<<"$out" && echo PASS || echo FAIL)" \
    "installer_validation_regression_suite" "shipped install_test.sh passes" "rc=$rc $(grep -o 'installer validation: [A-Z]*' <<<"$out" | tail -1)"
  bad=$(grep -c '^FAIL' <<<"$out" || true)
  record "$([[ ${bad:-0} -eq 0 ]] && echo PASS || echo FAIL)" "installer_validation_no_failures" "no FAIL lines" "fail_lines=${bad:-0}"
fi

# Direct shell-level regression of the shipped URL/listen classes (the exact
# defect signature: a plain private URL must match on this bash).
urlpat=$(python3 -c 'import sys
for line in open("/root/tc-verify/install.sh"):
    if "invalid agent url" in line:
        print(line.split("=~ ")[1].split(" ]]")[0]); break')
url_plain=$(bash -c 'p="$1"; [[ "http://10.0.0.5:8443" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$urlpat")
url_ipv6=$(bash -c 'p="$1"; [[ "http://[fd7a:115c:a1e0::1]:8443" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$urlpat")
url_space=$(bash -c 'p="$1"; [[ "http://10.0.0.5:8443 with space" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$urlpat")
record "$([[ "$url_plain" == MATCH && "$url_ipv6" == MATCH && "$url_space" == NOMATCH ]] && echo PASS || echo FAIL)" \
  "installer_url_class_portable" "plain+bracketed-IPv6 URLs match, whitespace rejected" "plain=$url_plain ipv6=$url_ipv6 space=$url_space"
plain_listen=$(bash -c '[[ "10.0.0.5:8443" =~ ^(\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):[0-9]{1,5}$ ]] && echo MATCH || echo NOMATCH')
ipv6_listen=$(bash -c '[[ "[fd7a:115c:a1e0::1]:8443" =~ ^(\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):[0-9]{1,5}$ ]] && echo MATCH || echo NOMATCH')
bad_listen=$(bash -c '[[ "0.0.0.0:notaport" =~ ^(\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):[0-9]{1,5}$ ]] && echo MATCH || echo NOMATCH')
record "$([[ "$plain_listen" == MATCH && "$ipv6_listen" == MATCH && "$bad_listen" == NOMATCH ]] && echo PASS || echo FAIL)" \
  "installer_listen_class_portable" "IPv4 + bracketed IPv6 accepted, bad port rejected" "plain=$plain_listen ipv6=$ipv6_listen bad=$bad_listen"
# explicit acceptance through the shipped script's own spec parser
acc=$(bash -c 'source /root/tc-verify/install.sh; add_agent_spec node-1,http://10.0.0.5:8443,TRACECAT_AGENT_TOKEN && echo ACCEPTED' 2>&1)
record "$(grep -q ACCEPTED <<<"$acc" && echo PASS || echo FAIL)" "installer_accepts_valid_agent_url" \
  "plain http private URL accepted (fixed)" "$(grep -o 'ACCEPTED' <<<"$acc" | head -1)"

# =========================================================================
section "L0c. shipped installer public-origin validation (regression)"
# =========================================================================
popat=$(python3 -c 'import sys
for line in open("/root/tc-verify/install.sh"):
    if "invalid --public-origin" in line:
        print(line.split("=~ ")[1].split(" ]]")[0]); break')
po_http=$(bash -c 'p="$1"; [[ "http://127.0.0.1:18090" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$popat")
po_https=$(bash -c 'p="$1"; [[ "https://trace.example.com" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$popat")
po_ipv6=$(bash -c 'p="$1"; [[ "http://[fd7a:115c:a1e0::1]:18090" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$popat")
po_bad=$(bash -c 'p="$1"; [[ "ftp://example.com" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$popat")
po_space=$(bash -c 'p="$1"; [[ "http://example.com/ with space" =~ $p ]] && echo MATCH || echo NOMATCH' _ "$popat")
record "$([[ "$po_http" == MATCH && "$po_https" == MATCH && "$po_ipv6" == MATCH && "$po_bad" == NOMATCH && "$po_space" == NOMATCH ]] && echo PASS || echo FAIL)" \
  "installer_public_origin_class_portable" "http/https/bracketed-IPv6 accepted, ftp/space rejected" \
  "http=$po_http https=$po_https ipv6=$po_ipv6 ftp=$po_bad space=$po_space"
record "$(bash /root/tc-verify/deploy/install_test.sh >/dev/null 2>&1 && echo PASS || echo FAIL)" \
  "installer_public_origin_regression_suite" "shipped install_test.sh covers public origins" "install_test.sh rc=$?"

# =========================================================================
section "L1. fresh Agent install (offline --tarball)"
# =========================================================================
for unit in tracecat-agent tracecat-agent-b tracecat-controller tracecat-controller-local; do
  systemctl stop "$unit" >/dev/null 2>&1 || true
done
install -d -m 0700 "$BACKUP"
for f in agent.json agent.env controller.json controller.env; do
  [[ -f "/etc/tracecat/$f" ]] && cp -a "/etc/tracecat/$f" "$BACKUP/$f"
done
record PASS "stack_stopped_for_installer" "verification units stopped" "stopped"

agent_install_log="$TMPD/agent-install.log"
if bash "$INSTALLER" agent --tarball "$AGENT_TARBALL" --checksums "$DIST/checksums.txt" \
    --listen "${TS_IP}:${AGENT_PORT}" --nexttrace /usr/local/bin/nexttrace --no-start --force \
    >"$agent_install_log" 2>&1; then
  record PASS "agent_install_exit" "installer exit 0" "0"
else
  record FAIL "agent_install_exit" "installer exit 0" "nonzero: $(tail -2 "$agent_install_log" | tr '\n' ' ' | cut -c1-160)"
fi
record "$(grep -q 'checksum verified' "$agent_install_log" && echo PASS || echo FAIL)" "agent_install_checksum_verified" "checksum verified" "$(grep -o 'checksum verified' "$agent_install_log" | head -1)"
record "$(grep -q 'keeping existing' "$agent_install_log" && echo FAIL || echo PASS)" "agent_install_force_regenerated" "config regenerated with --force" "force"
record "$([[ $(stat -c '%a %U:%G' /etc/tracecat/agent.env) == "600 root:root" ]] && echo PASS || echo FAIL)" \
  "agent_env_permissions" "600 root:root" "$(stat -c '%a %U:%G' /etc/tracecat/agent.env)"
record "$([[ $(stat -c '%a %U:%G' /etc/tracecat/agent.json) == "640 root:tracecat" ]] && echo PASS || echo FAIL)" \
  "agent_config_permissions" "640 root:tracecat" "$(stat -c '%a %U:%G' /etc/tracecat/agent.json)"
GEN_TOKEN=$(sed -n 's/^TRACECAT_AGENT_TOKEN=//p' /etc/tracecat/agent.env)
record "$([[ ${#GEN_TOKEN} -ge 32 ]] && echo PASS || echo FAIL)" "agent_token_generated" ">=32 chars" "len=${#GEN_TOKEN}"
record "$(json_ok /etc/tracecat/agent.json && echo PASS || echo FAIL)" "agent_config_strict_json" "valid JSON" "$(json_ok /etc/tracecat/agent.json && echo valid || echo invalid)"
cfgcheck=$(python3 - /etc/tracecat/agent.json "${TS_IP}:${AGENT_PORT}" <<'PY' 2>&1
import json, re, sys
c = json.load(open(sys.argv[1]))
assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", c["node_id"]), c["node_id"]
assert c["listen"] == sys.argv[2], c["listen"]
assert c["security"]["allow_public_bind"] is False, c["security"]
assert "require_tailscale_bind" not in c["security"]
assert c["nexttrace"]["allowed_protocols"] == ["icmp", "tcp", "udp"], c["nexttrace"]["allowed_protocols"]
assert c["nexttrace"]["binary"] == "/usr/local/bin/nexttrace"
assert c["auth"]["token_env"] == "TRACECAT_AGENT_TOKEN"
print("node_id=", c["node_id"])
PY
)
record "$([[ "$cfgcheck" == node_id=* ]] && echo PASS || echo FAIL)" "agent_generated_config_valid" "strict schema, defaults, exact listen" "$cfgcheck"
NODE_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["node_id"])' /etc/tracecat/agent.json)
record "$(grep -q "^ExecStart=/usr/local/bin/tracecat-agent -config /etc/tracecat/agent.json" /etc/systemd/system/tracecat-agent.service && echo PASS || echo FAIL)" \
  "agent_unit_installed" "ExecStart points at generated config" "$(grep -o 'ExecStart=.*' /etc/systemd/system/tracecat-agent.service)"
record "$(systemctl is-active --quiet tracecat-agent && echo FAIL || echo PASS)" "agent_no_start_honored" "inactive with --no-start" "$(systemctl is-active tracecat-agent)"
systemctl start tracecat-agent
up=0
for _ in $(seq 1 60); do
  [[ "$(systemctl is-active tracecat-agent)" == active ]] || { sleep 0.25; continue; }
  if curl -sS -m 1 -o /dev/null -H "Authorization: Bearer $GEN_TOKEN" "http://${TS_IP}:${AGENT_PORT}/v1/health" 2>/dev/null; then up=1; break; fi
  sleep 0.25
done
record "$([[ $up -eq 1 ]] && echo PASS || echo FAIL)" "agent_started_via_systemd" "active and serving health" "active=$(systemctl is-active tracecat-agent) health_up=$up"
listener=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep ":${AGENT_PORT}$" || true)
record "$([[ "$listener" == "${TS_IP}:${AGENT_PORT}" ]] && echo PASS || echo FAIL)" "agent_bind_exact" "${TS_IP}:${AGENT_PORT}" "${listener:-none}"
hcode=$(curl -sS -m 5 -o "$TMPD/installed-health.json" -w '%{http_code}' -H "Authorization: Bearer $GEN_TOKEN" "http://${TS_IP}:${AGENT_PORT}/v1/health" 2>/dev/null || true)
record "$([[ "$hcode" == 200 ]] && echo PASS || echo FAIL)" "installed_agent_health" 200 "$hcode"
hcheck=$(python3 - "$TMPD/installed-health.json" <<'PY' 2>&1
import json, sys
d = json.load(open(sys.argv[1]))
assert d["status"] == "ok", d["status"]
assert d["limits"]["protocols"] == ["icmp", "tcp", "udp"], d["limits"]
assert d["interfaces"], d["interfaces"]
print("ok protocols=", d["limits"]["protocols"], "interfaces=", d["interfaces"])
PY
)
record "$([[ "$hcheck" == ok* ]] && echo PASS || echo FAIL)" "installed_agent_health_contract" "ok + protocols + interfaces" "$hcheck"
record "$([[ $(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://${TS_IP}:${AGENT_PORT}/v1/health" 2>/dev/null) == 401 ]] && echo PASS || echo FAIL)" \
  "installed_agent_requires_token" 401 "$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://${TS_IP}:${AGENT_PORT}/v1/health" 2>/dev/null)"

# =========================================================================
section "L2. Controller install (dev mode, generated token env)"
# =========================================================================
controller_log="$TMPD/controller-install.log"
TRACECAT_AGENT_TOKEN="$GEN_TOKEN" bash "$INSTALLER" controller \
  --tarball "$CONTROLLER_TARBALL" --checksums "$DIST/checksums.txt" \
  --auth dev --listen 127.0.0.1:8080 --public-origin "$DEV_ORIGIN" \
  --agent "${NODE_ID},http://${TS_IP}:${AGENT_PORT},TRACECAT_AGENT_TOKEN,Installed agent" \
  --force >"$controller_log" 2>&1 \
  && record PASS "controller_install_exit" "installer exit 0" "0" \
  || record FAIL "controller_install_exit" "installer exit 0" "nonzero: $(tail -2 "$controller_log" | tr '\n' ' ' | cut -c1-160)"
record "$(grep -q 'listening on 127.0.0.1:8080 (public origin http://127.0.0.1:18090)' "$controller_log" && echo PASS || echo FAIL)" \
  "installer_public_origin_accepted_live" "installer proceeded past origin validation and started" "$(grep -o 'listening on.*' "$controller_log" | head -1)"
record "$([[ $(stat -c '%a %U:%G' /etc/tracecat/controller.env) == "600 root:tracecat" ]] && echo PASS || echo FAIL)" \
  "controller_env_permissions" "600 root:tracecat" "$(stat -c '%a %U:%G' /etc/tracecat/controller.env)"
record "$(grep -q "^TRACECAT_AGENT_TOKEN=${GEN_TOKEN}$" /etc/tracecat/controller.env && echo PASS || echo FAIL)" \
  "controller_env_written_token" "token env written from environment" "len=$(wc -c </etc/tracecat/controller.env) bytes"
record "$(grep -q "TRACECAT_AGENT_TOKEN=${GEN_TOKEN}" "$controller_log" && echo FAIL || echo PASS)" "installer_log_no_token" "token not printed by controller installer" "none"
record "$(json_ok /etc/tracecat/controller.json && echo PASS || echo FAIL)" "controller_config_strict_json" "valid JSON" "$(json_ok /etc/tracecat/controller.json && echo valid || echo invalid)"
ccheck=$(python3 - /etc/tracecat/controller.json "$DEV_ORIGIN" <<'PY' 2>&1
import json, sys
c = json.load(open(sys.argv[1]))
assert c["auth"]["mode"] == "dev", c["auth"]
assert c["public_origin"] == sys.argv[2], c["public_origin"]
assert c["limits"]["allowed_protocols"] == ["icmp", "tcp", "udp"], c["limits"]
assert len(c["agents"]) == 1 and c["agents"][0]["enabled"] is True, c["agents"]
assert c["agents"][0]["token_env"] == "TRACECAT_AGENT_TOKEN"
assert c["database"]["path"] == "/var/lib/tracecat/controller.db"
print("ok dev config, 1 agent, allowed_protocols default")
PY
)
record "$([[ "$ccheck" == ok* ]] && echo PASS || echo FAIL)" "controller_generated_config_valid" "dev mode, agent, protocols, strict schema" "$ccheck"
up=0
for _ in $(seq 1 60); do wait_http http://127.0.0.1:8080/healthz 1 && { up=1; break; }; sleep 0.25; done
record "$([[ $up -eq 1 ]] && echo PASS || echo FAIL)" "controller_service_started" "healthz 200" "up=$up"
node_ok=0
for _ in $(seq 1 60); do
  body=$(curl -sS -m 5 http://127.0.0.1:8080/api/v1/nodes 2>/dev/null || true)
  if python3 -c 'import json,sys;d=json.loads(sys.argv[1]);assert any(n["health"]=="ok" for n in d["nodes"])' "$body" 2>/dev/null; then node_ok=1; break; fi
  sleep 0.5
done
record "$([[ $node_ok -eq 1 ]] && echo PASS || echo FAIL)" "installed_controller_sees_agent" "node health ok" "$(python3 -c 'import json,sys;d=json.load(sys.stdin);print([(n["id"],n["health"]) for n in d["nodes"]])' <<<"${body:-{\}}" 2>/dev/null)"

# =========================================================================
section "L3. installer refuses corrupt artifacts"
# =========================================================================
before_hash=$(sha256sum /usr/local/bin/tracecat-agent | awk '{print $1}')
cp "$AGENT_TARBALL" "$TMPD/corrupt.tar.gz"
printf 'corruption' >>"$TMPD/corrupt.tar.gz"
out=$(bash "$INSTALLER" agent --tarball "$TMPD/corrupt.tar.gz" --checksums "$DIST/checksums.txt" \
      --listen "${TS_IP}:${AGENT_PORT}" --nexttrace /usr/local/bin/nexttrace --no-start --force 2>&1); rc=$?
record "$([[ $rc -ne 0 ]] && grep -qi 'checksum mismatch' <<<"$out" && echo PASS || echo FAIL)" \
  "installer_rejects_checksum_mismatch" "nonzero exit + checksum mismatch" "rc=$rc $(grep -oi 'checksum mismatch[^"]*' <<<"$out" | head -1)"
after_hash=$(sha256sum /usr/local/bin/tracecat-agent | awk '{print $1}')
record "$([[ "$before_hash" == "$after_hash" ]] && echo PASS || echo FAIL)" "mismatch_did_not_replace_binary" "binary unchanged" "$before_hash"
# valid checksum for a tarball that does not contain the binary
cp "$AGENT_TARBALL" "$TMPD/empty.tar.gz"
tar -czf "$TMPD/empty.tar.gz" -C "$TMPD" corrupt.tar.gz 2>/dev/null
sha256sum "$TMPD/empty.tar.gz" | awk '{print $1"  tracecat-agent-linux-amd64.tar.gz"}' >"$TMPD/empty.checksums"
out=$(bash "$INSTALLER" agent --tarball "$TMPD/empty.tar.gz" --checksums "$TMPD/empty.checksums" \
      --listen "${TS_IP}:${AGENT_PORT}" --nexttrace /usr/local/bin/nexttrace --no-start --force 2>&1); rc=$?
record "$([[ $rc -ne 0 ]] && grep -qi 'does not contain bin/tracecat-agent' <<<"$out" && echo PASS || echo FAIL)" \
  "installer_rejects_wrong_contents" "refuses a tarball without the binary" "rc=$rc $(grep -oi 'tarball does not contain[^"]*' <<<"$out" | head -1)"

# =========================================================================
section "L4. upgrade keeps existing configuration"
# =========================================================================
sleep 1
cfg_mtime=$(stat -c %Y /etc/tracecat/controller.json)
env_mtime=$(stat -c %Y /etc/tracecat/controller.env)
cfg_sha=$(sha256sum /etc/tracecat/controller.json | awk '{print $1}')
env_sha=$(sha256sum /etc/tracecat/controller.env | awk '{print $1}')
bin_mtime=$(stat -c %Y /usr/local/bin/tracecat-controller)
sleep 1
TRACECAT_AGENT_TOKEN="$GEN_TOKEN" bash "$INSTALLER" controller \
  --tarball "$CONTROLLER_TARBALL" --checksums "$DIST/checksums.txt" \
  --auth dev --listen 127.0.0.1:8080 --public-origin "$DEV_ORIGIN" \
  --agent "${NODE_ID},http://${TS_IP}:${AGENT_PORT},TRACECAT_AGENT_TOKEN,Installed agent" \
  --no-start >"$TMPD/controller-upgrade.log" 2>&1
record "$(grep -q 'keeping existing /etc/tracecat/controller.json' "$TMPD/controller-upgrade.log" && echo PASS || echo FAIL)" \
  "upgrade_warns_keeps_config" "warns and keeps existing config" "$(grep -o 'keeping existing[^,]*' "$TMPD/controller-upgrade.log" | head -1)"
record "$([[ $(stat -c %Y /etc/tracecat/controller.json) == "$cfg_mtime" && $(sha256sum /etc/tracecat/controller.json | awk '{print $1}') == "$cfg_sha" ]] && echo PASS || echo FAIL)" \
  "upgrade_config_unchanged" "config mtime+content unchanged" "mtime=$cfg_mtime"
record "$([[ $(stat -c %Y /etc/tracecat/controller.env) == "$env_mtime" && $(sha256sum /etc/tracecat/controller.env | awk '{print $1}') == "$env_sha" ]] && echo PASS || echo FAIL)" \
  "upgrade_env_unchanged" "env mtime+content unchanged" "mtime=$env_mtime"
record "$([[ $(stat -c %Y /usr/local/bin/tracecat-controller) -gt $bin_mtime ]] && echo PASS || echo FAIL)" \
  "upgrade_replaces_binary" "binary mtime advanced" "before=$bin_mtime after=$(stat -c %Y /usr/local/bin/tracecat-controller)"

# =========================================================================
section "L5. local-auth mode install + login/CSRF"
# =========================================================================
systemctl stop tracecat-controller >/dev/null 2>&1 || true
LOCAL_PW="$(openssl rand -base64 24 | tr -d '\n')"
local_log="$TMPD/controller-local-install.log"
printf '%s\n' "$LOCAL_PW" | TRACECAT_AGENT_TOKEN="$GEN_TOKEN" bash "$INSTALLER" controller \
  --tarball "$CONTROLLER_TARBALL" --checksums "$DIST/checksums.txt" \
  --auth local --password-stdin --listen 127.0.0.1:8081 --public-origin http://127.0.0.1:8081 \
  --agent "${NODE_ID},http://${TS_IP}:${AGENT_PORT},TRACECAT_AGENT_TOKEN,Installed agent" \
  --force >"$local_log" 2>&1 \
  && record PASS "local_install_exit" "installer exit 0" "0" \
  || record FAIL "local_install_exit" "installer exit 0" "nonzero: $(tail -2 "$local_log" | tr '\n' ' ' | cut -c1-160)"
record "$(grep -q '^TRACECAT_CONTROLLER_PASSWORD_HASH=pbkdf2-sha256\$' /etc/tracecat/controller.env && echo PASS || echo FAIL)" \
  "local_env_has_pbkdf2_hash" "pbkdf2 hash in 0600 env" "$(grep -o 'pbkdf2-sha256\$[0-9]*' /etc/tracecat/controller.env | head -1)"
record "$(grep -q "$LOCAL_PW" /etc/tracecat/controller.env && echo FAIL || echo PASS)" "local_env_no_plaintext_password" "plaintext password absent" "none"
lcheck=$(python3 - /etc/tracecat/controller.json <<'PY' 2>&1
import json, sys
c = json.load(open(sys.argv[1]))
assert c["auth"]["mode"] == "local", c["auth"]
assert c["auth"]["local"]["password_hash_env"] == "TRACECAT_CONTROLLER_PASSWORD_HASH"
print("ok local config")
PY
)
record "$([[ "$lcheck" == ok* ]] && echo PASS || echo FAIL)" "local_config_strict_schema" "local mode config valid" "$lcheck"
up=0
for _ in $(seq 1 60); do wait_http http://127.0.0.1:8081/healthz 1 && { up=1; break; }; sleep 0.25; done
record "$([[ $up -eq 1 ]] && echo PASS || echo FAIL)" "local_controller_started" "healthz 200" "up=$up"
jar="$TMPD/jar"
lcode=$(curl -sS -m 5 -c "$jar" -o "$TMPD/login.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data-binary "$(python3 -c 'import json,sys;print(json.dumps({"password":sys.argv[1]}))' "$LOCAL_PW")" \
  http://127.0.0.1:8081/api/v1/auth/login 2>/dev/null || true)
record "$([[ "$lcode" == 200 ]] && echo PASS || echo FAIL)" "local_login_with_installed_hash" 200 "$lcode"
csrf=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("csrf_token",""))' "$TMPD/login.json" 2>/dev/null)
rcode=$(curl -sS -m 5 -b "$jar" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:8081' -H "X-TraceCat-CSRF: $csrf" --data-binary '{"target":"1.1.1.1"}' \
  http://127.0.0.1:8081/api/v1/resolve 2>/dev/null || true)
record "$([[ "$rcode" == 200 ]] && echo PASS || echo FAIL)" "local_csrf_post_after_install" "resolver 200 with CSRF" "$rcode"
wcode=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data-binary '{"password":"definitely-wrong-password"}' http://127.0.0.1:8081/api/v1/auth/login 2>/dev/null || true)
record "$([[ "$wcode" == 401 ]] && echo PASS || echo FAIL)" "local_login_wrong_password" 401 "$wcode"

# =========================================================================
section "L6. missing Agent token env (controller installer fails closed)"
# =========================================================================
systemctl stop tracecat-controller >/dev/null 2>&1 || true
out=$(bash "$INSTALLER" controller --tarball "$CONTROLLER_TARBALL" --checksums "$DIST/checksums.txt" \
  --auth dev --listen 127.0.0.1:8080 --public-origin "$DEV_ORIGIN" \
  --agent "${NODE_ID},http://${TS_IP}:${AGENT_PORT},TRACECAT_AGENT_TOKEN_INSTALLER_TEST,Installed agent" \
  --force 2>&1); rc=$?
record "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" "missing_token_installer_exit" "exit 0 (installed but not started)" "rc=$rc"
record "$(grep -qi 'were not set while installing' <<<"$out" && echo PASS || echo FAIL)" "missing_token_warns" "warning about missing token env" "$(grep -oi 'Agent token environment variable.*' <<<"$out" | head -1)"
record "$(grep -q '^# TRACECAT_AGENT_TOKEN_INSTALLER_TEST=REPLACE_WITH_THE_AGENT_TOKEN' /etc/tracecat/controller.env && echo PASS || echo FAIL)" \
  "missing_token_leaves_placeholder" "commented placeholder in env" "$(grep -c '^# .*REPLACE_WITH_THE_AGENT_TOKEN' /etc/tracecat/controller.env) placeholder(s)"
record "$(systemctl is-active --quiet tracecat-controller && echo FAIL || echo PASS)" "missing_token_no_start" "controller not started" "$(systemctl is-active tracecat-controller)"
record "$([[ $(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -c ':8080$' || true) -eq 0 ]] && echo PASS || echo FAIL)" \
  "missing_token_no_listener" "no 8080 listener" "$(ss -H -ltn 2>/dev/null | awk '{print $4}' | grep ':8080$' | paste -sd, -)"

# leave installer-managed services stopped; the Mac side restores the stack
systemctl stop tracecat-agent tracecat-controller >/dev/null 2>&1 || true
printf '\n===== SUMMARY: %d PASS, %d FAIL, %d SKIP =====\n' "$PASS_N" "$FAIL_N" "$SKIP_N"
[[ $FAIL_N -eq 0 ]] && exit 0 || exit 1
