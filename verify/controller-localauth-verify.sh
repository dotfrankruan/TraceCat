#!/usr/bin/env bash
# Independent verification of the Controller's `local` authentication mode.
#
# RUNS ON THE TEST HOST AS ROOT. Uses the second Controller instance on
# 127.0.0.1:8081 (config /etc/tracecat/controller-local.json) and the random
# password stored in /root/tc-verify/local-password.txt (0600). The password is
# never printed.
#
# Covers: PBKDF2 login success/failure/rate limit, HttpOnly+SameSite=Strict
# session cookie, CSRF + Origin/Sec-Fetch-Site enforcement, logout revocation,
# SQLite session persistence, default-deny API auth, body limits, JSON 404/405,
# dashboard security headers, and secret leakage in responses/journals/DB.
set -uo pipefail

UNIT="${UNIT:-tracecat-controller-local}"
BASE="${BASE:-http://127.0.0.1:8081}"
ORIGIN="${ORIGIN:-http://127.0.0.1:8081}"
CONFIG="${CONFIG:-/etc/tracecat/controller-local.json}"
ENVFILE="${ENVFILE:-/etc/tracecat/controller-local.env}"
DB="${DB:-/var/lib/tracecat/controller-local.db}"
PASSFILE="${PASSFILE:-/root/tc-verify/local-password.txt}"
RESULTS="${RESULTS:-/tmp/tracecat-localauth-verify.tsv}"
AGENT_A="${AGENT_A:-debian-test-1}"
AGENT_B="${AGENT_B:-debian-test-2}"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "error: run as root on the host" >&2; exit 2; }
PASSWORD=$(cat "$PASSFILE")
HASH=$(sed -n 's/^TRACECAT_CONTROLLER_PASSWORD_HASH=//p' "$ENVFILE")
TOKEN_A=$(sed -n 's/^TRACECAT_AGENT_TOKEN_1=//p' "$ENVFILE")
TOKEN_B=$(sed -n 's/^TRACECAT_AGENT_TOKEN_2=//p' "$ENVFILE")

TMPD=$(mktemp -d /tmp/tc-local-verify.XXXXXX)
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

BODY="$TMPD/body"; HDR="$TMPD/hdr"; CODE="000"
req() { # req JAR METHOD PATH [BODY] [CONTENT_TYPE] [extra curl args...]
  local jar=$1 method=$2 path=$3 body=${4-} ct=${5-application/json}
  if [[ $# -ge 5 ]]; then shift 5; else shift $#; fi
  : >"$BODY"; : >"$HDR"
  local args=(-sS --max-time 120 -o "$BODY" -D "$HDR" -w '%{http_code}' -X "$method")
  [[ "$jar" != "-" ]] && args+=(-c "$jar" -b "$jar")
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: $ct" --data-binary "$body")
  fi
  CODE=$(curl "${args[@]}" "$@" "${BASE}${path}" 2>"$TMPD/err") || true
  [[ -n "$CODE" ]] || CODE="000"
}
jget() {
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
hdr_get() { awk -v IGNORECASE=1 -v k="$1" 'BEGIN{FS=": "} tolower($1)==tolower(k){v=substr($0,length($1)+3); sub(/\r$/,"",v); print v}' "$HDR" | tail -1; }
hdr_has() { grep -qiE "^$1:" "$HDR"; }
session_cookie() { sed -n 's/^Set-Cookie: tracecat_session=\([^;]*\).*/\1/ip' "$HDR" | tail -1; }
restart_local() {
  systemctl restart "$UNIT"
  for _ in $(seq 1 40); do sleep 0.3; curl -sS -m 2 -o /dev/null "$BASE/healthz" && break; done
}
login() { # login <jar> <password> [extra curl args...]
  local jar=$1 pw=$2; shift 2
  req "$jar" POST /api/v1/auth/login "$(python3 -c 'import json,sys;print(json.dumps({"password":sys.argv[1]}))' "$pw")" application/json "$@"
}

echo "TraceCat local-auth independent verification — $(date -u +%FT%TZ)"
echo "host=$(hostname) base=$BASE unit=$UNIT"

# =========================================================================
section "A. instance posture"
# =========================================================================
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "unit_active" active "$(systemctl is-active "$UNIT")"
record "$([[ $(systemctl show -p User --value "$UNIT") == tracecat ]] && echo PASS || echo FAIL)" \
  "runs_as_unprivileged" tracecat "$(systemctl show -p User --value "$UNIT")"
listener=$(ss -H -ltnp 2>/dev/null | awk '{print $4}' | grep ':8081$' || true)
record "$([[ "$listener" == "127.0.0.1:8081" ]] && echo PASS || echo FAIL)" "loopback_only" "127.0.0.1:8081" "${listener:-none}"
record "$([[ $(stat -c '%a %U:%G' "$CONFIG") == "640 root:tracecat" ]] && echo PASS || echo FAIL)" \
  "config_permissions" "640 root:tracecat" "$(stat -c '%a %U:%G' "$CONFIG")"
record "$([[ $(stat -c '%a %U:%G' "$ENVFILE") == "600 root:root" ]] && echo PASS || echo FAIL)" \
  "env_permissions" "600 root:root" "$(stat -c '%a %U:%G' "$ENVFILE")"
dbmode=$(stat -c '%a %U:%G' "$DB" 2>/dev/null)
record "$([[ "$dbmode" == 600* ]] && echo PASS || echo FAIL)" "database_permissions" "0600 tracecat" "${dbmode:-absent}"

# =========================================================================
section "B. default-deny API authentication"
# =========================================================================
req - GET /api/v1/session
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "session_unauthenticated" 401 "$CODE $(jget error.code)"
req - GET /api/v1/nodes
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "nodes_unauthenticated" 401 "$CODE $(jget error.code)"
req - POST /api/v1/resolve '{"target":"example.com"}'
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "resolve_unauthenticated" 401 "$CODE $(jget error.code)"
req - GET /api/v1/jobs
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "jobs_unauthenticated" 401 "$CODE $(jget error.code)"
req - GET /api/v1/jobs/0123456789abcdef0123456789abcdef/events
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "sse_unauthenticated" 401 "$CODE $(jget error.code)"
req - POST /api/v1/jobs '{"target_ip":"1.1.1.1","node_ids":["debian-test-1"],"protocol":"icmp","max_hops":1,"queries":1,"timeout_ms":5000}'
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "job_create_unauthenticated" 401 "$CODE $(jget error.code)"

# =========================================================================
section "C. login validation"
# =========================================================================
FAKEJAR="$TMPD/fakejar"
login "$FAKEJAR" "wrong-password-123" -H 'X-Forwarded-For: 198.51.100.10'
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "login_wrong_password" 401 "$CODE $(jget error.code)"
failed_cookie=$(session_cookie)
record "$( [[ -z "$failed_cookie" ]] && ! grep -qi '^Set-Cookie: tracecat_session' "$HDR" && echo PASS || echo FAIL)" \
  "login_failure_no_cookie" "no session cookie" "len=${#failed_cookie}"

req "$FAKEJAR" POST /api/v1/auth/login '{bad json' application/json -H 'X-Forwarded-For: 198.51.100.10'
record "$([[ "$CODE" == 400 ]] && echo PASS || echo FAIL)" "login_malformed_json" 400 "$CODE $(jget error.code)"
req "$FAKEJAR" POST /api/v1/auth/login '{"password":"x","extra":true}' application/json -H 'X-Forwarded-For: 198.51.100.10'
record "$([[ "$CODE" == 400 ]] && echo PASS || echo FAIL)" "login_unknown_field" 400 "$CODE $(jget error.code)"
python3 -c 'import json;print(json.dumps({"password":"a"*5000}))' >"$TMPD/big-login.json"
req "$FAKEJAR" POST /api/v1/auth/login "@$TMPD/big-login.json" application/json -H 'X-Forwarded-For: 198.51.100.10'
record "$([[ "$CODE" == 413 ]] && echo PASS || echo FAIL)" "login_body_over_4kib" 413 "$CODE $(jget error.code) size=$(stat -c %s "$TMPD/big-login.json")"
req "$FAKEJAR" POST /api/v1/auth/login "$(python3 -c 'import json;print(json.dumps({"password":"whatever-pw"}))')" text/plain -H 'X-Forwarded-For: 198.51.100.10'
record "$([[ "$CODE" != 200 && ( "$CODE" == 401 || "$CODE" == 415 ) ]] && echo PASS || echo FAIL)" \
  "login_content_type_not_bypassed" "not 200 (401 or 415); JSON/password still validated" "$CODE $(jget error.code)"

# =========================================================================
section "D. successful login, cookie attributes, CSRF"
# =========================================================================
JAR="$TMPD/jar1"
login "$JAR" "$PASSWORD"
record "$([[ "$CODE" == 200 && $(jget authenticated) == True ]] && echo PASS || echo FAIL)" \
  "login_success" "200 authenticated=true" "$CODE mode=$(jget mode) user=$(jget user.email)"
CSRF=$(jget csrf_token)
record "$([[ ${#CSRF} -ge 32 ]] && echo PASS || echo FAIL)" "login_returns_csrf" ">=32 chars" "len=${#CSRF}"
raw_token=$(session_cookie)
record "$([[ -n "$raw_token" && ${#raw_token} -ge 32 ]] && echo PASS || echo FAIL)" \
  "session_cookie_issued" "tracecat_session set" "len=${#raw_token}"
cookie_line=$(grep -i '^Set-Cookie: tracecat_session=' "$HDR" | tr -d '\r' || true)
record "$(grep -qi 'HttpOnly' <<<"$cookie_line" && echo PASS || echo FAIL)" "cookie_httponly" HttpOnly "$(grep -oi 'HttpOnly' <<<"$cookie_line" | head -1)"
record "$(grep -qi 'SameSite=Strict' <<<"$cookie_line" && echo PASS || echo FAIL)" "cookie_samesite_strict" SameSite=Strict "$(grep -oi 'SameSite=[A-Za-z]*' <<<"$cookie_line" | head -1)"
record "$(grep -qi 'Path=/' <<<"$cookie_line" && echo PASS || echo FAIL)" "cookie_path" "Path=/" "$(grep -oi 'Path=[^;]*' <<<"$cookie_line" | head -1)"
record "$([[ "$ORIGIN" == https://* ]] && echo PASS || echo SKIP)" "cookie_secure_flag" "Secure only on https origin" "http origin -> $(grep -qi 'Secure' <<<"$cookie_line" && echo Secure || echo no-Secure)"
record "$( ! grep -qF -- "$PASSWORD" "$BODY" && ! grep -qF -- "$HASH" "$BODY" && echo PASS || echo FAIL)" \
  "login_response_no_secret" "no password/hash echo" "none"

req "$JAR" GET /api/v1/session
record "$([[ "$CODE" == 200 && $(jget mode) == local ]] && echo PASS || echo FAIL)" \
  "session_with_cookie" "200 mode=local" "$CODE $(jget mode)"
record "$( ! grep -qF -- "$raw_token" "$BODY" && echo PASS || echo FAIL)" "session_body_no_raw_token" "session token not echoed" "none"

req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}'
record "$([[ "$CODE" == 403 && $(jget error.code) == csrf_failed ]] && echo PASS || echo FAIL)" \
  "csrf_required_on_post" "403 csrf_failed" "$CODE $(jget error.code)"
req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H 'X-TraceCat-CSRF: wrong-token' -H "Origin: $ORIGIN"
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "csrf_wrong_token" 403 "$CODE $(jget error.code)"
req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF" -H "Origin: $ORIGIN"
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "csrf_valid_token" 200 "$CODE $(jget kind)"
req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF" -H 'Origin: http://evil.example'
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "csrf_wrong_origin" 403 "$CODE $(jget error.code)"
req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF" -H 'Sec-Fetch-Site: cross-site'
record "$([[ "$CODE" == 403 ]] && echo PASS || echo FAIL)" "csrf_cross_site_fetch" 403 "$CODE $(jget error.code)"
req "$JAR" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF" -H 'Sec-Fetch-Site: same-origin'
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "csrf_same_origin_fetch" 200 "$CODE $(jget kind)"

# =========================================================================
section "E. logout revocation and forged sessions"
# =========================================================================
JAR2="$TMPD/jar2"
login "$JAR2" "$PASSWORD"
CSRF2=$(jget csrf_token)
token2=$(session_cookie)
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "second_login" 200 "$CODE"
req "$JAR2" POST /api/v1/auth/logout '' application/json -H "X-TraceCat-CSRF: $CSRF2" -H "Origin: $ORIGIN"
record "$([[ "$CODE" == 204 ]] && echo PASS || echo FAIL)" "logout_ok" 204 "$CODE"
cleared=$(grep -i '^Set-Cookie: tracecat_session=' "$HDR" | tr -d '\r' || true)
record "$([[ -z "$cleared" ]] || grep -qiE 'Max-Age=0|Expires=Thu, 01 Jan 1970' <<<"$cleared" && echo PASS || echo FAIL)" \
  "logout_clears_cookie" "expired cookie" "$(grep -oiE 'Max-Age=[0-9-]+' <<<"$cleared" | head -1)"
printf 'tracecat_session=%s\n' "$token2" >"$TMPD/revoked.jar.txt"
req - GET /api/v1/session "" application/json -H "Cookie: tracecat_session=$token2"
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "revoked_session_rejected" 401 "$CODE $(jget error.code)"
req - GET /api/v1/session "" application/json -H 'Cookie: tracecat_session=not-a-real-session-token-1234567890'
record "$([[ "$CODE" == 401 ]] && echo PASS || echo FAIL)" "forged_session_rejected" 401 "$CODE $(jget error.code)"

# =========================================================================
section "F. session persistence in SQLite"
# =========================================================================
JAR3="$TMPD/jar3"
login "$JAR3" "$PASSWORD"
CSRF3=$(jget csrf_token)
token3=$(session_cookie)
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "third_login_for_persistence" 200 "$CODE"
restart_local
req "$JAR3" GET /api/v1/session
record "$([[ "$CODE" == 200 && $(jget authenticated) == True ]] && echo PASS || echo FAIL)" \
  "session_survives_restart" "200 after controller restart" "$CODE"
record "$(systemctl is-active --quiet "$UNIT" && echo PASS || echo FAIL)" "local_instance_active_after_restart" active "$(systemctl is-active "$UNIT")"

dbcheck=$(python3 - "$DB" "$token3" "$CSRF3" 2>&1 <<'PY'
import hashlib, os, sqlite3, sys
db, token, csrf = sys.argv[1], sys.argv[2], sys.argv[3]
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
assert "sessions" in tables, tables
cols = [r[1] for r in con.execute("pragma table_info(sessions)")]
rows = list(con.execute(f"select * from sessions"))
assert rows, "no sessions rows"
hashes = [str(r[cols.index(c)]) for r in rows for c in cols if "hash" in c.lower()]
assert hashes, cols
want = hashlib.sha256(token.encode()).hexdigest()
assert any(want == h.lower() for h in hashes), "raw token hash not stored"
csrf_cols = [c for c in cols if "csrf" in c.lower()]
assert csrf_cols, cols
assert any(any(str(row[cols.index(c)]) == csrf for c in csrf_cols) for row in rows), "csrf token not stored"
blob = b""
for path in (db, db + "-wal", db + "-shm"):
    if os.path.exists(path):
        blob += open(path, "rb").read()
assert token.encode() not in blob, "RAW session token present in database files"
print(f"tables={tables} sessions={len(rows)} cols={cols} token_hash=sha256(stored) raw_token_absent=yes")
PY
)
record "$([[ "$dbcheck" != *Traceback* && "$dbcheck" == *raw_token_absent=yes* ]] && echo PASS || echo FAIL)" \
  "session_storage_hashed_and_persistent" "sha256(token) in SQLite, raw token absent, csrf stored" "$dbcheck"

# =========================================================================
section "G. controller rate limits (local instance has small limits)"
# =========================================================================
restart_local # reset in-memory limiters; sessions are unaffected
# resolve: 5/min -> 6th must be 429
resolve_codes=""
for _ in $(seq 1 6); do
  req "$JAR3" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF3" -H "Origin: $ORIGIN"
  resolve_codes="$resolve_codes $CODE"
done
record "$(grep -q ' 429' <<<"$resolve_codes" && echo PASS || echo FAIL)" "resolve_rate_limit" "5 allowed then 429" "codes=${resolve_codes# }"
req "$JAR3" POST /api/v1/resolve '{"target":"1.1.1.1"}' application/json -H "X-TraceCat-CSRF: $CSRF3" -H "Origin: $ORIGIN"
record "$([[ "$CODE" == 429 && $(jget error.code) == rate_limited ]] && echo PASS || echo FAIL)" \
  "resolve_rate_limit_envelope" "429 rate_limited" "$CODE $(jget error.code) retry_after=$(hdr_get Retry-After)"

# jobs: 3/min -> 4th must be 429 (jobs are tiny: 1 hop, 5 s timeout)
job_codes=""
for _ in $(seq 1 4); do
  body=$(printf '{"target_ip":"1.1.1.1","node_ids":["%s"],"protocol":"icmp","max_hops":1,"queries":1,"timeout_ms":5000}' "$AGENT_A")
  req "$JAR3" POST /api/v1/jobs "$body" application/json -H "X-TraceCat-CSRF: $CSRF3" -H "Origin: $ORIGIN"
  job_codes="$job_codes $CODE"
  sleep 0.2
done
sleep 8  # let the quick jobs finish so the 4th request hits the rate limit, not the concurrency cap
record "$(grep -q ' 429' <<<"$job_codes" && echo PASS || echo FAIL)" "job_rate_limit" "3 allowed then 429" "codes=${job_codes# }"

# =========================================================================
section "H. login rate limit (per client IP, trusted-proxy aware)"
# =========================================================================
codes=""
for _ in $(seq 1 13); do
  login "$FAKEJAR" "wrong-password-$RANDOM" -H 'X-Forwarded-For: 198.51.100.7'
  codes="$codes $CODE"
done
n429=$(grep -o '429' <<<"$codes" | wc -l | tr -d ' ')
record "$([[ "$n429" -ge 1 ]] && echo PASS || echo FAIL)" "login_rate_limit" ">=1 x 429 within 13 failures" "codes=${codes# }"
login "$FAKEJAR" "wrong-password-final" -H 'X-Forwarded-For: 198.51.100.7'
record "$([[ "$CODE" == 429 ]] && echo PASS || echo FAIL)" "login_rate_limit_envelope" "429 rate_limited" "$CODE $(jget error.code) retry_after=$(hdr_get Retry-After)"
# a different client is unaffected (the limiter is per client IP)
login "$TMPD/jar_other" "$PASSWORD"
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "login_rate_limit_per_client" "other client still logs in" "$CODE"

# =========================================================================
section "I. API surface, body limits, dashboard headers"
# =========================================================================
req "$JAR3" GET /api/v1/does-not-exist
record "$([[ "$CODE" == 404 && $(jget error.code) == not_found ]] && echo PASS || echo FAIL)" "api_unknown_path_json" "404 not_found" "$CODE $(jget error.code)"
req "$JAR3" DELETE /api/v1/jobs/0123456789abcdef0123456789abcdef
record "$([[ "$CODE" == 405 ]] && echo PASS || echo FAIL)" "method_not_allowed" 405 "$CODE Allow=$(hdr_get Allow)"
req "$JAR3" GET /api/v1/auth/login
record "$([[ "$CODE" == 405 ]] && echo PASS || echo FAIL)" "login_get_not_allowed" 405 "$CODE Allow=$(hdr_get Allow)"
python3 -c 'import json;print(json.dumps({"target_ip":"1.1.1.1","original_target":"x"*9000,"node_ids":["debian-test-1"],"protocol":"icmp","max_hops":1,"queries":1,"timeout_ms":5000}))' >"$TMPD/big-job.json"
req "$JAR3" POST /api/v1/jobs "@$TMPD/big-job.json" application/json -H "X-TraceCat-CSRF: $CSRF3" -H "Origin: $ORIGIN"
record "$([[ "$CODE" == 413 ]] && echo PASS || echo FAIL)" "jobs_body_over_8kib" 413 "$CODE $(jget error.code)"

req - GET /
record "$([[ "$CODE" == 200 ]] && echo PASS || echo FAIL)" "dashboard_shell_public" "200 HTML (login screen)" "$CODE $(hdr_get Content-Type)"
csp=$(hdr_get Content-Security-Policy)
record "$([[ "$csp" == *"default-src 'self'"* && "$csp" == *"frame-ancestors 'none'"* ]] && echo PASS || echo FAIL)" \
  "dashboard_csp" "default-src 'self' + frame-ancestors 'none'" "${csp:0:90}"
record "$([[ $(hdr_get X-Frame-Options) == DENY && $(hdr_get X-Content-Type-Options) == nosniff ]] && echo PASS || echo FAIL)" \
  "dashboard_clickjacking_and_sniffing" "DENY + nosniff" "$(hdr_get X-Frame-Options)/$(hdr_get X-Content-Type-Options)"

# =========================================================================
section "J. secret leakage"
# =========================================================================
leak=""
for needle in "$PASSWORD" "$HASH" "$TOKEN_A" "$TOKEN_B" "$raw_token" "$token3" "pbkdf2-sha256"; do
  grep -qF -- "$needle" "$BODY" 2>/dev/null && leak="$leak body"
done
jlog=$(journalctl -u "$UNIT" --no-pager -o cat --since '-40 min' 2>/dev/null || true)
for needle in "$PASSWORD" "$HASH" "$TOKEN_A" "$TOKEN_B" "$raw_token" "$token3" "pbkdf2-sha256"; do
  grep -qF -- "$needle" <<<"$jlog" && leak="$leak journal"
done
record "$([[ -z "$leak" ]] && echo PASS || echo FAIL)" "no_secret_in_responses_or_journal" "no password/hash/tokens" "${leak:-none}"
record "$(grep -qE 'level":"(WARN|ERROR)' <<<"$jlog" && echo FAIL || echo PASS)" \
  "journal_clean_no_warn_error" "no WARN/ERROR" "$(grep -oE '"level":"(WARN|ERROR)","msg":"[^"]*"' <<<"$jlog" | sort -u | head -2 | paste -sd';' -)"

printf '\n===== SUMMARY: %d PASS, %d FAIL, %d SKIP =====\n' "$PASS_N" "$FAIL_N" "$SKIP_N"
[[ $FAIL_N -eq 0 ]] && exit 0 || exit 1
