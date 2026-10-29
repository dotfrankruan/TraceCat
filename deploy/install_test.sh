#!/usr/bin/env bash
# Argument-validation regression tests for deploy/install.sh.
# Run standalone (CI) so installer parsing cannot silently break again.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/deploy/install.sh"

fail=0
check_ok() {
  if ! add_agent_spec "$1" 2>/dev/null; then
    echo "FAIL: expected valid agent spec: $1"
    fail=1
  fi
}
check_reject() {
  if ( add_agent_spec "$1" ) 2>/dev/null; then
    echo "FAIL: expected rejected agent spec: $1"
    fail=1
  fi
}

check_ok "node-1,http://10.0.0.5:8443,TRACECAT_AGENT_TOKEN"
check_ok "node-1,https://trace.example.com,TRACECAT_AGENT_TOKEN,Tokyo,Tokyo JP,Example"
check_ok "node-2,http://[fd7a:115c:a1e0::1]:8443,TRACECAT_TOKEN_NODE_2"
check_ok "node-3,https://100.64.0.10:8443,TRACECAT_TOKEN_NODE_3"
check_reject "node-1,not-a-url,TRACECAT_AGENT_TOKEN"
check_reject "Node-1,http://10.0.0.5:8443,TRACECAT_AGENT_TOKEN"
check_reject "node-1,http://10.0.0.5:8443,lowercase-token-env"
check_reject "node-1,http://10.0.0.5:8443"
check_reject "node-1,http://10.0.0.5:8443,TRACECAT_AGENT_TOKEN,bad\"name"

# Bracket-character-class regression: must work on bash 3.2 and 5.x.
if [[ "http://10.0.0.5:8443" =~ ^https?://[][A-Za-z0-9._:/-]+/?$ ]]; then :; else
  echo "FAIL: URL character class does not match a plain URL on this bash"; fail=1
fi
if [[ "http://[fd7a:115c:a1e0::1]:8443" =~ ^https?://[][A-Za-z0-9._:/-]+/?$ ]]; then :; else
  echo "FAIL: URL character class does not match a bracketed IPv6 URL"; fail=1
fi
if [[ "http://10.0.0.5:8443 with space" =~ ^https?://[][A-Za-z0-9._:/-]+/?$ ]]; then
  echo "FAIL: URL with whitespace was accepted"; fail=1
fi

# Public-origin validation (portable character class, no escaped brackets).
origin_re='^https?://[][A-Za-z0-9._:/-]+/?$'
for good in "http://127.0.0.1:18090" "https://trace.example.com" "https://trace.example.com/" "http://[fd7a:115c:a1e0::1]:8080"; do
  if [[ "$good" =~ $origin_re ]]; then :; else
    echo "FAIL: public origin rejected: $good"; fail=1
  fi
done
for bad in "trace.example.com" "ftp://trace.example.com" "https://trace.example.com with space" "javascript:alert(1)"; do
  if [[ "$bad" =~ $origin_re ]]; then
    echo "FAIL: invalid public origin accepted: $bad"; fail=1
  fi
done

# dev-mode loopback listener check (escaped brackets are fine outside classes).
for good in "127.0.0.1:8080" "[::1]:8080"; do
  if [[ "$good" =~ ^(127\.0\.0\.1|\[::1\]): ]]; then :; else
    echo "FAIL: dev loopback listen rejected: $good"; fail=1
  fi
done
for bad in "0.0.0.0:8080" "10.0.0.5:8080"; do
  if [[ "$bad" =~ ^(127\.0\.0\.1|\[::1\]): ]]; then
    echo "FAIL: non-loopback dev listen accepted: $bad"; fail=1
  fi
done

# Listen validation (IPv4, bracketed IPv6, reject wildcard-less input).
for good in "10.0.0.5:8443" "127.0.0.1:9481" "[fd7a:115c:a1e0::1]:8443"; do
  if [[ "$good" =~ ^(\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):[0-9]{1,5}$ ]]; then :; else
    echo "FAIL: listen address rejected: $good"; fail=1
  fi
done
for bad in "8443" "10.0.0.5" "0.0.0.0:notaport"; do
  if [[ "$bad" =~ ^(\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:.]+):[0-9]{1,5}$ ]]; then
    echo "FAIL: invalid listen accepted: $bad"; fail=1
  fi
done

bash -n "$ROOT/deploy/install.sh" || { echo "FAIL: install.sh syntax"; fail=1; }
bash -n "$ROOT/deploy/quickstart.sh" || { echo "FAIL: quickstart.sh syntax"; fail=1; }
if bash "$ROOT/deploy/quickstart.sh" --help >/dev/null 2>&1; then :; else
  echo "FAIL: quickstart.sh --help did not exit 0"; fail=1
fi

# No trailing `[[ ... ]] && log ...` idiom that makes a successful install
# function return 1 under `set -e` when the condition is false.
if grep -nE '^[[:space:]]*\[\[ .* \]\] && (log|warn|echo)' "$ROOT/deploy/install.sh" >/dev/null; then
  echo "FAIL: installer has a trailing conditional-log idiom (exit-status hazard)"; fail=1
fi

# Node-id validation used by quickstart/install.sh.
for good in local node-1 a1; do
  if [[ "$good" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]; then :; else
    echo "FAIL: valid node id rejected: $good"; fail=1
  fi
done
for bad in "Local" "-node" "node id" "node.name"; do
  if [[ "$bad" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]]; then
    echo "FAIL: invalid node id accepted: $bad"; fail=1
  fi
done

# Address auto-detection must prefer a tailnet address over a LAN address.
fakebin="$(mktemp -d)"
cat >"$fakebin/ip" <<'FAKE'
#!/usr/bin/env bash
cat <<'OUT'
2: eth0    inet 10.0.0.45/24 brd 10.0.0.255 scope global eth0
3: tailscale0    inet 100.66.66.66/32 scope global tailscale0
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
OUT
FAKE
chmod +x "$fakebin/ip"
detected="$(PATH="$fakebin:$PATH" detect_private_ip)"
if [[ "$detected" != "100.66.66.66" ]]; then
  echo "FAIL: detect_private_ip preferred '$detected' over the tailnet address"; fail=1
fi
rm -rf "$fakebin"

# Enrollment-mode flags parse without requiring an --agent machine list.
if ! ( parse_args controller --enrollment --auth local --listen 10.0.0.5:8080 \
        --public-origin https://trace.example.com ) 2>/dev/null; then
  echo "FAIL: controller --enrollment parse failed"; fail=1
fi
if ! ( export TRACECAT_ENROLLMENT_TOKEN="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
      parse_args agent --controller http://10.0.0.5:8080 --listen 10.0.0.5:8443 ) 2>/dev/null; then
  echo "FAIL: agent --controller parse failed"; fail=1
fi

# --help must exit 0; an unknown option must exit non-zero.
if bash "$ROOT/deploy/install.sh" --help >/dev/null 2>&1; then :; else
  echo "FAIL: install.sh --help did not exit 0"; fail=1
fi
if bash "$ROOT/deploy/install.sh" agent --not-a-real-flag >/dev/null 2>&1; then
  echo "FAIL: install.sh accepted an unknown option"; fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "installer validation: FAILED"
  exit 1
fi
echo "installer validation: PASS"
