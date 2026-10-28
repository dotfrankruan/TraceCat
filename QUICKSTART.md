# TraceCat Quick Start

Get a working dashboard and one Agent running locally in about five minutes,
then trace a target over ICMP, TCP or UDP.

> **Security note:** the local setup below uses `auth.mode=dev`, an explicit
> loopback-only authentication bypass. Never expose it beyond `127.0.0.1`.
> Production deployment is in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## 1. Prerequisites

| Requirement | Notes |
| --- | --- |
| Go 1.23+ | builds the Controller and Agent |
| [NextTrace](https://github.com/nxtrace/NTrace-core) | the Agent executes this binary; v1.7.x is verified. It must be an **absolute path** in the Agent config and executable by the Agent user |
| Node.js 22+ / pnpm | **only** if you rebuild the dashboard from `web/`; the compiled UI is committed and embedded, so a plain `go build` needs no Node |
| Linux + `CAP_NET_RAW` | required for real probes (see step 4); macOS works for a local demo |

## 2. Build

```bash
git clone https://github.com/dotfrankruan/TraceCat.git
cd TraceCat
make build          # -> bin/tracecat-controller and bin/tracecat-agent
```

`make build` uses the committed dashboard assets. Rebuild them with
`make ui` only after changing `web/`.

## 3. Point the Agent at your NextTrace binary

`configs/agent.dev.json` contains `"binary": "/usr/local/bin/nexttrace"`.
If yours lives elsewhere, set the absolute path:

```bash
# macOS Homebrew example
which nexttrace                       # e.g. /opt/homebrew/bin/nexttrace
export TRACECAT_AGENT_TOKEN=local-dev-token-please-change
jq '.nexttrace.binary="/opt/homebrew/bin/nexttrace"' \
   configs/agent.dev.json > /tmp/agent.dev.json
```

Hostnames and `PATH` lookup are intentionally not accepted for the binary.

## 4. Run the Agent (terminal 1)

```bash
export TRACECAT_AGENT_TOKEN=local-dev-token-please-change
./bin/tracecat-agent -config /tmp/agent.dev.json
# expected: "nexttrace detected" ... "agent listening" listen=127.0.0.1:9481
```

The dev config binds loopback and explicitly relaxes the Tailscale-only bind
rule. A production Agent binds only its Tailscale address and fails startup
otherwise. Real probes need `CAP_NET_RAW` for the NextTrace child (see
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) §2.1).

## 5. Run the Controller (terminal 2)

```bash
export TRACECAT_AGENT_TOKEN=local-dev-token-please-change
./bin/tracecat-controller -config configs/controller.dev.json
# expected: "tracecat-controller listening" listen=127.0.0.1:8080
```

The dev Controller uses `./var/controller.db`; `configs/controller.dev.json`
already expects the Agent on `127.0.0.1:9481` with that token.

## 6. Trace something

Open **http://127.0.0.1:8080**:

1. Enter a literal IP such as `1.1.1.1` (or a domain such as `example.com`).
2. Press **Resolve**. For a domain, all A/AAAA addresses are shown as explicit
   choices — you must pick one when there are several. The exact numeric IP
   being traced is always displayed.
3. Select one or more Agents (the dev config has one; add more to compare).
4. Choose the protocol:
   - **ICMP** — no port, the default.
   - **TCP** — enter the destination port (default `80`).
   - **UDP** — enter the destination port (default `33494`).
5. Press **Start trace**. Per-node status updates arrive live; expand hops for
   RTT/ASN/org/geo/PTR/MPLS/probe details, switch to **Compare** for aligned
   paths and honest differences, and use **Export JSON** to download the job
   including bounded raw NextTrace output.

Quick API check (dev mode):

```bash
CSRF=$(curl -sS http://127.0.0.1:8080/api/v1/session | jq -r .csrf_token)
curl -sS -X POST http://127.0.0.1:8080/api/v1/resolve \
  -H 'Content-Type: application/json' -H "X-TraceCat-CSRF: $CSRF" \
  -d '{"target":"1.1.1.1"}'
```

A TCP job body looks like:

```json
{
  "target_ip": "1.1.1.1",
  "original_target": "1.1.1.1",
  "node_ids": ["local-1"],
  "protocol": "tcp",
  "port": 443,
  "max_hops": 30,
  "queries": 3,
  "timeout_ms": 60000
}
```

Ports are integers in `1..65535`, required for TCP/UDP and forbidden for ICMP.
The Controller and the Agent each enforce their own `allowed_protocols` list.

## 7. Troubleshooting

| Symptom | Fix |
| --- | --- |
| Agent: `nexttrace binary ... does not exist` | set the absolute `nexttrace.binary` path in the Agent config |
| Agent: `nexttrace is not usable; agent starts degraded` | run `nexttrace --version` and the health endpoint; NextTrace is missing a required flag or failed capability detection |
| Agent: `listen address ... is not assigned` | Tailscale is down or the configured IP changed; in dev mode use `127.0.0.1` with `allow_non_tailscale_bind` |
| Agent: `address already in use` | another process owns port 9481; change `listen` in both configs |
| Controller: `bind: address already in use` | change `listen` in `configs/controller.dev.json` and `public_origin` to match |
| Resolve returns `no_addresses` | the local resolver returned only filtered addresses (or none); try a literal IP |
| `target_rejected` | destination is not globally routable unicast; use a public IP or configure a narrow `security.allowed_cidrs` allowlist on **both** Controller and Agent |
| `403 csrf_failed` | dev CSRF tokens rotate on Controller restart; reload the page |
| Hops show **no reply** | intermediate routers often drop probes; this does not mean the route is broken |
| TCP/UDP unavailable in the UI | check `limits.allowed_protocols` (Controller), `nexttrace.allowed_protocols` (Agent) and the binary's detected `tcp`/`udp` capabilities in `/v1/health` |
| Probes fail with permission errors | grant `CAP_NET_RAW` to NextTrace (systemd ambient capability or `setcap`; see deployment docs) |

## 8. Next steps

- Production: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — systemd, Tailscale
  ACLs, Cloudflare Tunnel/Access, safe defaults.
- API: [docs/API.md](docs/API.md) — versioned request/response schemas.
- Security: [`SECURITY.md`](SECURITY.md) — threat model and residual risks.
- Verification: [docs/VERIFICATION.md](docs/VERIFICATION.md) — independent
  real-host PASS/FAIL evidence.
