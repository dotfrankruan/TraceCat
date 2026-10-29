# TraceCat Quick Start

One command on a Linux host (systemd + NextTrace installed):

```bash
curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/quickstart.sh | sudo bash
```

It installs the Controller and one Agent as loopback-only systemd services,
generates a random login password and prints:

```
TraceCat is running.
  URL       http://127.0.0.1:8080
  Password  <generated>
```

Open the URL, log in with that password, then:

1. Enter `1.1.1.1` (or a domain) and press **Resolve**.
2. Pick the destination IP if more than one is offered.
3. Select the Agent, choose **ICMP**, **TCP** (port 443) or **UDP** (port 33494),
   and press **Start trace**.

That's it. Data lives in `/var/lib/tracecat/controller.db`; services are
`tracecat-controller` and `tracecat-agent`.

## Add Agents on other machines (multi-host, automatic)

Agents introduce themselves to the Controller — you do **not** list machines on
the Controller command line.

**On the Controller host**, enable enrollment (it prints a token and the exact
Agent command):

```bash
sudo bash /tmp/tc-install.sh controller --enrollment --auth local \
  --listen 10.0.0.10:8080 --public-origin https://trace.example.com
```

Use an address the Agents can reach for `--listen` (private overlay/VPC is
ideal); the browser URL stays the HTTPS `--public-origin`.

**On each Agent host** (NextTrace installed), run the command it printed:

```bash
TRACECAT_ENROLLMENT_TOKEN='<token from the Controller>' \
  sudo -E bash /tmp/tc-install.sh agent --controller http://10.0.0.10:8080
```

That's it: the Agent registers itself, receives its own trace token, and appears
in the dashboard automatically (no Controller restart, no `--agent` flags).
Agents refresh registration automatically. The enrollment token is a shared
secret: keep it out of shell history where possible and rotate it by restarting
the Controller with a new token.

Pre-registering specific Agents with `--agent id,url,token_env` is still
supported for locked-down setups; statically configured Agents take precedence
over auto-registered ones with the same id. Details:
[docs/DEPLOYMENT.md](DEPLOYMENT.md).

## Run from source instead (developers)

```bash
git clone https://github.com/dotfrankruan/TraceCat.git && cd TraceCat
make build            # dashboard is committed; no Node.js needed

# terminal 1 — Agent (loopback dev config)
TRACECAT_AGENT_TOKEN=local-dev-token-please-change \
  ./bin/tracecat-agent -config configs/agent.dev.json

# terminal 2 — Controller (dev auth, loopback only)
./bin/tracecat-controller -config configs/controller.dev.json
# open http://127.0.0.1:8080
```

If NextTrace is not at `/usr/local/bin/nexttrace`, set the absolute path in
`configs/agent.dev.json` → `nexttrace.binary`.

## Lifecycle

```bash
systemctl status tracecat-controller tracecat-agent
journalctl -u tracecat-controller -u tracecat-agent -f
systemctl restart tracecat-controller tracecat-agent
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `Controller did not become healthy` | `journalctl -u tracecat-controller -n 50`; usually a port conflict or missing Agent token env |
| Agent `listen address ... is not assigned` | the configured address is not on this host; use `127.0.0.1` for a single host or a real private IP |
| Probes fail with permission errors | grant `CAP_NET_RAW` to NextTrace (see `docs/DEPLOYMENT.md` §2.1) |
| `target_rejected` | only globally routable unicast is allowed by default; configure `security.allowed_cidrs` on Controller and Agent for lab ranges |
| Hops show **no reply** | common for intermediate routers; not proof of a broken route |

## Going further

- **Multiple Agents / private network / production**: [docs/DEPLOYMENT.md](DEPLOYMENT.md)
  (run `deploy/install.sh agent` on each host, then `deploy/install.sh controller`).
- **Network options** (overlay, VPC, SSH tunnel; Tailscale optional): [docs/PRIVATE-NETWORKING.md](PRIVATE-NETWORKING.md)
- **API / security / verification**: [docs/API.md](API.md), [SECURITY.md](../SECURITY.md), [docs/VERIFICATION.md](VERIFICATION.md)
