# TraceCat Quick Start

TraceCat runs **one Controller and any number of Agents**. Agents register
themselves automatically — there is no machine list to maintain.

## 1. Controller (one host)

```bash
curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/install.sh -o /tmp/tc-install.sh
sudo bash /tmp/tc-install.sh controller \
  --auth local \
  --listen 10.0.0.10:8080 \
  --public-origin https://trace.example.com
```

- `--listen` is the private address Agents use to reach the Controller (an
  overlay/VPC address is ideal). The browser URL stays the HTTPS
  `--public-origin` (Cloudflare Tunnel/Access or a reverse proxy).
- Enrollment is **on by default**. The installer prints an enrollment token and
  the exact Agent command. Keep that token secret.

## 2. Agents (each additional host)

On every Agent host, with [NextTrace](https://github.com/nxtrace/NTrace-core)
installed:

```bash
TRACECAT_ENROLLMENT_TOKEN='<token printed by the Controller>' \
  sudo -E bash /tmp/tc-install.sh agent \
  --controller http://10.0.0.10:8080
```

That is all. The Agent dials the Controller, receives its own trace token, and
shows up automatically in the dashboard. Repeat on as many hosts as you want;
they appear without editing the Controller configuration or restarting it.
Agents re-register/refresh automatically.

Open the Controller URL, log in, then:

1. Enter `1.1.1.1` (or a domain) and press **Resolve**.
2. Pick the destination IP if more than one is offered.
3. Select one or more Agents, choose **ICMP**, **TCP** (port 443) or **UDP**
   (port 33494), and press **Start trace**.

## Single-host demo (optional)

To try everything on one machine without TLS or a private network:

```bash
curl -fsSL https://raw.githubusercontent.com/dotfrankruan/TraceCat/main/deploy/quickstart.sh | sudo bash
```

It installs a loopback-only Controller + Agent and prints a generated password
and URL. This is just a demo; the multi-Agent setup above is the normal
deployment.

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
| `Controller did not become healthy` | `journalctl -u tracecat-controller -n 50`; usually a port conflict or missing token env |
| Agent `listen address ... is not assigned` | the configured address is not on this host; use a real private IP or `127.0.0.1` for the demo |
| Agent never appears | check `journalctl -u tracecat-agent`; it needs outbound access to the `--controller` URL and the correct `TRACECAT_ENROLLMENT_TOKEN` |
| Probes fail with permission errors | grant `CAP_NET_RAW` to NextTrace (see `docs/DEPLOYMENT.md` §2.1) |
| `target_rejected` | only globally routable unicast is allowed by default; configure `security.allowed_cidrs` on Controller and Agent for lab ranges |
| Hops show **no reply** | common for intermediate routers; not proof of a broken route |

## Going further

- **Private networking options** (overlay, VPC, SSH tunnel; Tailscale optional): [docs/PRIVATE-NETWORKING.md](PRIVATE-NETWORKING.md)
- **Deployment reference / Cloudflare Access / systemd details**: [docs/DEPLOYMENT.md](DEPLOYMENT.md)
- **API / security / verification**: [docs/API.md](API.md), [SECURITY.md](../SECURITY.md), [docs/VERIFICATION.md](VERIFICATION.md)
