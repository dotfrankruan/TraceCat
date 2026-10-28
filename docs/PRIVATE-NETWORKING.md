# Private Networking

TraceCat needs one thing from the network: **the Controller must be able to
reach each Agent's configured `listen` address and port, and nothing else should
be able to.** Any private network technology that provides that is fine.

Tailscale is a convenient default because it gives every host a stable private
address and encrypts transport, but it is **not required**, and TraceCat does
not use Tailscale tags, ACL tags or MagicDNS features. The Agent simply binds
the explicit address in its config; it fails startup if that address is missing
or is a wildcard.

## Supported topologies

| Topology | Notes |
| --- | --- |
| **WireGuard / Tailscale / Nebula / ZeroTier overlay** | Recommended for distributed vantage points. Bind the Agent to its overlay address (e.g. `100.x.y.z` or `fd00::x`); restrict Controller→Agent port 8443 at the overlay/firewall layer. No tags are needed; ordinary device ACLs or firewall rules are sufficient. |
| **Cloud private VPC / private subnet** | Bind the Agent to the instance's private IP and allow the Controller's private IP on the Agent port via security groups. Keep the port closed to the internet. |
| **Same host / loopback** | Useful for a local demo or a single-vantage deployment: Controller and Agent both bind `127.0.0.1`. |
| **SSH tunnel** | For low-volume or bastion-only setups: `ssh -N -L 8443:127.0.0.1:8443 controller-host` on the Controller, Agent config `listen: 127.0.0.1:8443`. The tunnel carries the bearer token inside SSH. |
| **HTTPS reverse proxy / sidecar** | If the Agent is not on an overlay, terminate TLS in front of it and use `https://` Agent URLs. TraceCat accepts cleartext `http://` only for non-public addresses; public Agent URLs must be `https://`. |

## Requirements

1. **Explicit bind address.** `agent.json` → `"listen": "<private-ip>:<port>"`.
   Wildcards (`0.0.0.0`, `::`) and unassigned addresses are refused at startup.
2. **No public exposure.** By default the Agent rejects a globally routable
   bind address. `security.allow_public_bind: true` exists only for carefully
   firewalled/TLS-fronted deployments and logs a warning.
3. **Application authorization is separate.** Network reachability is not
   authentication: every request still needs that Agent's bearer token
   (`/etc/tracecat/agent.env`, mode `0600`). Use a different token per Agent.
4. **Restrict the port.** Allow only the Controller host to reach the Agent
   port. Example firewall rules (adapt names/addresses):

   ```bash
   # nftables on an Agent
   nft add rule inet filter input tcp dport 8443 ip saddr 10.0.0.10 accept
   nft add rule inet filter input tcp dport 8443 drop

   # ufw
   ufw allow from 10.0.0.10 to any port 8443 proto tcp
   ufw deny 8443/tcp
   ```

5. **TLS where the network is not already encrypted.** On an overlay/VPC the
   transport is encrypted in transit. If traffic crosses a shared or untrusted
   path, put HTTPS in front of the Agent and configure `https://` URLs on the
   Controller (the Controller refuses cleartext to public IPs and any hostname).

## Verification

From the Controller host:

```bash
# 401 without the token proves the Agent is reachable and enforcing auth
curl -s -o /dev/null -w '%{http_code}\n' http://<agent-private-ip>:8443/v1/health

# 200 for the authenticated health check
TOKEN="$(grep '^TRACECAT_AGENT_TOKEN=' /etc/tracecat/agent.env | cut -d= -f2-)" # on the Agent host
curl -fsS -H "Authorization: Bearer $TOKEN" http://<agent-private-ip>:8443/v1/health
```

On the Agent host, `ss -ltnp | grep 8443` must show **only** the configured
private address — never `0.0.0.0` or `::`.

## What TraceCat intentionally does not do

- No automatic node discovery, registration or peer-to-peer Agent traffic.
- No Tailscale API calls, tag management or MagicDNS dependency.
- No inbound connections from Agents to the Controller.
- No public listener by default and no self-update.
