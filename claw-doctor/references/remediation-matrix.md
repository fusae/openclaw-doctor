# Remediation Matrix

Use this file after the audit script identifies concrete findings. Prefer the smallest change that meaningfully reduces blast radius.

## Highest-value fixes

### Gateway reachable beyond loopback

Risk:
- Anyone who can reach the Gateway port gets a chance to probe or authenticate against it.
- If auth is weak or misconfigured, exposure becomes much worse.

Preferred fixes:
- Set `gateway.bind` back to `loopback` unless remote access is truly required.
- If remote access is required, require token or password auth before exposing the port.
- Put remote access behind Tailscale, SSH forwarding, or a trusted reverse proxy.

Example config snippet:

```json5
{
  gateway: {
    bind: "loopback",
    auth: {
      mode: "token",
      token: "replace-me",
    },
  },
}
```

### Loose state or config permissions

Risk:
- Local users or backup agents may read config, approvals, credentials, or session artifacts.

Preferred fixes:

```bash
chmod 700 ~/.openclaw
chmod 600 ~/.openclaw/openclaw.json
chmod 600 ~/.openclaw/exec-approvals.json
find ~/.openclaw/credentials -type f -name '*.json' -exec chmod 600 {} +
find ~/.openclaw/agents -type f \( -name 'auth-profiles.json' -o -name 'sessions.json' \) -exec chmod 600 {} +
```

### Sandbox disabled

Risk:
- Runtime and filesystem tools execute directly on the host.
- Prompt-injection or operator mistakes have full host impact.

Preferred fixes:
- Move to `agents.defaults.sandbox.mode: "non-main"` as a practical baseline.
- Use `"all"` when the bot is exposed to untrusted or mixed-trust senders.
- Keep `workspaceAccess` at `"none"` or `"ro"` unless write access is necessary.

Example config snippet:

```json5
{
  agents: {
    defaults: {
      sandbox: {
        mode: "non-main",
        workspaceAccess: "ro",
      },
    },
  },
}
```

### Elevated exec broadly available

Risk:
- Elevated exec can bypass sandbox protections and run on the host.
- `full` approval posture is especially risky.

Preferred fixes:
- Disable elevated exec unless a trusted operator workflow needs it.
- Keep approvals enabled and use allowlists instead of blanket approval.
- Restrict `tools.elevated.allowFrom` to specific trusted operators.

### mDNS / Bonjour metadata leakage

Risk:
- LAN observers can learn the Gateway port and, in `full` mode, additional host details.

Preferred fixes:
- Set `discovery.mdns.mode` to `"minimal"` or `"off"`.
- Set `OPENCLAW_DISABLE_BONJOUR=1` when discovery is not needed.

Example config snippet:

```json5
{
  discovery: {
    mdns: { mode: "off" },
  },
}
```

## Secondary fixes

### Enabled plugins

Risk:
- Plugins can add tools, RPC surfaces, and secrets handling paths.

Preferred fixes:
- Remove plugins you do not actively use.
- Review each enabled plugin before keeping it on an internet- or LAN-exposed gateway.

### Docker-published ports

Risk:
- Containerized deployments often publish `0.0.0.0:18789` by accident.

Preferred fixes:
- Publish to `127.0.0.1` only, or remove the published port and reach the container through a private network.
- If using Compose, prefer `127.0.0.1:18789:18789` over `18789:18789`.

### Missing reverse proxy or TLS terminator

Risk:
- A directly exposed Gateway often ends up without TLS, request filtering, or rate-limiting.

Preferred fixes:
- Terminate TLS with Caddy, Nginx, Traefik, or another trusted proxy.
- Keep OpenClaw on loopback behind the proxy whenever possible.
- If TLS termination lives on another host, document that architecture so operators do not misread the exposure.

### No private tunnel for remote access

Risk:
- Direct LAN or public exposure is usually broader than intended for a personal agent.

Preferred fixes:
- Prefer Tailscale, SSH forwarding, or another authenticated private-access path.
- If a public endpoint is required, combine it with TLS, strong auth, and host firewall rules.

### Firewall inactive on an exposed host

Risk:
- Even a correctly configured app can be reached from more networks than intended if the host allows broad ingress.

Preferred fixes:
- Enable the host firewall and scope ingress to trusted peers or interfaces only.
- On Docker hosts, enforce the same policy at both the host and container-network layer.

### Auto-start with unresolved high-risk findings

Risk:
- Reboot persistence turns a weak configuration into a continuously available target.

Preferred fixes:
- Fix network exposure, auth, sandbox, and permissions before keeping LaunchAgent, LaunchDaemon, or systemd persistence.
- Disable the auto-start unit temporarily if the host is currently exposed.

### Plaintext secrets in shell startup files

Risk:
- Shell profile files are easy to over-share via backups, dotfiles repos, support bundles, or local multi-user access.

Preferred fixes:
- Move long-lived credentials into Keychain, 1Password CLI, `pass`, or another secret manager.
- If a file must be used, keep it outside shell startup files and lock it down to `600`.
- Avoid exporting secrets from files that are synced into Git or cloud backup by default.

## Mutation guardrails

Do not auto-run these without approval:

- `openclaw security audit --fix`
- `openclaw doctor --fix`
- Direct edits to `~/.openclaw/openclaw.json`
- Permission changes that affect shared or multi-user environments
