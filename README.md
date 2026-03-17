# OpenClaw Doctor

Security audit and hardening skill for OpenClaw installations, covering network exposure, permissions, sandboxing, plugins, and host-level risks.

## What It Does

`claw-doctor` is a Codex skill that inspects a local or self-hosted OpenClaw installation and produces a prioritized hardening report.

It combines:

- Official `openclaw security audit` findings when available
- Host-level checks that the official audit may not fully cover
- Concrete remediation guidance for reducing exposure

## What It Checks

- OpenClaw installation, version, config file, and state directory
- `openclaw security audit --deep --json`
- `openclaw secrets audit --json`
- `openclaw plugins list --json`
- Gateway bind mode, auth mode, and port exposure
- mDNS / Bonjour discovery posture
- Sandbox mode and workspace access
- Elevated exec and broad tool profiles
- Live listening sockets and Docker-published ports
- State directory, config, credentials, approvals, and session file permissions
- Reverse proxy / TLS terminator heuristics
- Tailscale / SSH tunnel / cloudflared-style private access heuristics
- Host firewall activity heuristics
- Auto-start persistence when higher-risk findings are present
- Plaintext API keys or OpenClaw secrets in shell startup files

## Repository Layout

```text
claw-doctor/
  SKILL.md
  agents/openai.yaml
  references/remediation-matrix.md
  scripts/audit_openclaw_host.py
```

## Install

Copy the `claw-doctor` folder into your Codex skills directory:

```bash
cp -R claw-doctor "$CODEX_HOME/skills/"
```

Or symlink it during development:

```bash
ln -s "$(pwd)/claw-doctor" "$CODEX_HOME/skills/claw-doctor"
```

## Use

From Codex, invoke the skill by name or ask for an OpenClaw security review.

You can also run the bundled audit script directly:

```bash
./claw-doctor/scripts/audit_openclaw_host.py
```

JSON output:

```bash
./claw-doctor/scripts/audit_openclaw_host.py --format json
```

## Output

The audit reports:

1. Detection summary
2. Findings ordered by severity
3. Concrete hardening recommendations
4. Commands that would mutate the host, when relevant

## Design Rules

- Read-only inspection first
- No automatic `--fix` execution
- Prioritize blast-radius reduction
- Avoid duplicating official audit findings unless host evidence adds value

## Limits

- Reverse proxy, tunnel, and firewall checks are heuristics
- The skill does not auto-remediate unless explicitly asked
- Some checks depend on the local platform and available commands
