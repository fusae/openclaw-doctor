---
name: claw-doctor
description: Audit a local OpenClaw installation for security exposure and hardening gaps, then recommend concrete mitigations. Use when a user asks to review OpenClaw safety, reduce OpenClaw risk, check exposed ports, tighten permissions, inspect OpenClaw config, or harden a host running OpenClaw.
homepage: https://github.com/fusae/openclaw-doctor
user-invocable: true
metadata: {"openclaw":{"skillKey":"claw-doctor","homepage":"https://github.com/fusae/openclaw-doctor","requires":{"bins":["python3"]}}}
---

# Claw Doctor

Inspect the current host for OpenClaw-specific security risks and produce a prioritized hardening plan. Prefer the bundled audit script so the review is consistent and host-level checks are combined with the official OpenClaw security audit.

## Workflow

1. Run `{baseDir}/scripts/audit_openclaw_host.py` on the gateway host.
2. Read the findings in severity order: `critical`, `high`, `medium`, `low`, `info`.
3. Cross-check fixes in `{baseDir}/references/remediation-matrix.md`.
4. Present a short report with:
   - what was detected
   - the top risks
   - exact config or permission changes to reduce risk
   - any commands that would mutate the system

## Quick Start

Run the bundled script first:

```bash
python3 {baseDir}/scripts/audit_openclaw_host.py
```

Use JSON when another tool or follow-up script will consume the results:

```bash
python3 {baseDir}/scripts/audit_openclaw_host.py --format json
```

## What The Script Checks

- Whether `openclaw` is installed and which config/state paths are active.
- Official CLI findings from `openclaw security audit --deep --json` when available.
- Optional CLI findings from `openclaw secrets audit --json` and `openclaw plugins list --json`.
- Host exposure such as listening sockets and Docker port publishing.
- Remote-access posture such as whether a local reverse proxy, TLS terminator, or private tunnel is evident.
- Host controls such as firewall status and whether OpenClaw auto-starts at boot.
- Local filesystem permissions for the state directory, config, approvals file, credentials, and session/auth state.
- Shell startup files that appear to contain plaintext API keys or OpenClaw secrets.
- High-impact config posture such as gateway bind mode, auth mode, mDNS/Bonjour mode, sandbox mode, workspace access, and elevated exec availability.

## Operating Rules

- Prefer read-only inspection first.
- Do not run `openclaw security audit --fix`, `openclaw doctor --fix`, or edit config unless the user asked for remediation.
- Treat non-loopback listeners, wildcard ingress, weak file permissions, disabled sandboxing, and broad elevated exec as the highest-value items to explain first.
- Treat reverse-proxy, tunnel, and firewall findings as heuristics. Phrase them as host observations, not proof of internet exposure.
- If the official audit already reports a risk, do not restate it with different wording unless you are adding host-specific evidence or a clearer remediation.
- When OpenClaw is not installed, report that clearly and stop after light discovery. Do not guess paths or fabricate risks.
- Assume the skill is running on the OpenClaw gateway host unless the user explicitly asks to inspect a remote node.

## Reporting Pattern

Use a compact structure:

1. Detection summary
2. Findings ordered by severity
3. Recommended fixes ordered by blast-radius reduction
4. Mutating commands that require approval

Keep remediation concrete. Good examples:

- Bind the Gateway back to loopback and expose it only through a trusted tunnel.
- Change `~/.openclaw` to `700` and `openclaw.json` to `600`.
- Move from `sandbox.mode="off"` to `sandbox.mode="non-main"` or `all`.
- Disable mDNS or keep it at `minimal` instead of `full`.
- Remove or review enabled plugins that widen the available tool surface.
- Move plaintext secrets out of shell startup files.
- If the service auto-starts, harden it before keeping that persistence.

## References

- Read `{baseDir}/references/remediation-matrix.md` for fix mapping and suggested commands.
