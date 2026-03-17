#!/usr/bin/env python3
"""Inspect a local machine for OpenClaw security risks."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def run_command(cmd: list[str], timeout: int = 15) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return {
            "ok": False,
            "code": None,
            "stdout": "",
            "stderr": f"command not found: {cmd[0]}",
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "code": None,
            "stdout": "",
            "stderr": f"command timed out after {timeout}s",
        }

    return {
        "ok": proc.returncode == 0,
        "code": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def normalize_scalar(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text


def parse_json_maybe(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def first_existing_path(text: str | None) -> str | None:
    if not text:
        return None
    for line in text.splitlines():
        candidate = line.strip()
        if candidate.startswith("~"):
            candidate = str(Path(candidate).expanduser())
        if candidate.startswith("/"):
            return candidate
    return None


def mode_string(path: Path) -> str | None:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except FileNotFoundError:
        return None


def permissive_mode(path: Path, expected: int) -> bool:
    try:
        current = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        return False
    return current & ~expected != 0


def add_finding(
    findings: list[dict[str, Any]],
    finding_id: str,
    severity: str,
    summary: str,
    evidence: str,
    remediation: str,
    source: str,
) -> None:
    findings.append(
        {
            "id": finding_id,
            "severity": severity,
            "summary": summary,
            "evidence": evidence,
            "remediation": remediation,
            "source": source,
        }
    )


def extract_cli_findings(payload: Any, source: str) -> list[dict[str, Any]]:
    extracted: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return

        if not isinstance(node, dict):
            return

        severity = node.get("severity")
        if isinstance(severity, str):
            level = severity.strip().lower()
            if level in SEVERITY_ORDER:
                summary = (
                    node.get("summary")
                    or node.get("message")
                    or node.get("title")
                    or node.get("description")
                    or node.get("code")
                    or node.get("id")
                )
                if isinstance(summary, str) and summary.strip():
                    extracted.append(
                        {
                            "id": str(node.get("code") or node.get("id") or summary).strip(),
                            "severity": level,
                            "summary": summary.strip(),
                            "evidence": str(
                                node.get("detail")
                                or node.get("evidence")
                                or node.get("path")
                                or ""
                            ).strip(),
                            "remediation": str(
                                node.get("remediation")
                                or node.get("fix")
                                or node.get("suggestion")
                                or ""
                            ).strip(),
                            "source": source,
                        }
                    )

        for value in node.values():
            walk(value)

    walk(payload)
    return extracted


def config_get(openclaw_bin: str, path: str) -> str | None:
    result = run_command([openclaw_bin, "config", "get", path])
    if not result["ok"]:
        return None
    return normalize_scalar(result["stdout"])


def discover_listeners() -> list[dict[str, str]]:
    lsof_bin = shutil.which("lsof")
    if not lsof_bin:
        return []

    result = run_command([lsof_bin, "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=10)
    if not result["ok"] or not result["stdout"]:
        return []

    lines = result["stdout"].splitlines()
    if not lines:
        return []

    listeners: list[dict[str, str]] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        listeners.append(
            {
                "command": parts[0],
                "pid": parts[1],
                "user": parts[2],
                "name": parts[-1],
            }
        )
    return listeners


def discover_docker() -> list[dict[str, str]]:
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return []

    result = run_command([docker_bin, "ps", "--format", "{{json .}}"], timeout=10)
    if not result["ok"] or not result["stdout"]:
        return []

    containers: list[dict[str, str]] = []
    for line in result["stdout"].splitlines():
        item = parse_json_maybe(line)
        if not isinstance(item, dict):
            continue
        containers.append(
            {
                "id": str(item.get("ID", "")),
                "image": str(item.get("Image", "")),
                "name": str(item.get("Names", "")),
                "ports": str(item.get("Ports", "")),
            }
        )
    return containers


def discover_processes() -> list[dict[str, str]]:
    ps_bin = shutil.which("ps")
    if not ps_bin:
        return []

    result = run_command([ps_bin, "ax", "-o", "pid=", "-o", "command="], timeout=10)
    if not result["ok"] or not result["stdout"]:
        return []

    processes: list[dict[str, str]] = []
    for line in result["stdout"].splitlines():
        entry = line.strip()
        if not entry:
            continue
        parts = entry.split(None, 1)
        if len(parts) != 2:
            continue
        processes.append({"pid": parts[0], "command": parts[1]})
    return processes


def discover_autostart_entries() -> list[str]:
    entries: list[str] = []
    home = Path.home()

    candidate_dirs = [
        home / "Library" / "LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        home / ".config" / "systemd" / "user",
        home / ".local" / "share" / "systemd" / "user",
        Path("/etc/systemd/system"),
        Path("/usr/lib/systemd/system"),
        Path("/lib/systemd/system"),
    ]

    for directory in candidate_dirs:
        if not directory.exists():
            continue
        for child in directory.iterdir():
            if "openclaw" in child.name.lower():
                entries.append(str(child))

    systemctl_bin = shutil.which("systemctl")
    if systemctl_bin:
        result = run_command(
            [systemctl_bin, "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
            timeout=15,
        )
        if result["ok"] and result["stdout"]:
            for line in result["stdout"].splitlines():
                if "openclaw" in line.lower():
                    entries.append(line.strip())

    launchctl_bin = shutil.which("launchctl")
    if launchctl_bin:
        result = run_command([launchctl_bin, "list"], timeout=10)
        if result["ok"] and result["stdout"]:
            for line in result["stdout"].splitlines():
                if "openclaw" in line.lower():
                    entries.append(line.strip())

    return sorted(set(entries))


def discover_tailscale() -> dict[str, Any]:
    tailscale_bin = shutil.which("tailscale")
    if not tailscale_bin:
        return {"installed": False, "ok": False, "tailscale_ips": []}

    result = run_command([tailscale_bin, "status", "--json"], timeout=15)
    payload = parse_json_maybe(result["stdout"])
    ips: list[str] = []
    if isinstance(payload, dict):
        self_info = payload.get("Self")
        if isinstance(self_info, dict):
            for key in ("TailscaleIPs", "tailscaleIPs"):
                values = self_info.get(key)
                if isinstance(values, list):
                    ips.extend(str(value) for value in values)
    return {
        "installed": True,
        "ok": result["ok"] and bool(payload),
        "tailscale_ips": ips,
        "stderr": result["stderr"],
    }


def discover_firewall_status() -> dict[str, Any]:
    status: dict[str, Any] = {"detected": [], "active": []}

    socketfilterfw = Path("/usr/libexec/ApplicationFirewall/socketfilterfw")
    if socketfilterfw.exists():
        result = run_command([str(socketfilterfw), "--getglobalstate"], timeout=10)
        if result["stdout"]:
            status["detected"].append("socketfilterfw")
            if re.search(r"enabled", result["stdout"], re.IGNORECASE):
                status["active"].append("socketfilterfw")

    pfctl_bin = shutil.which("pfctl")
    if pfctl_bin:
        result = run_command([pfctl_bin, "-s", "info"], timeout=10)
        if result["stdout"]:
            status["detected"].append("pfctl")
            if re.search(r"status:\s*enabled", result["stdout"], re.IGNORECASE):
                status["active"].append("pfctl")

    ufw_bin = shutil.which("ufw")
    if ufw_bin:
        result = run_command([ufw_bin, "status"], timeout=10)
        if result["stdout"]:
            status["detected"].append("ufw")
            if re.search(r"status:\s*active", result["stdout"], re.IGNORECASE):
                status["active"].append("ufw")

    firewall_cmd_bin = shutil.which("firewall-cmd")
    if firewall_cmd_bin:
        result = run_command([firewall_cmd_bin, "--state"], timeout=10)
        if result["stdout"] or result["stderr"]:
            status["detected"].append("firewalld")
            if result["stdout"].strip().lower() == "running":
                status["active"].append("firewalld")

    nft_bin = shutil.which("nft")
    if nft_bin:
        result = run_command([nft_bin, "list", "ruleset"], timeout=10)
        if result["stdout"] or result["stderr"]:
            status["detected"].append("nftables")
            if result["ok"] and result["stdout"].strip():
                status["active"].append("nftables")

    status["detected"] = sorted(set(status["detected"]))
    status["active"] = sorted(set(status["active"]))
    return status


def scan_shell_secret_files() -> list[dict[str, str]]:
    home = Path.home()
    candidates = [
        home / ".zshrc",
        home / ".zprofile",
        home / ".zshenv",
        home / ".bashrc",
        home / ".bash_profile",
        home / ".profile",
    ]
    var_pattern = re.compile(
        r"\b("
        r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|OPENROUTER_API_KEY|"
        r"MISTRAL_API_KEY|XAI_API_KEY|AZURE_OPENAI_API_KEY|"
        r"OPENCLAW_[A-Z0-9_]*(TOKEN|KEY|SECRET|PASSWORD)"
        r")\b"
    )

    hits: list[dict[str, str]] = []
    for path in candidates:
        if not path.exists():
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue

        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                continue
            if not var_pattern.search(stripped):
                continue
            if "$(" in stripped or "`" in stripped:
                continue
            preview = stripped
            if len(preview) > 120:
                preview = preview[:117] + "..."
            hits.append(
                {
                    "path": str(path),
                    "line": str(number),
                    "preview": preview,
                }
            )
    return hits


def is_loopback_listener(name: str) -> bool:
    return bool(re.search(r"(127\.0\.0\.1|localhost|\[::1\])", name))


def listener_matches_port(name: str, ports: set[str]) -> bool:
    return any(re.search(rf":{re.escape(port)}(?:\D|$)", name) for port in ports if port)


def published_broadly(ports: str) -> bool:
    return bool(re.search(r"(0\.0\.0\.0:|\[::\]:|:::)", ports))


def has_openclaw_exposure(findings: list[dict[str, Any]]) -> bool:
    risky_ids = {
        "gateway-bind-exposed",
        "live-listener-non-loopback",
        "docker-published-port",
    }
    return any(item["id"] in risky_ids for item in findings)


def high_impact_findings_present(findings: list[dict[str, Any]]) -> bool:
    return any(item["severity"] in {"critical", "high"} for item in findings)


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_ORDER}
    for item in findings:
        severity = item["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def sort_and_dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in findings:
        key = (item["severity"], item["id"], item["summary"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    deduped.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["summary"].lower()))
    return deduped


def render_text(report: dict[str, Any]) -> str:
    lines = []
    openclaw = report["openclaw"]
    summary = report["summary"]

    lines.append("OpenClaw host audit")
    lines.append(f"Detected: {'yes' if openclaw['detected'] else 'no'}")
    if openclaw.get("binary"):
        lines.append(f"Binary: {openclaw['binary']}")
    if openclaw.get("version"):
        lines.append(f"Version: {openclaw['version']}")
    if openclaw.get("config_file"):
        lines.append(f"Config: {openclaw['config_file']}")
    if openclaw.get("state_dir"):
        lines.append(f"State dir: {openclaw['state_dir']}")
    lines.append(
        "Summary: "
        + ", ".join(f"{severity}={summary[severity]}" for severity in SEVERITY_ORDER)
    )

    findings = report["findings"]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("")
    for item in findings:
        lines.append(f"[{item['severity']}] {item['summary']}")
        if item.get("evidence"):
            lines.append(f"  evidence: {item['evidence']}")
        if item.get("remediation"):
            lines.append(f"  fix: {item['remediation']}")
        lines.append(f"  source: {item['source']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a machine for OpenClaw security risks.")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    listeners = discover_listeners()
    docker_containers = discover_docker()
    processes = discover_processes()
    autostart_entries = discover_autostart_entries()
    tailscale_status = discover_tailscale()
    firewall_status = discover_firewall_status()
    shell_secret_hits = scan_shell_secret_files()
    openclaw_bin = shutil.which("openclaw")
    openclaw_info: dict[str, Any] = {
        "detected": bool(openclaw_bin),
        "binary": openclaw_bin,
        "version": None,
        "config_file": None,
        "state_dir": None,
        "commands": {},
        "autostart_entries": autostart_entries,
        "tailscale": tailscale_status,
        "firewall": firewall_status,
    }

    if openclaw_bin:
        version_result = run_command([openclaw_bin, "--version"])
        openclaw_info["commands"]["version"] = version_result
        if version_result["ok"]:
            openclaw_info["version"] = version_result["stdout"]

        config_file_result = run_command([openclaw_bin, "config", "file"])
        openclaw_info["commands"]["config_file"] = config_file_result
        config_file = first_existing_path(config_file_result["stdout"])
        if config_file:
            openclaw_info["config_file"] = config_file
            openclaw_info["state_dir"] = str(Path(config_file).expanduser().resolve().parent)

        if not openclaw_info["state_dir"]:
            state_dir_env = os.environ.get("OPENCLAW_STATE_DIR")
            if state_dir_env:
                openclaw_info["state_dir"] = str(Path(state_dir_env).expanduser())
            else:
                openclaw_info["state_dir"] = str(Path("~/.openclaw").expanduser())

        for name, cmd in (
            ("security_audit", [openclaw_bin, "security", "audit", "--deep", "--json"]),
            ("secrets_audit", [openclaw_bin, "secrets", "audit", "--json"]),
            ("plugins_list", [openclaw_bin, "plugins", "list", "--json"]),
        ):
            result = run_command(cmd, timeout=30)
            openclaw_info["commands"][name] = result
            payload = parse_json_maybe(result["stdout"])
            if result["ok"] and payload is not None:
                source = name.replace("_", "-")
                findings.extend(extract_cli_findings(payload, source))
                if name == "plugins_list" and isinstance(payload, list):
                    enabled = [
                        item
                        for item in payload
                        if isinstance(item, dict) and item.get("enabled") is not False
                    ]
                    if enabled:
                        add_finding(
                            findings,
                            "plugins-enabled",
                            "medium",
                            "Installed plugins widen the OpenClaw attack surface",
                            f"{len(enabled)} plugin(s) reported by openclaw plugins list --json",
                            "Review each enabled plugin and remove anything you do not actively trust and use.",
                            "plugins-list",
                        )
            elif not result["ok"] and name == "security_audit":
                add_finding(
                    findings,
                    "official-audit-unavailable",
                    "medium",
                    "The official OpenClaw security audit could not be executed",
                    result["stderr"] or "openclaw security audit --deep --json failed",
                    "Run the official audit manually after fixing the CLI or config, then compare results with this host scan.",
                    "host-scan",
                )

        bind = config_get(openclaw_bin, "gateway.bind")
        auth_mode = config_get(openclaw_bin, "gateway.auth.mode")
        port = config_get(openclaw_bin, "gateway.port") or "18789"
        mdns_mode = config_get(openclaw_bin, "discovery.mdns.mode")
        sandbox_mode = config_get(openclaw_bin, "agents.defaults.sandbox.mode")
        workspace_access = config_get(openclaw_bin, "agents.defaults.sandbox.workspaceAccess")
        tools_profile = config_get(openclaw_bin, "tools.profile")
        elevated_enabled = config_get(openclaw_bin, "tools.elevated.enabled")

        openclaw_info["bind"] = bind
        openclaw_info["auth_mode"] = auth_mode
        openclaw_info["port"] = port
        openclaw_info["mdns_mode"] = mdns_mode
        openclaw_info["sandbox_mode"] = sandbox_mode
        openclaw_info["workspace_access"] = workspace_access
        openclaw_info["tools_profile"] = tools_profile
        openclaw_info["elevated_enabled"] = elevated_enabled

        if bind and bind not in {"loopback", "local"}:
            severity = "critical" if not auth_mode or auth_mode in {"off", "none", "disabled"} else "high"
            add_finding(
                findings,
                "gateway-bind-exposed",
                severity,
                "Gateway is configured beyond loopback",
                f"gateway.bind={bind}, gateway.auth.mode={auth_mode or 'unset'}, gateway.port={port}",
                "Bind the Gateway to loopback unless remote access is required. If it must stay exposed, require token or password auth and place it behind a trusted tunnel or proxy.",
                "config",
            )

        if mdns_mode == "full":
            add_finding(
                findings,
                "mdns-full",
                "medium",
                "mDNS is configured in full mode",
                "discovery.mdns.mode=full",
                "Use discovery.mdns.mode=minimal or off to avoid broadcasting extra host metadata.",
                "config",
            )

        if sandbox_mode == "off":
            add_finding(
                findings,
                "sandbox-off",
                "high",
                "Sandboxing is disabled",
                "agents.defaults.sandbox.mode=off",
                "Use sandbox.mode=non-main as a baseline, or all for higher-risk deployments.",
                "config",
            )

        if workspace_access == "rw":
            add_finding(
                findings,
                "sandbox-workspace-rw",
                "medium",
                "Sandboxed sessions can write into the host workspace",
                "agents.defaults.sandbox.workspaceAccess=rw",
                "Prefer workspaceAccess=none or ro unless the agent must write back into the host workspace.",
                "config",
            )

        if tools_profile in {None, "", "full"}:
            add_finding(
                findings,
                "tools-profile-broad",
                "medium",
                "Tool profile appears broad or unrestricted",
                f"tools.profile={tools_profile or 'unset'}",
                "Use a narrower base profile and explicitly allow only the tools you need.",
                "config",
            )

        if elevated_enabled == "true":
            add_finding(
                findings,
                "elevated-enabled",
                "medium",
                "Elevated exec is enabled",
                "tools.elevated.enabled=true",
                "Disable elevated exec unless trusted operators need it, and keep approvals enabled with tight allowlists.",
                "config",
            )

    else:
        default_state_dir = Path(os.environ.get("OPENCLAW_STATE_DIR", "~/.openclaw")).expanduser()
        if default_state_dir.exists():
            openclaw_info["state_dir"] = str(default_state_dir)
            openclaw_info["detected"] = True
        else:
            add_finding(
                findings,
                "openclaw-not-detected",
                "info",
                "OpenClaw was not detected on this machine",
                "No openclaw binary in PATH and no default state directory found",
                "Install OpenClaw first or point the audit at the correct profile before evaluating security posture.",
                "host-scan",
            )

    state_dir = Path(openclaw_info["state_dir"]).expanduser() if openclaw_info.get("state_dir") else None
    config_file = Path(openclaw_info["config_file"]).expanduser() if openclaw_info.get("config_file") else None

    if state_dir and state_dir.exists():
        if permissive_mode(state_dir, 0o700):
            add_finding(
                findings,
                "state-dir-permissions",
                "high",
                "OpenClaw state directory permissions are broader than 700",
                f"{state_dir} mode={mode_string(state_dir)}",
                f"Run chmod 700 {state_dir}",
                "filesystem",
            )

        sensitive_paths = [
            state_dir / "exec-approvals.json",
            state_dir / "credentials",
        ]

        if config_file and config_file.exists() and permissive_mode(config_file, 0o600):
            add_finding(
                findings,
                "config-file-permissions",
                "high",
                "OpenClaw config permissions are broader than 600",
                f"{config_file} mode={mode_string(config_file)}",
                f"Run chmod 600 {config_file}",
                "filesystem",
            )

        for base in sensitive_paths:
            if base.is_file() and permissive_mode(base, 0o600):
                add_finding(
                    findings,
                    f"sensitive-file-{base.name}",
                    "high",
                    "Sensitive OpenClaw state file permissions are too broad",
                    f"{base} mode={mode_string(base)}",
                    f"Run chmod 600 {base}",
                    "filesystem",
                )
            if base.is_dir():
                for child in base.rglob("*.json"):
                    if permissive_mode(child, 0o600):
                        add_finding(
                            findings,
                            "credentials-permissions",
                            "high",
                            "Credential or state JSON files are readable beyond the current user",
                            f"{child} mode={mode_string(child)}",
                            f"Run chmod 600 {child}",
                            "filesystem",
                        )

        agents_dir = state_dir / "agents"
        if agents_dir.exists():
            for child in agents_dir.rglob("*"):
                if child.is_file() and child.name in {"auth-profiles.json", "sessions.json"}:
                    if permissive_mode(child, 0o600):
                        add_finding(
                            findings,
                            f"{child.name}-permissions",
                            "high",
                            "Agent auth or session state permissions are too broad",
                            f"{child} mode={mode_string(child)}",
                            f"Run chmod 600 {child}",
                            "filesystem",
                        )

    candidate_ports = {"18789"}
    if openclaw_info.get("port"):
        candidate_ports.add(str(openclaw_info["port"]))

    for listener in listeners:
        name = listener["name"]
        command = listener["command"].lower()
        if "openclaw" not in command and not listener_matches_port(name, candidate_ports):
            continue
        if is_loopback_listener(name):
            continue
        add_finding(
            findings,
            "live-listener-non-loopback",
            "high",
            "A live OpenClaw-related listener appears reachable beyond loopback",
            f"{listener['command']} pid={listener['pid']} listening on {listener['name']}",
            "Bind the Gateway to loopback or publish the port only on a trusted private interface.",
            "network",
        )

    for container in docker_containers:
        descriptor = f"{container['name']} ({container['image']})"
        match_text = " ".join(container.values()).lower()
        if "openclaw" not in match_text:
            continue
        ports = container["ports"]
        if published_broadly(ports):
            add_finding(
                findings,
                "docker-published-port",
                "high",
                "An OpenClaw container publishes ports broadly",
                f"{descriptor} ports={ports}",
                "Publish the Gateway port to 127.0.0.1 only, or keep it on a private container network.",
                "docker",
            )
        elif ports:
            add_finding(
                findings,
                "docker-openclaw-present",
                "info",
                "OpenClaw appears to be running in Docker",
                f"{descriptor} ports={ports}",
                "Confirm the published ports and network mode match your intended exposure.",
                "docker",
            )

    exposure_present = has_openclaw_exposure(findings)
    proxy_commands = ("nginx", "caddy", "traefik", "haproxy", "httpd", "apache2", "envoy")
    proxy_evidence = []
    for listener in listeners:
        command = listener["command"].lower()
        if any(command.startswith(proxy) or f"/{proxy}" in command for proxy in proxy_commands):
            proxy_evidence.append(listener["name"])
            continue
        if listener_matches_port(listener["name"], {"80", "443"}) and any(
            marker in command for marker in proxy_commands
        ):
            proxy_evidence.append(listener["name"])
    tunnel_evidence = []
    for process in processes:
        raw_command = process["command"]
        command = raw_command.lower()
        if "cloudflared" in command or "tailscaled" in command or "tailscale " in command:
            tunnel_evidence.append(process["command"])
            continue
        if "ssh " in raw_command and (" -L " in raw_command or " -R " in raw_command):
            tunnel_evidence.append(process["command"])

    if exposure_present and not proxy_evidence:
        add_finding(
            findings,
            "no-local-reverse-proxy",
            "medium",
            "No local reverse proxy or TLS terminator was detected for an exposed OpenClaw service",
            "OpenClaw appears exposed beyond loopback and no common proxy listener was found on this host",
            "If the service is intended to be remote, put it behind Caddy, Nginx, Traefik, or another trusted TLS-terminating proxy.",
            "network",
        )

    if exposure_present and not tunnel_evidence and not tailscale_status["tailscale_ips"]:
        add_finding(
            findings,
            "no-private-tunnel-detected",
            "medium",
            "No private access tunnel was detected for a remotely reachable OpenClaw service",
            "No active Tailscale identity, SSH forwarding process, or cloudflared-style tunnel was detected locally",
            "Prefer Tailscale, SSH forwarding, or a similarly private access path over direct public or broad LAN exposure.",
            "network",
        )

    if exposure_present and firewall_status["detected"] and not firewall_status["active"]:
        add_finding(
            findings,
            "firewall-inactive",
            "medium",
            "OpenClaw appears exposed while the host firewall looks inactive",
            f"Detected firewall tooling: {', '.join(firewall_status['detected'])}; active: none",
            "Enable a host firewall or add interface-scoped allow rules so the Gateway is reachable only from intended peers.",
            "network",
        )

    if openclaw_info["detected"] and shell_secret_hits:
        preview = ", ".join(
            f"{item['path']}:{item['line']}" for item in shell_secret_hits[:3]
        )
        add_finding(
            findings,
            "shell-rc-plain-secrets",
            "medium",
            "Sensitive API keys or OpenClaw secrets appear to be stored in shell startup files",
            preview,
            "Move persistent secrets into a dedicated secret manager, OS keychain, or a file with tighter access controls than shell profile files.",
            "filesystem",
        )

    if autostart_entries and high_impact_findings_present(findings):
        add_finding(
            findings,
            "autostart-persistent-risk",
            "medium",
            "OpenClaw appears to auto-start while higher-risk findings are present",
            ", ".join(autostart_entries[:3]),
            "Fix the high-severity exposure first, then keep autostart only if the service must survive reboots in that hardened state.",
            "service",
        )

    findings = sort_and_dedupe(findings)
    report = {
        "openclaw": openclaw_info,
        "summary": summarize(findings),
        "findings": findings,
    }

    if args.format == "json":
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(report) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
