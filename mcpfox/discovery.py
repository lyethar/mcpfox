"""Local MCP config file discovery and parsing."""

import json
import os
from pathlib import Path

COMMON_CONFIG_PATHS: dict[str, Path] = {
    "Claude Desktop (Win)": Path(os.environ.get("APPDATA", ""), "Claude", "claude_desktop_config.json"),
    "Claude Desktop (Mac)": Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    "Claude Code project":  Path(".claude") / "settings.json",
    "Claude Code user (Win)": Path(os.environ.get("APPDATA", ""), "Claude") / "settings.json",
    "VS Code MCP":   Path.home() / ".vscode" / "mcp.json",
    "Cursor":        Path.home() / ".cursor" / "mcp.json",
    "Windsurf":      Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    "Zed":           Path.home() / ".config" / "zed" / "settings.json",
}


def discover_local_configs() -> dict[str, str]:
    return {label: str(path) for label, path in COMMON_CONFIG_PATHS.items() if path.exists()}


def extract_mcp_servers_from_config(path: str) -> list[dict]:
    servers: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        return [{"error": str(e)}]

    def _parse_entry(name: str, cfg: dict) -> dict:
        server: dict = {"name": name, "type": "unknown"}
        if "url" in cfg:
            server["type"] = "http"
            server["url"] = cfg["url"]
        elif "command" in cfg:
            server["type"] = "stdio"
            server["command"] = cfg["command"]
            server["args"] = cfg.get("args", [])
            server["env"] = cfg.get("env", {})
        return server

    # Claude Desktop / Claude Code format
    for name, cfg in data.get("mcpServers", {}).items():
        servers.append(_parse_entry(name, cfg))

    # VS Code / Cursor format
    for name, cfg in data.get("servers", {}).items():
        servers.append(_parse_entry(name, cfg))

    return servers
