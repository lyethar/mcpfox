<p align="center">
  <img src="assets/mcpfox-banner.png" alt="MCPFox" width="800">
</p>

<p align="center">
  <strong>MCP server enumeration, interaction, and security analysis for penetration testers</strong>
</p>

---

## Features

- **Full capability enumeration** — tools, resources, resource templates, and prompts
- **Automated security analysis** — flags dangerous tool capabilities, injection surfaces, sensitive resources, and permissive schemas
- **Interactive REPL client** — call tools and read resources interactively, with Tab autocomplete for commands, tool names, and resource URIs
- **Resource downloading** — fetch every resource to a cataloged on-disk directory with a `manifest.json` inventory
- **HTML report** — self-contained dark-theme inventory report covering tools, resources, templates, prompts, and security findings
- **One-shot scripting** — call any tool or read any resource non-interactively for pipeline use
- **Config discovery** — finds MCP server definitions in Claude Desktop, Claude Code, VS Code, Cursor, Windsurf, and Zed config files
- **Port scanning** — probes a host for HTTP-accessible MCP endpoints across common ports
- **JSON reporting** — machine-readable output for integration with other tooling
- **Rich terminal output** — colour-coded tables and findings (degrades gracefully without `rich`)

---

## Installation

**From source (recommended for pentesting):**

```bash
git clone https://github.com/yourhandle/mcp-enum.git
cd mcp-enum
pip install -e .
```

**Dependencies only (without installing):**

```bash
pip install -r requirements.txt
python -m mcp_enum --help
```

**Requirements:** Python 3.10+

---

## Quick Start

```bash
# Enumerate a server
mcpfox --url http://target:8080/mcp/

# Full scan: download all resources + generate HTML report
mcpfox --url http://target:8080/mcp/ --download --html-report

# Enumerate, then interact (Tab autocomplete enabled)
mcpfox --url http://target:8080/mcp/ --interact

# One-shot tool call
mcpfox --url http://target:8080/mcp/ --call-tool execute_server_command --args '{"command":"whoami"}'

# Read a resource
mcpfox --url http://target:8080/mcp/ --read-resource resource://logs
```

---

## Modes of Operation

### Enumeration (`--url`)

Connects to an MCP server and enumerates all exposed capabilities with security analysis.

```
mcpfox --url http://target:8080/mcp/ [--read-resources] [--prompts] [--verbose] [--json report.json]
```

| Flag | Description |
|------|-------------|
| `--read-resources` | Fetch and display the content of every resource |
| `--prompts` | Enumerate server-side prompt definitions |
| `--verbose` / `-v` | Show full parameter schemas and content previews |
| `--json FILE` | Save the full report as JSON |

**Example output:**

```
╔═════════════════════════════════════════════════════════════╗
║  MCP Enumeration Report — http://target:8080/mcp/           ║
╚═════════════════════════════════════════════════════════════╝

>>> Tools (2 found)
 Name                    Parameters  Description              Flags
 execute_server_command  command     Execute a safe command   Shell/command execution,
                                                              Unconstrained string 'command'
 fetch_price_data        url         Fetch price from URL     Network/HTTP access

>>> Security Findings (3 total)
  [MEDIUM] [tool] execute_server_command: Shell/command execution
  [MEDIUM] [tool] fetch_price_data: Network/HTTP access
  [LOW]    [tool_schema] execute_server_command: Unconstrained string param 'command'
```

---

### Interactive Client (`--interact` / `-i`)

Enumerates first, then drops into a persistent REPL session with the server connection held open.

```
mcp-enum --url http://target:8080/mcp/ --interact
```

**REPL commands:**

| Command | Description |
|---------|-------------|
| `list tools` | Refresh and display available tools |
| `list resources` | Refresh and display available resources |
| `list templates` | Show URI templates |
| `list prompts` | Show available prompts |
| `info <tool>` | Display full parameter schema for a tool |
| `call <tool>` | Interactively call a tool (prompts for each argument) |
| `call <tool> -j <JSON>` | Call a tool with inline JSON args |
| `read <uri>` | Read a resource by URI |
| `history` | Show timestamped call log for this session |
| `clear` | Clear call history |
| `help` / `?` | Show command reference |
| `exit` / `quit` | End the session |

**Example session:**

```
mcp> list tools
 #  Name                    Parameters  Description
 1  execute_server_command  command     Execute a safe command on the server.
 2  fetch_price_data        url         Fetch price data from an external URL.

mcp> info execute_server_command
execute_server_command — Execute a safe command on the server.
 Parameter  Type    Required  Description
 command    string  no        The command to execute

mcp> call execute_server_command
  command (string) [optional] — The command to execute
  > whoami

→ execute_server_command({"command": "whoami"})

Result from execute_server_command:
root

mcp> read resource://logs
Content of resource://logs:
2026-01-01 12:00:00: MCP server starting...
...

mcp> history
  1. [2026-01-01T12:01:00Z] CALL execute_server_command({"command": "whoami"}) → OK
```

---

### One-Shot Tool Call (`--call-tool`)

Non-interactive; suitable for scripts and pipelines.

```bash
mcp-enum --url http://target/mcp/ --call-tool <tool> --args '<json>'
```

```bash
# Examples
mcp-enum --url http://target/mcp/ --call-tool execute_server_command --args '{"command":"id"}'
mcp-enum --url http://target/mcp/ --call-tool fetch_price_data --args '{"url":"http://internal/secret"}'
```

---

### One-Shot Resource Read (`--read-resource`)

```bash
mcp-enum --url http://target/mcp/ --read-resource resource://logs
mcp-enum --url http://target/mcp/ --read-resource resource://items
```

---

### Config Discovery (`--discover-configs`)

Searches standard locations for MCP client configuration files and extracts all configured server definitions. Auto-enumerates any HTTP servers found.

```bash
mcp-enum --discover-configs
```

Searches:

| Client | Config location |
|--------|----------------|
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code (project) | `.claude/settings.json` |
| VS Code | `~/.vscode/mcp.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Zed | `~/.config/zed/settings.json` |

---

### Port Scanning (`--scan-host`)

Probes a host for HTTP-accessible MCP endpoints. Auto-enumerates any that respond.

```bash
mcpfox --scan-host 192.168.1.10
mcpfox --scan-host 192.168.1.10 --ports 3000,8080,9000
```

Default ports probed: `3000, 3001, 4000, 5000, 7000, 8000, 8080, 8443, 8888, 9000, 31194`

---

### Resource Download (`--download`)

Fetches every enumerated resource and saves it to a cataloged directory on disk. A `manifest.json` inventory is written alongside the files.

```bash
mcpfox --url http://target/mcp/ --download

# Specify where files land
mcpfox --url http://target/mcp/ --download --output-dir my-scan/
```

Output layout:

```
mcpfox_target_31194_20260516_120000/
├── manifest.json          # full download inventory (URI, filename, bytes, status)
└── resources/
    ├── get_logs.txt
    ├── get_items.json
    └── ...
```

---

### HTML Report (`--html-report`)

Generates a self-contained dark-theme HTML inventory of every component on the scanned server — tools with full parameter schemas, resources with content or download links, templates, prompts, and colour-coded security findings.

```bash
mcpfox --url http://target/mcp/ --html-report

# Combined: download resources AND generate report
mcpfox --url http://target/mcp/ --download --html-report

# Specify output location
mcpfox --url http://target/mcp/ --download --html-report --output-dir reports/target/
```

The report embeds the MCPFox banner automatically if `assets/mcpfox-banner.png` is present in the repository root.

---

## Security Analysis

The tool applies automated heuristics to every enumerated item. Findings are rated HIGH / MEDIUM / LOW.

### Tool flags (MEDIUM)

| Pattern | Flag |
|---------|------|
| `exec`, `shell`, `command`, `run`, `spawn` | Shell/command execution |
| `eval`, `script`, `code` | Code evaluation |
| `delete`, `remove`, `drop`, `wipe` | Destructive operation |
| `write`, `upload`, `create`, `save` | Write/upload capability |
| `password`, `secret`, `token`, `credential` | Credential handling |
| `sql`, `query`, `database` | Database access |
| `http`, `fetch`, `request`, `curl` | Network/HTTP access |
| `file`, `path`, `open`, `dir` | Filesystem access |
| `env`, `environment`, `config` | Environment/config access |
| `admin`, `root`, `sudo`, `privilege` | Privilege operation |
| `email`, `slack`, `webhook`, `send` | Outbound messaging |

### Schema flags (LOW)

| Condition | Flag |
|-----------|------|
| No required parameters | Permissive input (any args accepted) |
| Unconstrained string param named `command`, `url`, `query`, `path`, `file`, `code` | Injection surface |

### Resource flags (HIGH)

| Pattern | Flag |
|---------|------|
| `.env`, `shadow`, `passwd`, `credential`, `secret` | Credential file |
| `ssh`, `private_key`, `.pem`, `keyring` | Private key material |
| `token`, `api_key`, `jwt` | API token |
| `log`, `history`, `audit` | Audit/history data |
| `config`, `settings`, `profile` | Configuration file |

---

## JSON Output Schema

```json
{
  "generated": "2026-01-01T00:00:00Z",
  "mcp_enum_version": "1.0.0",
  "reports": [
    {
      "url": "http://target/mcp/",
      "timestamp": "2026-01-01T00:00:00Z",
      "tools": [
        {
          "name": "execute_server_command",
          "description": "...",
          "schema": { "properties": { "command": { "type": "string" } } },
          "security": [
            { "severity": "MEDIUM", "label": "Shell/command execution" }
          ]
        }
      ],
      "resources": [...],
      "resource_templates": [...],
      "prompts": [...],
      "security_findings": [
        { "type": "tool", "item": "execute_server_command", "severity": "MEDIUM", "detail": "Shell/command execution" }
      ]
    }
  ]
}
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check mcp_enum/
```

### Project layout

```
mcp_enum/
├── __init__.py       version
├── __main__.py       python -m mcp_enum entry point
├── analysis.py       security heuristics
├── cli.py            argument parsing + main()
├── discovery.py      local config file discovery
├── enumeration.py    MCP server enumeration
├── http_probe.py     HTTP port scanning
├── interactive.py    REPL client
└── rendering.py      terminal output helpers
```

---

## Legal

This tool is intended for use against systems you own or have explicit written authorisation to test. Unauthorised use against third-party systems may violate computer fraud laws in your jurisdiction.

---

## License

MIT — see [LICENSE](LICENSE).
