"""Interactive REPL client for MCP servers, with Tab autocomplete."""

import json
import shlex
from datetime import datetime

try:
    from fastmcp import Client
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False

try:
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.styles import Style
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

from mcpfox.rendering import (
    console,
    format_resource_error,
    print_header,
    print_section,
    print_finding,
    print_info,
    render_tool_result,
    render_resource_content,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMMANDS = ["call", "clear", "exit", "help", "history", "info", "list", "quit", "read"]
LIST_SUBCOMMANDS = ["prompts", "resources", "templates", "tools"]
CALL_FLAGS = ["-j", "--json"]

REPL_HELP = """
Commands:
  list tools            Refresh and list available tools
  list resources        Refresh and list available resources
  list templates        List resource URI templates
  list prompts          List available prompts
  info <tool>           Show full parameter schema for a tool
  call <tool>           Interactively call a tool (prompts per argument)
  call <tool> -j <JSON> Call a tool with inline JSON arguments
  read <uri>            Read a resource by URI  (Tab-completes known URIs)
  history               Show timestamped call log for this session
  clear                 Clear call history
  help / ?              Show this help
  exit / quit           Exit the interactive client

Tab completes commands, subcommands, tool names, and resource URIs.
"""

PROMPT_STYLE = Style.from_dict({"prompt": "bold ansired"}) if PROMPT_TOOLKIT_AVAILABLE else None


# ---------------------------------------------------------------------------
# Autocomplete
# ---------------------------------------------------------------------------

if PROMPT_TOOLKIT_AVAILABLE:
    class _MCPCompleter(Completer):
        """
        Context-aware Tab completer for the mcpfox REPL.

        Completion rules:
          position 0  ->  command names
          position 1:
            list  ->  tools | resources | templates | prompts
            info  ->  tool names (with description as meta)
            call  ->  tool names (with description as meta)
            read  ->  known resource URIs + template patterns
          position 2 (call <tool>):
            ->  -j / --json
        """

        def __init__(self, tools_index: dict, resources_index: dict) -> None:
            # Live references -- mutated by _cmd_list so completions stay fresh
            self._tools = tools_index
            self._resources = resources_index

        def get_completions(self, document, complete_event):
            text = document.text_before_cursor
            stripped = text.rstrip()
            parts = stripped.split() if stripped else []
            # Are we starting a new token (trailing space or empty line)?
            starts_new = (len(text) > len(stripped)) or not stripped

            if starts_new:
                completing_idx = len(parts)
                partial = ""
            else:
                completing_idx = len(parts) - 1
                partial = parts[-1] if parts else ""

            cmd = parts[0].lower() if parts else ""

            if completing_idx == 0:
                for c in COMMANDS:
                    if c.startswith(partial):
                        yield Completion(c, start_position=-len(partial),
                                         display_meta="command")

            elif completing_idx == 1:
                if cmd == "list":
                    for sub in LIST_SUBCOMMANDS:
                        if sub.startswith(partial):
                            yield Completion(sub, start_position=-len(partial))

                elif cmd in ("info", "call"):
                    for name, tool in self._tools.items():
                        if name.startswith(partial):
                            meta = (tool.get("description") or "")[:50]
                            yield Completion(name, start_position=-len(partial),
                                             display_meta=meta)

                elif cmd == "read":
                    for uri in self._resources:
                        if uri.startswith(partial):
                            yield Completion(uri, start_position=-len(partial),
                                             display_meta="resource")

            elif completing_idx == 2 and cmd == "call":
                for flag in CALL_FLAGS:
                    if flag.startswith(partial):
                        yield Completion(flag, start_position=-len(partial),
                                         display_meta="inline JSON args")


# ---------------------------------------------------------------------------
# Argument prompting (for interactive `call`)
# ---------------------------------------------------------------------------

def _prompt_args(schema: dict) -> dict:
    """Walk a JSON schema and interactively prompt for each parameter."""
    props = schema.get("properties", {})
    required = schema.get("required", [])
    args: dict = {}

    for pname, pdef in props.items():
        ptype = pdef.get("type", "string")
        desc = pdef.get("description", "")
        is_req = pname in required
        enum_vals = pdef.get("enum")

        tag = "[required]" if is_req else "[optional]"
        hint = f" ({ptype})"
        enum_hint = f" [{'/'.join(str(e) for e in enum_vals)}]" if enum_vals else ""

        if RICH_AVAILABLE:
            console.print(f"  [cyan]{pname}[/cyan]{hint}{enum_hint} {tag} -- {desc}")
        raw = input("  > ").strip()

        if not raw:
            if is_req:
                print_finding("LOW", f"Required param '{pname}' left empty")
            continue

        if ptype == "integer":
            args[pname] = int(raw) if raw.lstrip("-").isdigit() else raw
        elif ptype == "number":
            try:
                args[pname] = float(raw)
            except ValueError:
                args[pname] = raw
        elif ptype == "boolean":
            args[pname] = raw.lower() in ("true", "1", "yes", "y")
        elif ptype in ("object", "array"):
            try:
                args[pname] = json.loads(raw)
            except json.JSONDecodeError:
                args[pname] = raw
        else:
            args[pname] = raw

    return args


# ---------------------------------------------------------------------------
# Main REPL
# ---------------------------------------------------------------------------

async def interactive_session(url: str, report: dict) -> None:
    """Open a persistent MCP connection and run the mcpfox interactive REPL."""
    if not FASTMCP_AVAILABLE:
        print("fastmcp not installed. Run: pip install fastmcp")
        return

    # Live indices -- updated in-place by list commands so the completer stays fresh
    tools_index: dict[str, dict] = {t["name"]: t for t in report.get("tools", [])}
    resources_index: dict[str, str] = {
        r["uri"]: r["name"] for r in report.get("resources", []) if r.get("uri")
    }
    history: list[dict] = []

    # Build prompt session with Tab autocomplete when prompt_toolkit is available
    if PROMPT_TOOLKIT_AVAILABLE:
        completer = _MCPCompleter(tools_index, resources_index)
        session: PromptSession = PromptSession(
            history=InMemoryHistory(),
            completer=completer,
            complete_while_typing=False,   # only complete on Tab
            style=PROMPT_STYLE,
        )

    print_header(f"mcpfox interactive client -- {url}")
    hint = "Tab for completions  |  " if PROMPT_TOOLKIT_AVAILABLE else ""
    if RICH_AVAILABLE:
        console.print(f"[dim]{hint}Type 'help' for commands, 'exit' to quit.[/dim]\n")
    else:
        print(f"{hint}Type 'help' for commands, 'exit' to quit.\n")

    client = Client(url)
    async with client:
        while True:
            try:
                if PROMPT_TOOLKIT_AVAILABLE:
                    raw_line = await session.prompt_async(
                        [("class:prompt", "mcpfox"), ("", "> ")]
                    )
                elif RICH_AVAILABLE:
                    console.print("[bold red]mcpfox[/bold red]> ", end="")
                    raw_line = input("")
                else:
                    raw_line = input("mcpfox> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break

            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                tokens = shlex.split(raw_line)
            except ValueError as e:
                print_finding("LOW", f"Parse error: {e}")
                continue

            cmd = tokens[0].lower()

            if cmd in ("exit", "quit", "q"):
                break
            elif cmd in ("help", "?"):
                print(REPL_HELP)
            elif cmd == "list":
                await _cmd_list(client, tokens, tools_index, resources_index)
            elif cmd == "info":
                _cmd_info(tokens, tools_index)
            elif cmd == "call":
                await _cmd_call(client, tokens, tools_index, history)
            elif cmd == "read":
                await _cmd_read(client, tokens, history)
            elif cmd == "history":
                _cmd_history(history)
            elif cmd == "clear":
                history.clear()
                print_info("History cleared.")
            else:
                print_finding("LOW", f"Unknown command '{cmd}'. Type 'help' for usage.")

    if RICH_AVAILABLE:
        console.print("\n[dim]Session ended.[/dim]")
    else:
        print("\nSession ended.")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def _cmd_list(
    client,
    tokens: list[str],
    tools_index: dict,
    resources_index: dict,
) -> None:
    sub = tokens[1].lower() if len(tokens) > 1 else ""

    if sub == "tools":
        tools = await client.list_tools()
        tools_index.clear()
        if RICH_AVAILABLE:
            tbl = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            tbl.add_column("#", style="dim")
            tbl.add_column("Name", style="cyan")
            tbl.add_column("Parameters")
            tbl.add_column("Description")
            for i, t in enumerate(tools, 1):
                schema = t.inputSchema or {}
                params = ", ".join(schema.get("properties", {}).keys())
                desc = (t.description[:55] + "...") if t.description and len(t.description) > 55 else (t.description or "")
                tbl.add_row(str(i), t.name, params or "(none)", desc)
                tools_index[t.name] = {
                    "name": t.name,
                    "description": t.description or "",
                    "schema": schema,
                    "security": [],
                }
            console.print(tbl)
        else:
            for i, t in enumerate(tools, 1):
                schema = t.inputSchema or {}
                params = ", ".join(schema.get("properties", {}).keys())
                print(f"  {i}. {t.name}({params})")
                tools_index[t.name] = {
                    "name": t.name,
                    "description": t.description or "",
                    "schema": schema,
                    "security": [],
                }

    elif sub == "resources":
        resources = await client.list_resources()
        resources_index.clear()
        for i, r in enumerate(resources, 1):
            uri = str(r.uri) if hasattr(r, "uri") else r.name
            mime = r.mimeType if hasattr(r, "mimeType") else "?"
            print_info(f"  {i}. {r.name} [{mime}] -> {uri}")
            resources_index[uri] = r.name

    elif sub == "templates":
        templates = await client.list_resource_templates()
        for i, t in enumerate(templates, 1):
            uri_t = t.uriTemplate if hasattr(t, "uriTemplate") else str(t)
            desc = getattr(t, "description", "") or ""
            print_info(f"  {i}. {uri_t} -- {desc[:55]}")

    elif sub == "prompts":
        try:
            prompts = await client.list_prompts()
            for i, p in enumerate(prompts, 1):
                args_str = ", ".join(a.name for a in (p.arguments or [])) if hasattr(p, "arguments") and p.arguments else ""
                print_info(f"  {i}. {p.name}({args_str}) -- {(p.description or '')[:60]}")
        except Exception as e:
            print_finding("LOW", f"Could not list prompts: {e}")

    else:
        print_info("Usage: list tools | resources | templates | prompts")


def _cmd_info(tokens: list[str], tools_index: dict) -> None:
    if len(tokens) < 2:
        print_info("Usage: info <tool_name>")
        return
    name = tokens[1]
    tool = tools_index.get(name)
    if not tool:
        print_finding("LOW", f"Unknown tool '{name}'. Run 'list tools' first.")
        return
    schema = tool.get("schema", {})
    props = schema.get("properties", {})
    required = schema.get("required", [])

    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{name}[/bold cyan] -- {tool['description']}")
        tbl = Table(show_header=True, header_style="bold", box=box.SIMPLE)
        tbl.add_column("Parameter", style="cyan")
        tbl.add_column("Type")
        tbl.add_column("Required")
        tbl.add_column("Description")
        for pname, pdef in props.items():
            tbl.add_row(
                pname,
                pdef.get("type", "?"),
                "yes" if pname in required else "no",
                pdef.get("description", ""),
            )
        console.print(tbl)
    else:
        print(f"\n{name} -- {tool['description']}")
        for pname, pdef in props.items():
            req = "[required]" if pname in required else "[optional]"
            print(f"  {pname}: {pdef.get('type','?')} {req} -- {pdef.get('description','')}")


async def _cmd_call(client, tokens: list[str], tools_index: dict, history: list) -> None:
    if len(tokens) < 2:
        print_info("Usage: call <tool_name> [-j <json_args>]")
        return
    tool_name = tokens[1]
    tool = tools_index.get(tool_name)
    if not tool:
        print_finding("LOW", f"Unknown tool '{tool_name}'. Run 'list tools' first.")
        return

    if len(tokens) >= 4 and tokens[2] in ("-j", "--json"):
        try:
            call_args = json.loads(" ".join(tokens[3:]))
        except json.JSONDecodeError as e:
            print_finding("LOW", f"Invalid JSON: {e}")
            return
    else:
        if RICH_AVAILABLE:
            console.print(f"\n[bold]Calling [cyan]{tool_name}[/cyan] -- enter arguments:[/bold]")
        else:
            print(f"\nCalling {tool_name} -- enter arguments:")
        call_args = _prompt_args(tool.get("schema", {}))

    if RICH_AVAILABLE:
        console.print(f"\n[dim]-> {tool_name}({json.dumps(call_args)})[/dim]")
    else:
        print(f"\n-> {tool_name}({json.dumps(call_args)})")

    try:
        result = await client.call_tool(tool_name, call_args)
        render_tool_result(tool_name, result)
        history.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "call",
            "tool": tool_name,
            "args": call_args,
            "result": str(result),
        })
    except Exception as e:
        print_finding("HIGH", f"Tool call failed: {e}")
        history.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "action": "call",
            "tool": tool_name,
            "args": call_args,
            "error": str(e),
        })


async def _cmd_read(client, tokens: list[str], history: list) -> None:
    if len(tokens) < 2:
        print_info("Usage: read <resource_uri>")
        return
    uri = tokens[1]
    try:
        content = await client.read_resource(uri)
        render_resource_content(uri, content)
        history.append({"ts": datetime.utcnow().isoformat() + "Z", "action": "read", "uri": uri})
    except Exception as e:
        print_finding("HIGH", f"Resource read failed:\n{format_resource_error(e)}")


def _cmd_history(history: list) -> None:
    if not history:
        print_info("No calls made yet.")
        return
    for i, entry in enumerate(history, 1):
        ts = entry["ts"]
        if entry["action"] == "call":
            status = "ERROR" if "error" in entry else "OK"
            print_info(f"  {i}. [{ts}] CALL {entry['tool']}({json.dumps(entry['args'])}) -> {status}")
        else:
            print_info(f"  {i}. [{ts}] READ {entry['uri']}")
