"""Console output helpers and report rendering."""

import json

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

SEVERITY_COLORS = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "green"}


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------

def _extract_mcp_error_fields(exc: BaseException, indent: str) -> list[str]:
    """
    Pull structured fields from the MCP SDK's McpError.error (ErrorData):
      .code    -- integer error code  (skipped when 0 / unset)
      .message -- error message       (skipped when identical to str(exc))
      .data    -- server-supplied payload with the full detail
    """
    lines = []
    mcp_err = getattr(exc, "error", None)
    if mcp_err is None:
        return lines
    code = getattr(mcp_err, "code", None)
    if code is not None and code != 0:
        lines.append(f"{indent}mcp.code: {code}")
    message = getattr(mcp_err, "data", None)  # .data first -- most useful field
    if message is not None:
        lines.append(f"{indent}mcp.data: {message}")
    # Only show .message if it adds something str(exc) doesn't already contain
    mcp_msg = getattr(mcp_err, "message", None)
    if mcp_msg and mcp_msg not in str(exc):
        lines.append(f"{indent}mcp.message: {mcp_msg}")
    return lines


def format_resource_error(e: Exception) -> str:
    """
    Return the full error detail for a failed resource read:
      - exception type + message
      - MCP ErrorData fields (code / message / data) when present
      - any extra args beyond the first
      - HTTP-style attributes (status_code, response, detail, body, text)
      - complete exception chain (__cause__ / __context__), each with
        its own MCP fields if applicable
    """
    lines = [f"{type(e).__name__}: {e}"]

    # MCP SDK McpError carries structured error info in .error (ErrorData)
    lines.extend(_extract_mcp_error_fields(e, "  "))

    # Extra positional args (the first is already shown via str(e))
    if len(e.args) > 1:
        lines.append(f"  args: {e.args[1:]}")

    # HTTP / generic library attributes
    for attr in ("status_code", "response", "detail", "body", "text", "data"):
        val = getattr(e, attr, None)
        if val is not None:
            lines.append(f"  {attr}: {val}")

    # Walk the full exception chain
    seen: set[int] = {id(e)}
    cause: BaseException | None = e.__cause__ or e.__context__
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        lines.append(f"  caused by {type(cause).__name__}: {cause}")
        lines.extend(_extract_mcp_error_fields(cause, "    "))
        cause = cause.__cause__ or cause.__context__

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def print_header(text: str) -> None:
    if RICH_AVAILABLE:
        console.print(Panel(f"[bold cyan]{text}[/bold cyan]", box=box.DOUBLE_EDGE))
    else:
        print(f"\n{'='*60}\n  {text}\n{'='*60}")


def print_section(text: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"\n[bold yellow]>>> {text}[/bold yellow]")
    else:
        print(f"\n--- {text} ---")


def print_finding(severity: str, message: str) -> None:
    if RICH_AVAILABLE:
        color = SEVERITY_COLORS.get(severity, "white")
        console.print(f"  [{color}][{severity}][/{color}] {message}")
    else:
        print(f"  [{severity}] {message}")


def print_info(text: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"  {text}")
    else:
        print(f"  {text}")


def print_json(data) -> None:
    try:
        parsed = json.loads(data) if isinstance(data, str) else data
        pretty = json.dumps(parsed, indent=2)
        if RICH_AVAILABLE:
            console.print(Syntax(pretty, "json", theme="monokai", line_numbers=False))
        else:
            print(pretty)
    except (json.JSONDecodeError, TypeError):
        print(str(data))


# ---------------------------------------------------------------------------
# Tool / resource result rendering (shared by REPL + one-shot)
# ---------------------------------------------------------------------------

def render_tool_result(tool_name: str, result) -> None:
    if RICH_AVAILABLE:
        console.print(f"\n[bold green]Result from [cyan]{tool_name}[/cyan]:[/bold green]")
    else:
        print(f"\nResult from {tool_name}:")

    for item in (result if isinstance(result, list) else [result]):
        if hasattr(item, "text"):
            text = item.text
        elif hasattr(item, "data"):
            text = str(item.data)
        else:
            text = str(item)
        print_json(text)


def render_resource_content(uri: str, content) -> None:
    if RICH_AVAILABLE:
        console.print(f"\n[bold green]Content of [cyan]{uri}[/cyan]:[/bold green]")
    else:
        print(f"\nContent of {uri}:")

    for item in (content if isinstance(content, list) else [content]):
        if hasattr(item, "text"):
            text = item.text
        elif hasattr(item, "blob"):
            text = f"<binary blob {len(item.blob)} bytes>"
        else:
            text = str(item)
        print_json(text)


# ---------------------------------------------------------------------------
# Full enumeration report
# ---------------------------------------------------------------------------

def render_report(report: dict, verbose: bool = False) -> None:
    url = report.get("url", "unknown")
    print_header(f"MCP Enumeration Report -- {url}")

    if "connection_error" in report:
        print_finding("HIGH", f"Connection failed: {report['connection_error']}")
        return

    # Tools
    tools = report.get("tools", [])
    print_section(f"Tools ({len(tools)} found)")
    if tools:
        if RICH_AVAILABLE:
            tbl = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            tbl.add_column("Name", style="cyan", no_wrap=True)
            tbl.add_column("Parameters")
            tbl.add_column("Description")
            tbl.add_column("Flags", style="yellow")
            for t in tools:
                params = ", ".join(t["schema"].get("properties", {}).keys())
                desc = (t["description"][:60] + "...") if len(t["description"]) > 60 else t["description"]
                flags = ", ".join(s["label"] for s in t["security"]) if t["security"] else ""
                tbl.add_row(t["name"], params or "(none)", desc, flags)
            console.print(tbl)
        else:
            for t in tools:
                params = ", ".join(t["schema"].get("properties", {}).keys())
                print(f"  [TOOL] {t['name']}({params})")
                print(f"         {t['description'][:80]}")

        if verbose:
            for t in tools:
                if t["schema"].get("properties"):
                    label = f"  Schema for [cyan]{t['name']}[/cyan]:" if RICH_AVAILABLE else f"  Schema for {t['name']}:"
                    print_info(f"\n{label}")
                    for pname, pdef in t["schema"]["properties"].items():
                        req = pname in t["schema"].get("required", [])
                        req_tag = "[required]" if req else "[optional]"
                        print_info(f"    • {pname}: {pdef.get('type','?')} {req_tag} -- {pdef.get('description','')}")
    else:
        err = report.get("tools_error", "")
        print_info("No tools returned." + (f" Error: {err}" if err else ""))

    # Resources
    resources = report.get("resources", [])
    print_section(f"Resources ({len(resources)} found)")
    if resources:
        for res in resources:
            flag = " [SENSITIVE]" if res["security"] else ""
            print_info(f"  • {res['name']} [{res.get('mime_type','?')}] -- {res.get('uri','')}{flag}")
            if res.get("content_error"):
                print_finding("HIGH", f"Resource read failed: {res['content_error']}")
            elif verbose and res.get("content"):
                snippet = res["content"][:400].replace("\n", " ")
                print_info(f"    Content preview: {snippet}...")
    else:
        err = report.get("resources_error", "")
        print_info("No resources returned." + (f" Error: {err}" if err else ""))

    # Resource templates
    templates = report.get("resource_templates", [])
    print_section(f"Resource Templates ({len(templates)} found)")
    if templates:
        for tmpl in templates:
            print_info(f"  • {tmpl['uri_template']} -- {tmpl.get('description','')[:60]}")
    else:
        print_info("No resource templates returned.")

    # Prompts
    prompts = report.get("prompts", [])
    if prompts:
        print_section(f"Prompts ({len(prompts)} found)")
        for p in prompts:
            args = ", ".join(a["name"] for a in p.get("arguments", []))
            print_info(f"  • {p['name']}({args}) -- {p['description'][:60]}")

    # Security findings
    findings = report.get("security_findings", [])
    print_section(f"Security Findings ({len(findings)} total)")
    if findings:
        by_severity: dict[str, list] = {}
        for f in findings:
            by_severity.setdefault(f["severity"], []).append(f)
        for sev in ("HIGH", "MEDIUM", "LOW"):
            for f in by_severity.get(sev, []):
                print_finding(sev, f"[{f['type']}] {f['item']}: {f['detail']}")
    else:
        print_finding("INFO", "No automated flags raised (manual review still recommended).")


def render_config_discovery(configs: dict, servers_by_label: dict) -> None:
    print_header("Local MCP Config Discovery")
    if not configs:
        print_info("No MCP configuration files found in standard locations.")
        return
    for label, path in configs.items():
        print_section(f"{label}: {path}")
        for srv in servers_by_label.get(label, []):
            if "error" in srv:
                print_finding("HIGH", f"Parse error: {srv['error']}")
                continue
            stype = srv.get("type", "?")
            name = srv.get("name", "?")
            if stype == "http":
                print_info(f"  [HTTP]  {name} -> {srv.get('url','?')}")
            elif stype == "stdio":
                cmd = srv.get("command", "?")
                args = " ".join(srv.get("args", []))
                print_info(f"  [STDIO] {name} -> {cmd} {args}")
                env_keys = list(srv.get("env", {}).keys())
                if env_keys:
                    print_finding("MEDIUM", f"Env vars passed to server: {', '.join(env_keys)}")


def render_port_scan(results: list[dict]) -> None:
    print_section("Port Scan Results")
    if not results:
        print_info("No open MCP endpoints detected.")
        return
    for r in results:
        sse_tag = " [SSE/MCP likely]" if r.get("is_sse") else ""
        json_tag = " [JSON API]" if r.get("is_json") else ""
        print_finding("INFO", f"{r['url']} -> HTTP {r['status']} {r.get('content_type','')}{sse_tag}{json_tag}")
        if r.get("server"):
            print_info(f"    Server: {r['server']}")
