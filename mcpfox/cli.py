"""Command-line interface: argument parsing and main entry point."""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

from mcpfox import __version__
from mcpfox.discovery import discover_local_configs, extract_mcp_servers_from_config
from mcpfox.downloader import download_all_resources, make_output_dir_name, print_download_inventory
from mcpfox.enumeration import enumerate_mcp_server
from mcpfox.html_report import generate_html_report
from mcpfox.http_probe import COMMON_MCP_PORTS, scan_ports
from mcpfox.interactive import interactive_session
from mcpfox.rendering import (
    console,
    format_resource_error,
    print_header,
    print_section,
    print_finding,
    render_config_discovery,
    render_port_scan,
    render_report,
    render_resource_content,
    render_tool_result,
    RICH_AVAILABLE,
)

try:
    from fastmcp import Client
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _parse_basic_auth(value: str):
    """
    Parse a USER:PASS string into an httpx.BasicAuth object.
    Raises SystemExit with a clear message if the format is wrong or httpx
    is unavailable.
    """
    if not HTTPX_AVAILABLE:
        print("[ERROR] httpx is required for --basic-auth. Run: pip install httpx")
        sys.exit(1)
    if ":" not in value:
        print("[ERROR] --basic-auth requires USER:PASS format (e.g. admin:secret)")
        sys.exit(1)
    user, _, password = value.partition(":")
    return httpx.BasicAuth(user, password)


# ---------------------------------------------------------------------------
# One-shot helpers
# ---------------------------------------------------------------------------

async def _call_tool_once(url: str, tool_name: str, raw_args: str, timeout: float, auth=None) -> None:  # noqa: ARG001
    try:
        call_args = json.loads(raw_args) if raw_args else {}
    except json.JSONDecodeError as e:
        print(f"[ERROR] --args must be valid JSON: {e}")
        return

    print_header(f"Calling {tool_name} on {url}")
    if RICH_AVAILABLE:
        console.print(json.dumps(call_args, indent=2))
    else:
        print(json.dumps(call_args, indent=2))

    try:
        client = Client(url, auth=auth)
        async with client:
            result = await client.call_tool(tool_name, call_args)
            render_tool_result(tool_name, result)
    except Exception as e:
        print_finding("HIGH", f"Call failed: {e}")


async def _read_resource_once(url: str, uri: str, auth=None) -> None:
    print_header(f"Reading resource {uri}")
    try:
        client = Client(url, auth=auth)
        async with client:
            content = await client.read_resource(uri)
            render_resource_content(uri, content)
    except Exception as e:
        print_finding("HIGH", f"Resource read failed:\n{format_resource_error(e)}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpfox",
        description="mcpfox -- MCP Server Enumeration & Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes of operation:

  Enumerate a server:
    mcpfox --url http://target:8080/mcp/

  Enumerate with HTTP Basic Auth:
    mcpfox --url http://target:8080/mcp/ --basic-auth admin:secret

  Enumerate then drop into interactive client (with Tab autocomplete):
    mcpfox --url http://target:8080/mcp/ --interact

  One-shot tool call:
    mcpfox --url http://target:8080/mcp/ --call-tool execute_server_command --args '{"command":"id"}'

  Read a single resource:
    mcpfox --url http://target:8080/mcp/ --read-resource resource://logs

  Discover MCP servers in local config files:
    mcpfox --discover-configs

  Port scan a host for MCP endpoints:
    mcpfox --scan-host 192.168.1.10 --ports 3000,8080,9000

  Save full JSON report:
    mcpfox --url http://target:8080/mcp/ --read-resources --prompts --json report.json
""",
    )
    parser.add_argument("--version", action="version", version=f"mcpfox {__version__}")

    target = parser.add_argument_group("Target")
    target.add_argument("--url", metavar="URL", help="MCP server URL to enumerate")
    target.add_argument("--timeout", type=float, default=5.0, metavar="SEC",
                        help="Connection/request timeout in seconds (default: 5)")
    target.add_argument(
        "--basic-auth", metavar="USER:PASS", dest="basic_auth",
        help="HTTP Basic Auth credentials in USER:PASS format",
    )

    enum_grp = parser.add_argument_group("Enumeration")
    enum_grp.add_argument("--read-resources", action="store_true",
                           help="Fetch and display all resource contents")
    enum_grp.add_argument("--prompts", action="store_true",
                           help="Enumerate server prompts")
    enum_grp.add_argument("--verbose", "-v", action="store_true",
                           help="Verbose output (full schemas, content previews)")

    interact_grp = parser.add_argument_group("Interaction")
    interact_grp.add_argument("--interact", "-i", action="store_true",
                               help="Drop into interactive REPL after enumeration (Tab autocomplete included)")
    interact_grp.add_argument("--call-tool", metavar="TOOL",
                               help="One-shot: call TOOL and exit (requires --url)")
    interact_grp.add_argument("--args", metavar="JSON", default="{}",
                               help="JSON arguments for --call-tool (default: {})")
    interact_grp.add_argument("--read-resource", metavar="URI",
                               help="One-shot: read a resource by URI and exit (requires --url)")

    disc_grp = parser.add_argument_group("Discovery")
    disc_grp.add_argument("--discover-configs", action="store_true",
                           help="Find local MCP config files and extract server definitions")
    disc_grp.add_argument("--scan-host", metavar="HOST",
                           help="HTTP port scan HOST for MCP endpoints")
    disc_grp.add_argument("--ports", metavar="PORTS",
                           help="Comma-separated ports for --scan-host (default: common MCP ports)")

    out_grp = parser.add_argument_group("Output")
    out_grp.add_argument("--json", metavar="FILE", dest="json_output",
                          help="Save full enumeration report as JSON to FILE")
    out_grp.add_argument("--download", action="store_true",
                          help="Download all server resources to <output-dir>/resources/")
    out_grp.add_argument("--html-report", action="store_true",
                          help="Generate HTML inventory report at <output-dir>/report.html")
    out_grp.add_argument("--output-dir", metavar="DIR", dest="output_dir",
                          help="Directory for --download / --html-report (default: auto-named from URL + timestamp)")

    return parser


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------

async def _main(args: argparse.Namespace) -> None:
    all_reports: list[dict] = []

    if not (args.url or args.discover_configs or args.scan_host):
        print("No target specified. Use --help for usage.")
        sys.exit(1)

    # Resolve auth object once — shared across all calls in this session
    auth = _parse_basic_auth(args.basic_auth) if args.basic_auth else None

    # One-shot modes bypass full enumeration
    if args.url and args.call_tool:
        await _call_tool_once(args.url, args.call_tool, args.args, args.timeout, auth=auth)
        return

    if args.url and args.read_resource:
        await _read_resource_once(args.url, args.read_resource, auth=auth)
        return

    # Config discovery
    if args.discover_configs:
        configs = discover_local_configs()
        servers_by_label: dict[str, list] = {
            label: extract_mcp_servers_from_config(path)
            for label, path in configs.items()
        }
        render_config_discovery(configs, servers_by_label)
        for srvs in servers_by_label.values():
            for srv in srvs:
                if srv.get("type") == "http" and srv.get("url"):
                    print_section(f"Auto-enumerating: {srv['name']}")
                    report = await enumerate_mcp_server(
                        srv["url"],
                        read_resources=args.read_resources,
                        probe_prompts=args.prompts,
                        auth=auth,
                    )
                    render_report(report, verbose=args.verbose)
                    all_reports.append(report)

    # Port scan
    if args.scan_host:
        ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else COMMON_MCP_PORTS
        print_header(f"Scanning {args.scan_host} on {len(ports)} ports")
        results = await scan_ports(args.scan_host, ports, timeout=args.timeout, auth=auth)
        render_port_scan(results)
        for r in results:
            if r.get("is_sse") or r.get("status") == 200:
                print_section(f"Auto-enumerating: {r['url']}")
                report = await enumerate_mcp_server(
                    r["url"],
                    read_resources=args.read_resources,
                    probe_prompts=args.prompts,
                    auth=auth,
                )
                render_report(report, verbose=args.verbose)
                all_reports.append(report)

    # Direct enumeration
    if args.url:
        report = await enumerate_mcp_server(
            args.url,
            read_resources=args.read_resources,
            probe_prompts=args.prompts,
            auth=auth,
        )
        render_report(report, verbose=args.verbose)
        all_reports.append(report)

        # Resolve output directory (shared by --download and --html-report)
        needs_output = args.download or args.html_report
        output_dir: Path | None = None
        if needs_output:
            raw_dir = getattr(args, "output_dir", None)
            output_dir = Path(raw_dir) if raw_dir else Path(make_output_dir_name(args.url))
            output_dir.mkdir(parents=True, exist_ok=True)
            if RICH_AVAILABLE:
                console.print(f"\n[dim]Output directory: {output_dir}[/dim]")
            else:
                print(f"\nOutput directory: {output_dir}")

        # Download resources
        manifest: dict | None = None
        if args.download and output_dir is not None:
            print_section("Downloading resources")
            manifest = await download_all_resources(args.url, report, output_dir, auth=auth)
            print_download_inventory(manifest)

        # HTML report
        if args.html_report and output_dir is not None:
            report_path = output_dir / "report.html"
            generate_html_report(report, report_path, manifest)
            if RICH_AVAILABLE:
                console.print(f"\n[green]HTML report -> {report_path}[/green]")
            else:
                print(f"\nHTML report -> {report_path}")

        if args.interact:
            await interactive_session(args.url, report, auth=auth)

    # JSON output
    if args.json_output and all_reports:
        payload = {
            "generated": datetime.utcnow().isoformat() + "Z",
            "mcpfox_version": __version__,
            "reports": all_reports,
        }
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        if RICH_AVAILABLE:
            console.print(f"\n[green]JSON report saved to {args.json_output}[/green]")
        else:
            print(f"\nJSON report saved to {args.json_output}")


def run() -> None:
    """Synchronous entry point (used by pyproject.toml scripts and __main__)."""
    try:
        import readline  # noqa: F401
    except Exception:
        pass

    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(_main(args))


if __name__ == "__main__":
    run()
