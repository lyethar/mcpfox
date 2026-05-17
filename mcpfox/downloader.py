"""Download MCP server resources to a cataloged directory on disk."""

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from fastmcp import Client
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False

from mcpfox import __version__
from mcpfox.rendering import format_resource_error, print_finding, print_info, RICH_AVAILABLE

try:
    from rich.console import Console
    console = Console() if RICH_AVAILABLE else None
except Exception:
    console = None

# ---------------------------------------------------------------------------
# MIME -> file extension
# ---------------------------------------------------------------------------

_MIME_EXT: dict[str, str] = {
    "application/json": ".json",
    "text/plain": ".txt",
    "text/html": ".html",
    "text/xml": ".xml",
    "application/xml": ".xml",
    "text/csv": ".csv",
    "text/markdown": ".md",
    "application/yaml": ".yaml",
    "application/x-yaml": ".yaml",
    "text/x-python": ".py",
    "application/javascript": ".js",
    "text/javascript": ".js",
}


def _mime_to_ext(mime: str) -> str:
    base = mime.split(";")[0].strip().lower()
    return _MIME_EXT.get(base, ".txt")


def _safe_filename(name: str) -> str:
    """Strip/replace characters that are unsafe in filenames."""
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    name = re.sub(r'[:/]+', "_", name)       # collapse URI separators
    name = name.strip(". ")
    return name[:100] or "resource"


def _extract_text(content) -> str:
    """Pull plain text out of a fastmcp content object (list or single item)."""
    items = content if isinstance(content, list) else [content]
    parts = []
    for item in items:
        if hasattr(item, "text") and item.text is not None:
            parts.append(item.text)
        elif hasattr(item, "blob") and item.blob is not None:
            parts.append(f"<binary blob: {len(item.blob)} bytes>")
        else:
            parts.append(str(item))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Output directory naming
# ---------------------------------------------------------------------------

def make_output_dir_name(url: str) -> str:
    parsed = urlparse(url)
    host = re.sub(r'[^a-zA-Z0-9_-]', "-", parsed.hostname or "unknown")
    port = str(parsed.port) if parsed.port else ""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    parts = ["mcpfox", host] + ([port] if port else []) + [ts]
    return "_".join(parts)


# ---------------------------------------------------------------------------
# Main download function
# ---------------------------------------------------------------------------

async def download_all_resources(
    url: str,
    report: dict,
    output_dir: Path,
) -> dict:
    """
    Download every enumerated resource to <output_dir>/resources/ and write
    a manifest.json catalogue.  Returns the manifest dict.
    """
    if not FASTMCP_AVAILABLE:
        return {"error": "fastmcp not installed"}

    resources_dir = output_dir / "resources"
    resources_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "mcpfox_version": __version__,
        "target": url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "output_dir": str(output_dir),
        "files": [],
    }

    resources = report.get("resources", [])
    if not resources:
        print_info("  No resources to download.")
        _write_manifest(manifest, output_dir)
        return manifest

    client = Client(url)
    async with client:
        for res in resources:
            uri = res.get("uri") or res.get("name", "unknown")
            name = res.get("name", uri)
            mime = res.get("mime_type", "")
            ext = _mime_to_ext(mime) if mime else ".txt"
            filename = _safe_filename(name) + ext
            filepath = resources_dir / filename

            record: dict = {
                "resource_name": name,
                "uri": uri,
                "mime_type": mime or "unknown",
                "file": f"resources/{filename}",
                "status": "pending",
            }

            try:
                content = await client.read_resource(uri)
                text = _extract_text(content)
                filepath.write_text(text, encoding="utf-8")
                record["status"] = "ok"
                record["bytes"] = len(text.encode())
                if RICH_AVAILABLE and console:
                    console.print(f"  [green]OK[/green]  {filename}  ({record['bytes']} bytes)")
                else:
                    print(f"  OK  {filename}  ({record['bytes']} bytes)")
            except Exception as e:
                err = format_resource_error(e)
                record["status"] = "error"
                record["error"] = err
                print_finding("HIGH", f"Failed to download {name}: {err}")

            manifest["files"].append(record)

    _write_manifest(manifest, output_dir)
    return manifest


def _write_manifest(manifest: dict, output_dir: Path) -> None:
    path = output_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    if RICH_AVAILABLE and console:
        console.print(f"  [dim]Manifest -> {path}[/dim]")
    else:
        print(f"  Manifest -> {path}")


# ---------------------------------------------------------------------------
# Console inventory print
# ---------------------------------------------------------------------------

def print_download_inventory(manifest: dict) -> None:
    files = manifest.get("files", [])
    ok = [f for f in files if f["status"] == "ok"]
    errors = [f for f in files if f["status"] == "error"]

    if RICH_AVAILABLE and console:
        from rich.table import Table
        from rich import box
        console.print(f"\n[bold yellow]>>> Downloaded Resources ({len(ok)}/{len(files)} succeeded)[/bold yellow]")
        if files:
            tbl = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
            tbl.add_column("Resource", style="cyan")
            tbl.add_column("URI")
            tbl.add_column("File")
            tbl.add_column("Status")
            for f in files:
                status = "[green]OK[/green]" if f["status"] == "ok" else "[red]ERROR[/red]"
                tbl.add_row(f["resource_name"], f["uri"], f.get("file", ""), status)
            console.print(tbl)
        if errors:
            console.print(f"\n  [red]{len(errors)} download(s) failed -- see manifest.json for details.[/red]")
    else:
        print(f"\n--- Downloaded Resources ({len(ok)}/{len(files)} succeeded) ---")
        for f in files:
            print(f"  [{f['status'].upper()}] {f['resource_name']} -> {f.get('file','')}")
