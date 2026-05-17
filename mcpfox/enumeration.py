"""Core MCP server enumeration logic."""

import re
from datetime import datetime

try:
    from fastmcp import Client
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False

from mcpfox.analysis import (
    analyze_name_description,
    assess_schema_risk,
    check_injection_surface,
    DANGEROUS_TOOL_PATTERNS,
    SENSITIVE_RESOURCE_PATTERNS,
)
from mcpfox.rendering import format_resource_error


async def enumerate_mcp_server(
    url: str,
    read_resources: bool = False,
    probe_prompts: bool = False,
) -> dict:
    """
    Connect to an MCP server and enumerate all exposed capabilities.
    Returns a structured report dict with security findings attached.
    """
    if not FASTMCP_AVAILABLE:
        return {"error": "fastmcp not installed. Run: pip install fastmcp"}

    report: dict = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "tools": [],
        "resources": [],
        "resource_templates": [],
        "prompts": [],
        "security_findings": [],
    }

    try:
        client = Client(url)
        async with client:
            _enum_tools(client, report, await client.list_tools())
            await _enum_resources(client, report, await client.list_resources(), read_resources)
            _enum_templates(report, await client.list_resource_templates())
            if probe_prompts:
                await _enum_prompts(client, report)
    except Exception as e:
        report["connection_error"] = str(e)

    return report


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _enum_tools(client, report: dict, tools) -> None:  # noqa: ARG001
    for tool in tools:
        schema = tool.inputSchema or {}
        entry: dict = {
            "name": tool.name,
            "description": tool.description or "",
            "schema": schema,
            "security": [],
        }
        for finding in analyze_name_description(tool.name, tool.description or "", DANGEROUS_TOOL_PATTERNS):
            entry["security"].append({"severity": "MEDIUM", **finding})
            report["security_findings"].append({
                "type": "tool", "item": tool.name,
                "severity": "MEDIUM", "detail": finding["label"],
            })
        for risk in assess_schema_risk(schema):
            entry["security"].append({"severity": "LOW", "label": risk})
            report["security_findings"].append({
                "type": "tool_schema", "item": tool.name,
                "severity": "LOW", "detail": risk,
            })
        if check_injection_surface(tool.description or ""):
            entry["security"].append({"severity": "LOW", "label": "Potential injection surface in description"})
        report["tools"].append(entry)


async def _enum_resources(client, report: dict, resources, read_resources: bool) -> None:
    for res in resources:
        uri = str(res.uri) if hasattr(res, "uri") else ""
        entry: dict = {
            "name": res.name,
            "uri": uri,
            "description": res.description or "",
            "mime_type": res.mimeType if hasattr(res, "mimeType") else "",
            "security": [],
            "content": None,
        }
        for finding in analyze_name_description(res.name, res.description or "", SENSITIVE_RESOURCE_PATTERNS):
            entry["security"].append({"severity": "HIGH", **finding})
            report["security_findings"].append({
                "type": "resource", "item": res.name,
                "severity": "HIGH", "detail": finding["label"],
            })
        if read_resources:
            try:
                content = await client.read_resource(uri or res.name)
                entry["content"] = str(content)[:2000]
            except Exception as e:
                entry["content_error"] = format_resource_error(e)
        report["resources"].append(entry)


def _enum_templates(report: dict, templates) -> None:
    for tmpl in templates:
        uri_str = tmpl.uriTemplate if hasattr(tmpl, "uriTemplate") else str(tmpl)
        entry: dict = {
            "uri_template": uri_str,
            "name": getattr(tmpl, "name", ""),
            "description": getattr(tmpl, "description", ""),
            "security": [],
        }
        if re.search(r'\.\./|%2e%2e', uri_str, re.I):
            entry["security"].append({"severity": "HIGH", "label": "Potential path traversal in URI template"})
            report["security_findings"].append({
                "type": "template", "item": uri_str,
                "severity": "HIGH", "detail": "Path traversal pattern in URI template",
            })
        report["resource_templates"].append(entry)


async def _enum_prompts(client, report: dict) -> None:
    try:
        for prompt in await client.list_prompts():
            entry: dict = {
                "name": prompt.name,
                "description": prompt.description or "",
                "arguments": [],
            }
            for arg in (prompt.arguments or []) if hasattr(prompt, "arguments") else []:
                entry["arguments"].append({
                    "name": arg.name,
                    "description": arg.description or "",
                    "required": getattr(arg, "required", False),
                })
            report["prompts"].append(entry)
    except Exception as e:
        report["prompts_error"] = str(e)
