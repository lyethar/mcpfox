"""Raw HTTP probing and port scanning for MCP endpoint discovery."""

import asyncio
from typing import Optional
import httpx

COMMON_MCP_PORTS = [3000, 3001, 4000, 5000, 7000, 8000, 8080, 8443, 8888, 9000, 31194]

MCP_PATHS = ["/mcp", "/mcp/", "/sse", "/events", "/api/mcp", "/v1/mcp", "/"]


async def http_probe(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """Try MCP-likely paths on a single host:port. Returns first successful hit."""
    for path in MCP_PATHS:
        url = f"http://{host}:{port}{path}"
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                r = await client.get(url, headers={"Accept": "text/event-stream,application/json,*/*"})
                content_type = r.headers.get("content-type", "")
                return {
                    "url": url,
                    "host": host,
                    "port": port,
                    "status": r.status_code,
                    "content_type": content_type,
                    "server": r.headers.get("server", ""),
                    "is_sse": "text/event-stream" in content_type,
                    "is_json": "json" in content_type,
                    "response_snippet": r.text[:300],
                }
        except Exception:
            continue
    return None


async def scan_ports(host: str, ports: list[int], timeout: float = 2.0) -> list[dict]:
    """Concurrently probe all ports; return only successful responses."""
    tasks = [http_probe(host, port, timeout) for port in ports]
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in responses if isinstance(r, dict)]
