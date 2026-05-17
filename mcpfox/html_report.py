"""Self-contained HTML inventory report generator for MCPFox scan results."""

import base64
import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mcpfox import __version__

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(value) -> str:
    """HTML-escape a value, converting None to empty string."""
    return _html.escape(str(value) if value is not None else "")


def _badge(severity: str) -> str:
    cls = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(severity, "info")
    return f'<span class="badge badge-{cls}">{_e(severity)}</span>'


def _find_banner() -> Optional[str]:
    """
    Locate the MCPFox banner image and return a data URI for inline embedding.
    Searches the package's assets/ directory and the repo root assets/.
    """
    candidates: list[Path] = []
    pkg_root = Path(__file__).parent.parent
    for base in (pkg_root / "assets", Path("assets")):
        for name in ("mcpfox-banner.png", "mcpfox-banner.jpg", "mcpfox-banner.jpeg"):
            candidates.append(base / name)

    for path in candidates:
        if path.exists():
            mime = "jpeg" if path.suffix in (".jpg", ".jpeg") else "png"
            data = base64.b64encode(path.read_bytes()).decode()
            return f"data:image/{mime};base64,{data}"
    return None


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_findings(findings: list) -> str:
    if not findings:
        return '<p class="muted">No automated security flags raised.</p>'
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_f = sorted(findings, key=lambda f: order.get(f.get("severity", "LOW"), 3))
    rows = []
    for f in sorted_f:
        sev = f.get("severity", "INFO")
        cls = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(sev, "info")
        rows.append(f"""
      <div class="finding finding-{cls}">
        <div>{_badge(sev)}</div>
        <div class="finding-detail">
          <div><strong>{_e(f.get('item', ''))}</strong>
            <span class="finding-type"> [{_e(f.get('type', ''))}]</span>
          </div>
          <div class="muted">{_e(f.get('detail', ''))}</div>
        </div>
      </div>""")
    return "\n".join(rows)


def _render_tools(tools: list) -> str:
    if not tools:
        return '<p class="muted">No tools returned by server.</p>'
    cards = []
    for tool in tools:
        schema = tool.get("schema", {})
        props = schema.get("properties", {})
        required = schema.get("required", [])
        flags = tool.get("security", [])

        # Parameter table rows
        if props:
            param_rows = "".join(
                f"<tr><td><code>{_e(pname)}</code></td>"
                f"<td>{_e(pdef.get('type','?'))}</td>"
                f"<td>{'yes' if pname in required else 'no'}</td>"
                f"<td class=\"muted\">{_e(pdef.get('description',''))}</td></tr>"
                for pname, pdef in props.items()
            )
            params_html = f"""
          <table class="inner-table">
            <tr><th>Parameter</th><th>Type</th><th>Required</th><th>Description</th></tr>
            {param_rows}
          </table>"""
        else:
            params_html = '<p class="muted" style="margin:0.5rem 0">No parameters.</p>'

        # Security flags
        _sev_cls = {"MEDIUM": "medium", "LOW": "low", "HIGH": "high"}
        if flags:
            flag_parts = []
            for fl in flags:
                cls = _sev_cls.get(fl.get("severity", "low"), "low")
                flag_parts.append(f'<span class="badge badge-{cls}">{_e(fl.get("label",""))}</span>')
            flag_html = " ".join(flag_parts)
        else:
            flag_html = '<span class="badge badge-info">clean</span>'

        cards.append(f"""
    <div class="tool-card">
      <div class="tool-header">
        <span class="tool-name">{_e(tool['name'])}</span>
        <span style="margin-left:auto;display:flex;gap:0.4rem;flex-wrap:wrap">{flag_html}</span>
      </div>
      <div class="tool-body">
        <p class="muted" style="margin-bottom:0.75rem">{_e(tool.get('description',''))}</p>
        {params_html}
      </div>
    </div>""")
    return "\n".join(cards)


def _render_resources(resources: list, manifest: Optional[dict]) -> str:
    if not resources:
        return '<p class="muted">No resources returned by server.</p>'

    # Build URI → download record map for linking
    dl_map: dict[str, dict] = {}
    if manifest:
        for rec in manifest.get("files", []):
            dl_map[rec.get("uri", "")] = rec

    cards = []
    for res in resources:
        uri = res.get("uri", "")
        flags = res.get("security", [])
        flag_html = " ".join(
            f'<span class="badge badge-high">{_e(f.get("label",""))}</span>' for f in flags
        ) if flags else ""

        # Content display: downloaded file / inline content / error / not fetched
        dl_rec = dl_map.get(uri)
        if dl_rec:
            if dl_rec["status"] == "ok":
                content_html = f"""
          <p style="margin-bottom:0.5rem">
            <a href="{_e(dl_rec['file'])}" class="file-link">
              {_e(dl_rec['file'])}
            </a>
            <span class="muted"> ({dl_rec.get('bytes', 0):,} bytes)</span>
          </p>"""
            else:
                content_html = f'<p class="error-text">Download failed: {_e(dl_rec.get("error",""))}</p>'
        elif res.get("content_error"):
            content_html = f'<p class="error-text">Read failed: {_e(res["content_error"])}</p>'
        elif res.get("content"):
            snippet = _e(res["content"][:1000])
            more = "…" if len(res.get("content", "")) > 1000 else ""
            content_html = f"<pre>{snippet}{more}</pre>"
        else:
            content_html = '<p class="muted">Content not fetched (use --download or --read-resources).</p>'

        cards.append(f"""
    <div class="resource-card">
      <div class="resource-header">
        <div>
          <span class="tool-name">{_e(res.get('name',''))}</span>
          <code style="margin-left:0.75rem;font-size:0.8rem">{_e(uri)}</code>
        </div>
        <div style="display:flex;gap:0.4rem;align-items:center">
          {f'<span class="badge badge-info">{_e(res.get("mime_type",""))}</span>' if res.get("mime_type") else ""}
          {flag_html}
        </div>
      </div>
      <div class="resource-content">
        <p class="muted" style="margin-bottom:0.5rem">{_e(res.get('description',''))}</p>
        {content_html}
      </div>
    </div>""")
    return "\n".join(cards)


def _render_templates(templates: list) -> str:
    if not templates:
        return '<p class="muted">No resource templates returned by server.</p>'
    row_parts = []
    for t in templates:
        flag_cell = '<span class="badge badge-high">Path traversal risk</span>' if t.get("security") else ""
        row_parts.append(
            f'<tr><td><code>{_e(t.get("uri_template",""))}</code></td>'
            f'<td class="muted">{_e(t.get("description",""))}</td>'
            f"<td>{flag_cell}</td></tr>"
        )
    rows = "".join(row_parts)
    return f"""
    <table>
      <tr><th>URI Template</th><th>Description</th><th>Flags</th></tr>
      {rows}
    </table>"""


def _render_prompts(prompts: list) -> str:
    if not prompts:
        return '<p class="muted">No prompts returned by server.</p>'
    rows = "".join(
        f"<tr><td><code>{_e(p['name'])}</code></td>"
        f"<td class=\"muted\">{_e(p.get('description',''))}</td>"
        f"<td>{', '.join('<code>' + _e(a['name']) + '</code>' for a in p.get('arguments', []))}</td></tr>"
        for p in prompts
    )
    return f"""
    <table>
      <tr><th>Name</th><th>Description</th><th>Arguments</th></tr>
      {rows}
    </table>"""


def _render_downloads(manifest: dict) -> str:
    files = manifest.get("files", [])
    if not files:
        return '<p class="muted">No files downloaded.</p>'
    ok = sum(1 for f in files if f["status"] == "ok")
    row_parts = []
    for f in files:
        if f["status"] == "ok":
            bytes_cell = f"{f.get('bytes', 0):,}"
            status_cell = '<span class="badge badge-info">OK</span>'
        else:
            bytes_cell = "—"
            status_cell = '<span class="badge badge-high">ERROR</span>'
        file_href = _e(f.get("file", ""))
        row_parts.append(
            f'<tr>'
            f'<td>{_e(f["resource_name"])}</td>'
            f'<td><code>{_e(f["uri"])}</code></td>'
            f'<td><a href="{file_href}" class="file-link">{file_href}</a></td>'
            f'<td>{bytes_cell}</td>'
            f'<td>{status_cell}</td>'
            f'</tr>'
        )
    rows = "".join(row_parts)
    return f"""
    <p class="muted" style="margin-bottom:1rem">
      {ok} of {len(files)} resource(s) downloaded to
      <code>{_e(manifest.get('output_dir',''))}/resources/</code>
    </p>
    <table>
      <tr><th>Resource</th><th>URI</th><th>File</th><th>Bytes</th><th>Status</th></tr>
      {rows}
    </table>"""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """<style>
:root {
  --bg:      #0d1117;
  --bg2:     #161b22;
  --bg3:     #21262d;
  --border:  #30363d;
  --text:    #c9d1d9;
  --muted:   #8b949e;
  --accent:  #58a6ff;
  --red:     #f85149;
  --orange:  #d29922;
  --blue:    #388bfd;
  --green:   #3fb950;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-size: 15px;
  line-height: 1.6;
}

/* ── Banner ── */
.banner {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 2.5rem 2rem 1.5rem;
  text-align: center;
}
.banner img { max-width: 720px; width: 100%; }
.banner-text {
  font-size: 3rem;
  font-weight: 800;
  letter-spacing: 0.15em;
  color: var(--accent);
  text-shadow: 0 0 30px rgba(88,166,255,0.4);
}
.banner-sub  { margin-top: 0.75rem; color: var(--muted); font-size: 0.95rem; }
.banner-meta { color: var(--muted); font-size: 0.8rem; margin-top: 0.25rem; }

/* ── Nav ── */
nav {
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 0.6rem 2rem;
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}
nav a {
  color: var(--muted);
  text-decoration: none;
  font-size: 0.875rem;
  font-weight: 500;
  transition: color 0.15s;
}
nav a:hover { color: var(--accent); }

/* ── Main ── */
main { max-width: 1200px; margin: 0 auto; padding: 2.5rem 2rem; }
section { margin-bottom: 3.5rem; }
h2 {
  font-size: 1.3rem;
  color: var(--accent);
  border-bottom: 1px solid var(--border);
  padding-bottom: 0.5rem;
  margin-bottom: 1.5rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

/* ── Summary cards ── */
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.summary-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem 1rem;
  text-align: center;
}
.summary-card .num  { font-size: 2.2rem; font-weight: 700; color: var(--accent); }
.summary-card .label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 0.2rem; }

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
th {
  background: var(--bg3);
  color: var(--muted);
  text-align: left;
  padding: 0.65rem 1rem;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.72rem;
  letter-spacing: 0.06em;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 0.65rem 1rem;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,0.025); }
.inner-table { margin-top: 0.5rem; }
.inner-table th { background: var(--bg); font-size: 0.68rem; padding: 0.4rem 0.75rem; }
.inner-table td { padding: 0.4rem 0.75rem; font-size: 0.8rem; background: transparent; }

/* ── Code ── */
code {
  font-family: 'SFMono-Regular', 'Cascadia Code', Consolas, monospace;
  font-size: 0.825em;
  background: var(--bg3);
  padding: 0.1em 0.4em;
  border-radius: 4px;
  color: #e6edf3;
}
pre {
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  overflow-x: auto;
  font-family: 'SFMono-Regular', Consolas, monospace;
  font-size: 0.82rem;
  white-space: pre-wrap;
  word-break: break-word;
  color: #e6edf3;
  max-height: 400px;
  overflow-y: auto;
}

/* ── Badges ── */
.badge {
  display: inline-block;
  padding: 0.18em 0.55em;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  white-space: nowrap;
}
.badge-high   { background: rgba(248,81,73,.15);  color: #f85149; border: 1px solid rgba(248,81,73,.35); }
.badge-medium { background: rgba(210,153,34,.15); color: #d29922; border: 1px solid rgba(210,153,34,.35); }
.badge-low    { background: rgba(56,139,253,.15); color: #388bfd; border: 1px solid rgba(56,139,253,.35); }
.badge-info   { background: rgba(63,185,80,.15);  color: #3fb950; border: 1px solid rgba(63,185,80,.35); }

/* ── Findings ── */
.finding {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.9rem 1.1rem;
  margin-bottom: 0.65rem;
  display: flex;
  align-items: flex-start;
  gap: 1rem;
}
.finding-high   { border-left: 3px solid var(--red); }
.finding-medium { border-left: 3px solid var(--orange); }
.finding-low    { border-left: 3px solid var(--blue); }
.finding-detail { flex: 1; }
.finding-type   { color: var(--muted); font-size: 0.8rem; }

/* ── Tool cards ── */
.tool-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 1rem;
  overflow: hidden;
}
.tool-header {
  background: var(--bg3);
  padding: 0.75rem 1rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}
.tool-name { font-family: monospace; font-size: 0.95rem; color: #e6edf3; font-weight: 600; }
.tool-body { padding: 1rem; }

/* ── Resource cards ── */
.resource-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 1rem;
  overflow: hidden;
}
.resource-header {
  background: var(--bg3);
  padding: 0.75rem 1rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 0.5rem;
}
.resource-content { padding: 1rem; }

/* ── Misc ── */
.muted      { color: var(--muted); }
.error-text { color: var(--red); font-size: 0.875rem; }
.file-link  { color: var(--accent); text-decoration: none; font-family: monospace; font-size: 0.85rem; }
.file-link:hover { text-decoration: underline; }

/* ── Footer ── */
footer {
  text-align: center;
  color: var(--muted);
  font-size: 0.8rem;
  padding: 2rem;
  border-top: 1px solid var(--border);
  margin-top: 3rem;
}
footer a { color: var(--accent); text-decoration: none; }
</style>
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_html_report(
    report: dict,
    output_path: Path,
    manifest: Optional[dict] = None,
) -> None:
    """
    Write a self-contained HTML inventory report to *output_path*.
    If *manifest* is provided (from download_all_resources), downloaded
    file links are woven into the resources section.
    """
    url = report.get("url", "unknown")
    parsed = urlparse(url)
    host = parsed.netloc or url
    timestamp = report.get("timestamp", datetime.utcnow().isoformat() + "Z")

    tools     = report.get("tools", [])
    resources = report.get("resources", [])
    templates = report.get("resource_templates", [])
    prompts   = report.get("prompts", [])
    findings  = report.get("security_findings", [])

    n_high   = sum(1 for f in findings if f.get("severity") == "HIGH")
    n_medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    n_low    = sum(1 for f in findings if f.get("severity") == "LOW")

    banner_uri = _find_banner()
    banner_html = (
        f'<img src="{banner_uri}" alt="MCPFox">'
        if banner_uri
        else '<div class="banner-text">MCPFox</div>'
    )

    prompts_section = (
        f'<section id="prompts"><h2>Prompts</h2>{_render_prompts(prompts)}</section>'
        if prompts else ""
    )
    downloads_section = (
        f'<section id="downloads"><h2>Downloaded Files</h2>{_render_downloads(manifest)}</section>'
        if manifest else ""
    )
    downloads_nav = (
        f'<a href="#downloads">Downloads ({len(manifest.get("files",[]))})</a>'
        if manifest else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCPFox — {_e(host)}</title>
  {_CSS}
</head>
<body>

<header class="banner">
  {banner_html}
  <p class="banner-sub">MCP Server Security Report &mdash; <code>{_e(url)}</code></p>
  <p class="banner-meta">Generated {_e(timestamp)} &bull; mcpfox v{_e(__version__)}</p>
</header>

<nav>
  <a href="#summary">Summary</a>
  <a href="#findings">Findings ({len(findings)})</a>
  <a href="#tools">Tools ({len(tools)})</a>
  <a href="#resources">Resources ({len(resources)})</a>
  <a href="#templates">Templates ({len(templates)})</a>
  {'<a href="#prompts">Prompts (' + str(len(prompts)) + ')</a>' if prompts else ''}
  {downloads_nav}
</nav>

<main>

  <!-- ── Summary ── -->
  <section id="summary">
    <h2>Summary</h2>
    <div class="summary-grid">
      <div class="summary-card"><div class="num">{len(tools)}</div><div class="label">Tools</div></div>
      <div class="summary-card"><div class="num">{len(resources)}</div><div class="label">Resources</div></div>
      <div class="summary-card"><div class="num">{len(templates)}</div><div class="label">Templates</div></div>
      <div class="summary-card"><div class="num">{len(prompts)}</div><div class="label">Prompts</div></div>
      <div class="summary-card"><div class="num" style="color:var(--red)">{n_high}</div><div class="label">High</div></div>
      <div class="summary-card"><div class="num" style="color:var(--orange)">{n_medium}</div><div class="label">Medium</div></div>
      <div class="summary-card"><div class="num" style="color:var(--blue)">{n_low}</div><div class="label">Low</div></div>
    </div>
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>Target URL</td><td><code>{_e(url)}</code></td></tr>
      <tr><td>Scan timestamp</td><td>{_e(timestamp)}</td></tr>
      <tr><td>mcpfox version</td><td>{_e(__version__)}</td></tr>
      {'<tr><td style="color:var(--red)">Connection error</td><td>' + _e(report.get("connection_error")) + '</td></tr>' if report.get("connection_error") else ''}
    </table>
  </section>

  <!-- ── Security Findings ── -->
  <section id="findings">
    <h2>Security Findings</h2>
    {_render_findings(findings)}
  </section>

  <!-- ── Tools ── -->
  <section id="tools">
    <h2>Tools</h2>
    {_render_tools(tools)}
  </section>

  <!-- ── Resources ── -->
  <section id="resources">
    <h2>Resources</h2>
    {_render_resources(resources, manifest)}
  </section>

  <!-- ── Resource Templates ── -->
  <section id="templates">
    <h2>Resource Templates</h2>
    {_render_templates(templates)}
  </section>

  {prompts_section}
  {downloads_section}

</main>

<footer>
  Generated by <a href="https://github.com/yourhandle/mcpfox">MCPFox</a> v{_e(__version__)}
  &mdash; For authorised security testing only.
</footer>

</body>
</html>"""

    output_path.write_text(html, encoding="utf-8")
