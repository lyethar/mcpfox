"""Security heuristics for MCP tool, resource, and schema analysis."""

import re

DANGEROUS_TOOL_PATTERNS = [
    (r'\bexec\b|\bshell\b|\bcommand\b|\brun\b|\bspawn\b|\bpopen\b', "Shell/command execution"),
    (r'\beval\b|\bscript\b|\bcode\b', "Code evaluation"),
    (r'\bdelete\b|\bremove\b|\bwipe\b|\bpurge\b|\bdrop\b', "Destructive operation"),
    (r'\bwrite\b|\bupload\b|\bcreate\b|\bsave\b|\bput\b|\bpatch\b|\bpost\b', "Write/upload capability"),
    (r'\bpassword\b|\bsecret\b|\btoken\b|\bcredential\b|\bapi.?key\b|\bauth\b', "Credential handling"),
    (r'\bsql\b|\bquery\b|\bdatabase\b|\bdb\b', "Database access"),
    (r'\bnetwork\b|\bhttp\b|\bfetch\b|\brequest\b|\bweb\b|\bcurl\b', "Network/HTTP access"),
    (r'\bfile\b|\bread\b|\bpath\b|\bopen\b|\bdir\b|\blist\b', "Filesystem access"),
    (r'\benv\b|\benvironment\b|\bconfig\b|\bsetting\b', "Environment/config access"),
    (r'\bprivilege\b|\badmin\b|\broot\b|\bsudo\b|\belevate\b', "Privilege operation"),
    (r'\bsend\b|\bemail\b|\bsms\b|\bnotif\b|\bmessage\b|\bslack\b|\bwebhook\b', "Outbound messaging"),
    (r'\bldap\b|\bsaml\b|\boauth\b|\bsso\b', "Identity/auth protocol"),
]

SENSITIVE_RESOURCE_PATTERNS = [
    (r'\bpasswd\b|\bshadow\b|\b\.env\b|\bsecret\b|\bcredential\b', "Credential file"),
    (r'\bssh\b|\bprivate.?key\b|\bpem\b|\bkeyring\b', "Private key material"),
    (r'\bhistory\b|\blog\b|\baudit\b', "Audit/history data"),
    (r'\bconfig\b|\bsettings\b|\bprofile\b', "Configuration file"),
    (r'\btoken\b|\bapi.?key\b|\bjwt\b', "API token"),
]

INJECTION_RISK_PATTERNS = [
    r'\{[^}]+\}',       # Template injection
    r'<[^>]+>',         # XML/HTML injection surface
    r'\$\{[^}]+\}',     # Shell/template variable
    r'%[a-zA-Z]',       # Printf-style format strings
]


def analyze_name_description(name: str, description: str, patterns: list) -> list[dict]:
    findings = []
    combined = f"{name} {description}".lower()
    for pattern, label in patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            findings.append({"label": label, "matched_pattern": pattern})
    return findings


def check_injection_surface(text: str) -> list[str]:
    return [pat for pat in INJECTION_RISK_PATTERNS if re.search(pat, text)]


def assess_schema_risk(schema: dict) -> list[str]:
    risks = []
    if not schema:
        return risks
    props = schema.get("properties", {})
    required = schema.get("required", [])

    if props and not required:
        risks.append("No required parameters (permissive input)")

    for param_name, param_def in props.items():
        ptype = param_def.get("type", "")
        if ptype == "string" and not param_def.get("enum"):
            if re.search(r'command|cmd|exec|script|query|sql|path|file|url|code', param_name, re.I):
                risks.append(f"Unconstrained string param '{param_name}' (injection surface)")

    return risks
